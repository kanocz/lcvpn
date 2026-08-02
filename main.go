package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/matishsiao/go_reuseport"
	"github.com/songgao/water"
	"golang.org/x/net/ipv4"
)

const (
	// AppVersion contains current application version for -version command flag
	AppVersion = "0.3.0-dev"
)

const (
	// I use TUN interface, so only plain IP packet,
	// no ethernet header + mtu is set to 1300

	// BUFFERSIZE is size of buffer to receive packets
	// (little bit bigger than maximum)
	BUFFERSIZE = 1518
)

func rcvrThread(proto string, port int, iface *water.Interface, replay *replayProtector) {
	conn, err := reuseport.NewReusableUDPPortConn(proto, fmt.Sprintf(":%v", port))
	if nil != err {
		log.Fatalln("Unable to get UDP socket:", err)
	}

	encrypted := make([]byte, BUFFERSIZE)
	var decrypted IPPacket = make([]byte, BUFFERSIZE)

	for {
		n, _, err := conn.ReadFrom(encrypted)

		if err != nil {
			log.Println("Error: ", err)
			continue
		}

		// ReadFromUDP can return 0 bytes on timeout
		if 0 == n {
			continue
		}

		conf := config.Load().(VPNState)

		if !conf.Main.main.CheckSize(n) {
			log.Println("invalid packet size ", n)
			continue
		}

		size, mainErr := DecryptV4Chk(conf.Main.main, encrypted[:n], decrypted, replay, conf.Main.localIP)
		if nil != mainErr {
			if nil != conf.Main.alt {
				size, err = DecryptV4Chk(conf.Main.alt, encrypted[:n], decrypted, replay, conf.Main.localIP)
				if nil != err {
					log.Println("Corrupted package: ", mainErr, " / ", err)
					continue
				}
			} else {
				log.Println("Corrupted package: ", mainErr)
				continue
			}
		}

		n, err = iface.Write(decrypted[:size])
		if nil != err {
			log.Println("Error writing to local interface: ", err)
		} else if n != size {
			log.Println("Partial package written to local interface")
		}
	}
}

func sndrThread(conn *net.UDPConn, iface *water.Interface, sender *packetSender) {
	// first time fill with random numbers
	ivbuf := make([]byte, config.Load().(VPNState).Main.main.IVLen())
	if _, err := io.ReadFull(rand.Reader, ivbuf); err != nil {
		log.Fatalln("Unable to get rand data:", err)
	}

	var packet IPPacket = make([]byte, BUFFERSIZE)
	var framed = make([]byte, BUFFERSIZE)
	var encrypted = make([]byte, BUFFERSIZE)

	for {
		plen, err := iface.Read(packet[:MTU])
		if err != nil {
			break
		}

		if 4 != packet.IPver() {
			header, _ := ipv4.ParseHeader(packet)
			log.Printf("Non IPv4 packet [%+v]\n", header)
			continue
		}

		// each time get pointer to (probably) new config
		c := config.Load().(VPNState)

		dst := packet.Dst()

		wanted := false

		addr, ok := c.remotes[dst]

		if ok {
			wanted = true
		}

		if dst == c.Main.bcastIP || packet.IsMulticast() {
			wanted = true
		}

		// very ugly and useful only for a limited numbers of routes!
		if !wanted {
			ip := packet.DstV4()
			for n, s := range c.routes {
				if n.Contains(ip) {
					addr = s
					ok = true
					wanted = true
					break
				}
			}
		}

		if wanted {
			sendTo := func(addr *net.UDPAddr) {
				recipient, exists := c.remoteIDs[addr.String()]
				if !exists {
					log.Println("Unable to find remote identity for", addr)
					return
				}
				frameLen, err := sender.Frame(addr.String(), recipient, packet[:plen], framed)
				if nil != err {
					log.Println("Unable to create packet frame:", err)
					return
				}

				clen := c.Main.main.AdjustInputSize(frameLen)
				if clen > len(framed) || clen+c.Main.main.OutputAdd() > len(encrypted) {
					log.Println("Encrypted packet is too large", clen, len(encrypted))
					return
				}
				clear(framed[frameLen:clen])

				tsize := c.Main.main.Encrypt(framed[:clen], encrypted, ivbuf)
				n, err := conn.WriteToUDP(encrypted[:tsize], addr)
				if nil != err {
					log.Println("Error sending package:", err)
				}
				if n != tsize {
					log.Println("Only ", n, " bytes of ", tsize, " sent")
				}
			}

			if ok {
				sendTo(addr)
			} else {
				// multicast or broadcast
				for _, addr := range c.remotes {
					sendTo(addr)
				}
			}
		} else {
			log.Println("Unknown dst: ", dst)
		}
	}

}

func main() {

	version := flag.Bool("version", false, "print lcvpn version")
	flag.Parse()

	if *version {
		fmt.Println(AppVersion)
		os.Exit(0)
	}

	routeReload := make(chan bool, 1)

	initConfig(routeReload)

	conf := config.Load().(VPNState)

	iface := ifaceSetup(conf.Main.local)
	replay := newReplayProtector()
	sender := newPacketSender()

	// start routes changes in config monitoring
	go routesThread(iface.Name(), routeReload)

	log.Println("Interface parameters configured")

	// Start listen threads
	for i := 0; i < conf.Main.RecvThreads; i++ {
		go rcvrThread("udp4", conf.Main.Port, iface, replay)
	}

	// init udp socket for write

	writeAddr, err := net.ResolveUDPAddr("udp", ":")
	if nil != err {
		log.Fatalln("Unable to get UDP socket:", err)
	}

	writeConn, err := net.ListenUDP("udp", writeAddr)
	if nil != err {
		log.Fatalln("Unable to create UDP socket:", err)
	}

	// Start sender threads

	for i := 0; i < conf.Main.SendThreads; i++ {
		go sndrThread(writeConn, iface, sender)
	}

	exitChan := make(chan os.Signal, 1)
	signal.Notify(exitChan, syscall.SIGTERM)

	<-exitChan

	err = writeConn.Close()
	if nil != err {
		log.Println("Error closing UDP connection: ", err)
	}
}
