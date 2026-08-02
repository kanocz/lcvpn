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

type packetInterface interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
}

func refreshIV(e PacketEncrypter, iv []byte, random io.Reader) ([]byte, error) {
	if len(iv) != e.IVLen() {
		iv = make([]byte, e.IVLen())
	}
	if _, err := io.ReadFull(random, iv); err != nil {
		return nil, err
	}
	return iv, nil
}

func rcvrThread(proto string, port int, iface packetInterface, replay *replayProtector) {
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

func sndrThread(conn *net.UDPConn, iface packetInterface, sender *packetSender) error {
	var packet IPPacket = make([]byte, BUFFERSIZE)
	var framed = make([]byte, BUFFERSIZE)
	var encrypted = make([]byte, BUFFERSIZE)
	var ivbuf []byte

	for {
		plen, err := iface.Read(packet[:MTU])
		if err != nil {
			return fmt.Errorf("reading local interface: %w", err)
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

		// Use the most specific configured network route.
		if !wanted {
			ip := packet.DstV4()
			if routeAddr, found := c.routeFor(ip); found {
				addr = routeAddr
				ok = true
				wanted = true
			}
		}

		if wanted {
			sendTo := func(addr *net.UDPAddr) error {
				recipient, exists := c.remoteIDs[addr.String()]
				if !exists {
					return fmt.Errorf("unable to find remote identity for %s", addr)
				}
				frameLen, err := sender.Frame(addr.String(), recipient, packet[:plen], framed)
				if nil != err {
					return fmt.Errorf("creating packet frame: %w", err)
				}

				clen := c.Main.main.AdjustInputSize(frameLen)
				if clen > len(framed) || clen+c.Main.main.OutputAdd() > len(encrypted) {
					return fmt.Errorf("encrypted packet is too large: %d bytes", clen+c.Main.main.OutputAdd())
				}
				clear(framed[frameLen:clen])
				ivbuf, err = refreshIV(c.Main.main, ivbuf, rand.Reader)
				if nil != err {
					return fmt.Errorf("reading random IV: %w", err)
				}

				tsize := c.Main.main.Encrypt(framed[:clen], encrypted, ivbuf)
				n, err := conn.WriteToUDP(encrypted[:tsize], addr)
				if nil != err {
					log.Println("Error sending package:", err)
				}
				if n != tsize {
					log.Println("Only ", n, " bytes of ", tsize, " sent")
				}
				return nil
			}

			if ok {
				if err := sendTo(addr); err != nil {
					return err
				}
			} else {
				// multicast or broadcast
				for _, addr := range c.remotes {
					if err := sendTo(addr); err != nil {
						return err
					}
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

	senderErrors := make(chan error, conf.Main.SendThreads)
	for i := 0; i < conf.Main.SendThreads; i++ {
		go func() {
			senderErrors <- sndrThread(writeConn, iface, sender)
		}()
	}

	exitChan := make(chan os.Signal, 1)
	signal.Notify(exitChan, syscall.SIGTERM)

	var senderErr error
	select {
	case <-exitChan:
	case senderErr = <-senderErrors:
	}

	err = writeConn.Close()
	if nil != err {
		log.Println("Error closing UDP connection: ", err)
	}
	if nil != senderErr {
		log.Fatalln("Sender thread stopped:", senderErr)
	}
}
