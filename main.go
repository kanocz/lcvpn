package main

import (
	"crypto/aes"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/kanocz/lcvpn/netlink"
	"github.com/matishsiao/go_reuseport"
	"github.com/milosgajdos83/tenus"
	"github.com/songgao/water"
	"golang.org/x/net/ipv4"
)

const (
	// AppVersion contains current application version for -version command flag
	AppVersion = "0.2.0a"
)

const (
	// I use TUN interface, so only plain IP packet, no ethernet header + mtu is set to 1300

	// BUFFERSIZE is size of buffer to receive packets (little bit bigger than maximum)
	BUFFERSIZE = 1518
	// MTU used for tunneled packets
	MTU = 1300
)

func rcvrThread(proto string, port int, iface *water.Interface) {
	conn, err := reuseport.NewReusableUDPPortConn(proto, fmt.Sprintf(":%v", port))
	if nil != err {
		log.Fatalln("Unable to get UDP socket:", err)
	}

	encrypted := make([]byte, BUFFERSIZE)
	decrypted := make([]byte, BUFFERSIZE)

	for {
		n, _, err := conn.ReadFrom(encrypted)

		if err != nil {
			fmt.Println("Error: ", err)
			continue
		}

		// ReadFromUDP can return 0 bytes on timeout
		if 0 == n {
			continue
		}

		conf := config.Load().(VPNState)

		if !conf.Main.main.CheckSize(n) {
			fmt.Println("invalid packet size ", n)
			continue
		}

		ne := conf.Main.main.Decrypt(encrypted[:n], decrypted)
		// make int from 2x byte
		size := int(decrypted[0]) | (int(decrypted[1]) << 8)
		// check if decrypted size if ok and if this is a ipv4 packet
		// don't forward something is corrupted on other size OR encrypted with a wrong key
		if 0 == ne || (n-aes.BlockSize-2)-size > 16 || (n-aes.BlockSize-2)-size < 0 || 4 != ((decrypted)[2]>>4) {
			if nil != conf.Main.alt {
				ne = conf.Main.alt.Decrypt(encrypted[:n], decrypted)
				size := int(decrypted[0]) | (int(decrypted[1]) << 8)
				if 0 == ne || (n-aes.BlockSize-2)-size > 16 || (n-aes.BlockSize-2)-size < 0 || 4 != ((decrypted)[2]>>4) {
					fmt.Println("Invalid size field or IPv4 id in decrypted message", size, (n - aes.BlockSize - 2))
					continue
				}
			}
		}

		iface.Write(decrypted[2 : 2+size])
	}
}

func sndrThread(conn *net.UDPConn, iface *water.Interface) {
	// first time fill with random numbers
	ivbuf := make([]byte, config.Load().(VPNState).Main.main.IVLen())
	if _, err := io.ReadFull(rand.Reader, ivbuf); err != nil {
		log.Fatalln("Unable to get rand data:", err)
	}

	var packet IPPacket = make([]byte, BUFFERSIZE)
	var encrypted = make([]byte, BUFFERSIZE)

	for {
		plen, err := iface.Read(packet[2 : MTU+2])
		if err != nil {
			break
		}

		if 4 != packet.IPver() {
			header, _ := ipv4.ParseHeader(packet[2:])
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
			// store orig packet len
			packet[0] = byte(plen & 0xff)
			packet[1] = byte((plen & 0xff00) >> 8)

			// new len contatins also 2byte original size
			clen := c.Main.main.AdjustInputSize(plen + 2)

			if clen > len(packet) {
				log.Println("clen > len(package)", clen, len(packet))
				continue
			}

			tsize := c.Main.main.Encrypt(packet[:clen], encrypted, ivbuf)

			if ok {
				n, err := conn.WriteToUDP(encrypted[:tsize], addr)
				if nil != err {
					log.Println("Error sending package:", err)
				}
				if n != tsize {
					log.Println("Only ", n, " bytes of ", tsize, " sent")
				}
			} else {
				// multicast or broadcast
				for _, addr := range c.remotes {
					n, err := conn.WriteToUDP(encrypted[:tsize], addr)
					if nil != err {
						log.Println("Error sending package:", err)
					}
					if n != tsize {
						log.Println("Only ", n, " bytes of ", tsize, " sent")
					}
				}
			}
		} else {
			fmt.Println("Unknown dst", dst)
		}
	}

}

func routesThread(ifaceName string, refresh chan bool) {
	currentRoutes := map[string]bool{}
	for {
		<-refresh
		log.Println("Reloading routes...")
		conf := config.Load().(VPNState)

		routes2Del := map[string]bool{}

		for r := range currentRoutes {
			routes2Del[r] = true
		}

		for r := range conf.routes {
			rs := r.String()
			if _, exist := routes2Del[rs]; exist {
				delete(routes2Del, rs)
			} else {
				// real add route
				currentRoutes[rs] = true
				log.Println("Adding route:", rs)
				err := netlink.AddRoute(rs, "", "", ifaceName)
				if nil != err {
					log.Println("Adding route", rs, "failed:", err)
				}
			}
		}

		for r := range routes2Del {
			delete(currentRoutes, r)
			log.Println("Removing route:", r)
			netlink.DelRoute(r, "", "", ifaceName)
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

	lIP, lNet, err := net.ParseCIDR(conf.Main.local)
	if nil != err {
		flag.Usage()
		log.Fatalln("\nlocal ip is not in ip/cidr format")
	}

	iface, err := water.NewTUN("")

	if nil != err {
		log.Fatalln("Unable to allocate TUN interface:", err)
	}

	log.Println("Interface allocated:", iface.Name())

	link, err := tenus.NewLinkFrom(iface.Name())
	if nil != err {
		log.Fatalln("Unable to get interface info", err)
	}

	err = link.SetLinkMTU(MTU)
	if nil != err {
		log.Fatalln("Unable to set MTU to 1300 on interface")
	}

	err = link.SetLinkIp(lIP, lNet)
	if nil != err {
		log.Fatalln("Unable to set IP to ", lIP, "/", lNet, " on interface")
	}

	err = link.SetLinkUp()
	if nil != err {
		log.Fatalln("Unable to UP interface")
	}

	// start routes changes in config monitoring
	go routesThread(iface.Name(), routeReload)

	log.Println("Interface parameters configured")

	// Start listen threads
	for i := 0; i < conf.Main.RecvThreads; i++ {
		go rcvrThread("udp4", conf.Main.Port, iface)
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
	defer writeConn.Close()

	// Start sender threads

	for i := 0; i < conf.Main.SendThreads; i++ {
		go sndrThread(writeConn, iface)
	}

	exitChan := make(chan os.Signal, 1)
	signal.Notify(exitChan, syscall.SIGTERM)

	<-exitChan
}
