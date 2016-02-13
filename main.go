package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/milosgajdos83/tenus"
	"github.com/songgao/water"
	"golang.org/x/net/ipv4"
)

const (
	// I use TUN interface, so only plain IP packet, no ethernet header + mtu is set to 1300
	BUFFERSIZE = 1500
	MTU        = 1300
)

var (
	localIP = flag.String("local", "", "Local tun interface IP/MASK like 192.168.3.3/24")
)

func main() {
	flag.Parse()
	initConfig()

	if "" == *localIP {
		flag.Usage()
		log.Fatalln("\nlocal ip is not specified")
	}

	lIP, lNet, err := net.ParseCIDR(*localIP)
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

	log.Println("Interface parameters configured")

	// listen to local socket...
	// TODO check if reopen socket is needed after config reload
	lstnAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%v", config.Load().(VPNState).Main.Port))
	if nil != err {
		log.Fatalln("Unable to get UDP socket:", err)
	}

	lstnConn, err := net.ListenUDP("udp", lstnAddr)
	if nil != err {
		log.Fatalln("Unable to listen on UDP socket:", err)
	}
	defer lstnConn.Close()

	// only one thread for now
	go func() {
		buf := make([]byte, 1500)
		for {
			n, _, err := lstnConn.ReadFromUDP(buf)

			if err != nil {
				fmt.Println("Error: ", err)
				continue
			}

			// ReadFromUDP can return 0 bytes on timeout
			if 0 == n {
				continue
			}

			if n%aes.BlockSize != 0 {
				fmt.Println("packet size ", n, " is not a multiple of the block size")
				continue
			}

			iv := buf[:aes.BlockSize]
			ciphertext := buf[aes.BlockSize:n]

			mode := cipher.NewCBCDecrypter(config.Load().(VPNState).Main.block, iv)

			mode.CryptBlocks(ciphertext, ciphertext)

			iface.Write(ciphertext[2:(2 + int(ciphertext[0]) + (256 * int(ciphertext[1])))])
		}
	}()

	var packet IPPacket = make([]byte, BUFFERSIZE)
	for {
		plen, err := iface.Read(packet[2:])
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
		addr, ok := c.remotes[dst]
		if ok || dst == c.Main.bcastIP || packet.IsMulticast() {
			// store orig packet len
			packet[0] = byte(plen % 256)
			packet[1] = byte(plen / 256)

			// encrypt
			clen := plen + 2

			if clen%aes.BlockSize != 0 {
				clen += aes.BlockSize - (clen % aes.BlockSize)
			}

			ciphertext := make([]byte, aes.BlockSize+clen)
			iv := ciphertext[:aes.BlockSize]
			if _, err := io.ReadFull(rand.Reader, iv); err != nil {
				log.Println("Unable to get rand data:", err)
				continue
			}

			mode := cipher.NewCBCEncrypter(c.Main.block, iv)
			mode.CryptBlocks(ciphertext[aes.BlockSize:], packet[:clen])

			if ok {
				n, err := lstnConn.WriteToUDP(ciphertext, addr)
				if nil != err {
					log.Println("Error sending package:", err)
				}
				if n != len(ciphertext) {
					log.Println("Only ", n, " bytes of ", len(ciphertext), " sent")
				}
			} else {
				// multicast or broadcast
				for _, addr := range c.remotes {
					n, err := lstnConn.WriteToUDP(ciphertext, addr)
					if nil != err {
						log.Println("Error sending package:", err)
					}
					if n != len(ciphertext) {
						log.Println("Only ", n, " bytes of ", len(ciphertext), " sent")
					}
				}
			}
		} else {
			fmt.Println("Unknown dst", dst)
		}
	}

}
