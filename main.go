package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
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
	readConfig()

	if "" == *localIP {
		flag.Usage()
		log.Fatalln("\nlocal ip is not specified")
	}

	lIP, lNet, err := net.ParseCIDR(*localIP)
	if nil != err {
		flag.Usage()
		log.Fatalln("\nlocal ip is not in ip/cidr format")
	}

	if "" == config.Main.AesKey {
		log.Fatalln("main.aeskey is empty")
	}

	key, err := hex.DecodeString(config.Main.AesKey)
	if nil != err {
		log.Fatalln("Error unhexing key:", err)
	}

	if (len(key) != 16) && (len(key) != 24) && (len(key) != 32) {
		log.Fatalln("Length of aeskey must be 16, 24 or 32 bytes (32, 48 or 64 hex symbols) to select AES-128, AES-192 or AES-256")
	}

	block, err := aes.NewCipher(key)
	if nil != err {
		log.Fatalln("NewCipher failed:", err)
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

	// listen to local socket
	lstnAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%v", config.Main.Port))
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
			// n, addr, err := lstnConn.ReadFromUDP(buf)
			// fmt.Println("Received ", n, " bytes from ", addr)

			if err != nil {
				fmt.Println("Error: ", err)
				continue
			}

			if 0 == n {
				continue
			}

			if n%aes.BlockSize != 0 {
				fmt.Println("packet size ", n, " is not a multiple of the block size")
				continue
			}

			iv := buf[:aes.BlockSize]
			ciphertext := buf[aes.BlockSize:n]

			mode := cipher.NewCBCDecrypter(block, iv)

			mode.CryptBlocks(ciphertext, ciphertext)

			iface.Write(ciphertext[2:(2 + int(ciphertext[0]) + (256 * int(ciphertext[1])))])
		}
	}()

	remotes := map[[4]byte]*net.UDPConn{}

	for name, r := range config.Remote {
		fmt.Printf("%s: %+v\n", name, *r)

		locAddr, err := net.ResolveUDPAddr("udp", ":")
		if nil != err {
			log.Fatalln("Stupid error #1")
		}

		rmtAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", r.ExtIP, config.Main.Port))
		if nil != err {
			log.Fatalln("Invalid addres for server", name, ":", err)
		}

		conn, err := net.DialUDP("udp", locAddr, rmtAddr)
		if nil != err {
			log.Fatalln("Unable to create outbound socket for server", name, ":", err)
		}
		defer conn.Close()

		xLocalIP := net.ParseIP(r.LocIP)
		if nil == xLocalIP {
			log.Fatalln("Invalid local ip", r.LocIP, "for server", name)
		}
		remotes[[4]byte{xLocalIP[12], xLocalIP[13], xLocalIP[14], xLocalIP[15]}] = conn
	}

	fmt.Printf("%+v\n", remotes)

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

		// TODO something with multicast... does anybody needs them? :D
		if packet.IsMulticast() {
			continue
		}

		// src := packet.Src()
		dst := packet.Dst()
		// fmt.Print(src, " -> ", dst)

		conn, ok := remotes[dst]
		if ok {
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

			mode := cipher.NewCBCEncrypter(block, iv)
			mode.CryptBlocks(ciphertext[aes.BlockSize:], packet[:clen])

			conn.Write(ciphertext)
		} else {
			fmt.Println("Unknown dst", dst)

		}

		// header, _ := ipv4.ParseHeader(packet[2:])
		// fmt.Printf("%+v (%+v)\n", header, err)
	}

}
