package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"

	"gopkg.in/gcfg.v1"
)

type VPNState struct {
	Main struct {
		Port   int
		AesKey string
		block  cipher.Block
	}
	Remote map[string]*struct {
		ExtIP string
		LocIP string
	}
	remotes map[[4]byte]*net.UDPAddr
}

var (
	configfile = flag.String("config", "lcvpn.conf", "Config file")
	config     atomic.Value
)

func readConfig() error {
	var newConfig VPNState

	err := gcfg.ReadFileInto(&newConfig, *configfile)
	if nil != err {
		return errors.New(fmt.Sprintf("Error reading config \"%s\" %s", *configfile, err))
	}
	if newConfig.Main.Port < 1 || newConfig.Main.Port > 65535 {
		return errors.New("main.port is invalid in config")
	}
	if "" == newConfig.Main.AesKey {
		return errors.New("main.aeskey is empty")
	}
	key, err := hex.DecodeString(newConfig.Main.AesKey)
	if nil != err {
		return errors.New("main.aeskey is not valid hex string")
	}
	if (len(key) != 16) && (len(key) != 24) && (len(key) != 32) {
		return errors.New("Length of aeskey must be 16, 24 or 32 bytes (32, 48 or 64 hex symbols) to select AES-128, AES-192 or AES-256")
	}
	newConfig.Main.block, err = aes.NewCipher(key)
	if nil != err {
		return err
	}

	newConfig.remotes = make(map[[4]byte]*net.UDPAddr, len(newConfig.Remote))
	for name, r := range newConfig.Remote {

		rmtAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", r.ExtIP, newConfig.Main.Port))
		if nil != err {
			return err
		}

		xLocalIP := net.ParseIP(r.LocIP)
		if nil == xLocalIP {
			log.Fatalln("Invalid local ip", r.LocIP, "for server", name)
		}

		newConfig.remotes[[4]byte{xLocalIP[12], xLocalIP[13], xLocalIP[14], xLocalIP[15]}] = rmtAddr
	}

	config.Store(newConfig)

	return nil
}

func initConfig() {
	err := readConfig()
	if nil != err {
		log.Fatalln("Error loading config:", err)
	}

	// setup reloading on HUP signal
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP)
	go func() {
		for _ = range c {
			err := readConfig()
			if nil != err {
				log.Println("Config reload failed:", err)
			} else {
				log.Println("Config reloaded")
			}
		}
	}()
}
