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

// VPNState represents config mixed with pre-parsed values
type VPNState struct {
	Main struct {
		Port        int
		AesKey      string
		AltKey      string
		Broadcast   string
		NetCIDR     int
		RecvThreads int
		SendThreads int

		// filled by readConfig
		bcastIP  [4]byte
		block    cipher.Block
		hasalt   bool
		altblock cipher.Block
		local    string
	}
	Remote map[string]*struct {
		ExtIP string
		LocIP string
		Route []string
	}
	// filled by readConfig
	remotes map[[4]byte]*net.UDPAddr
	routes  map[*net.IPNet]*net.UDPAddr
}

var (
	configfile = flag.String("config", "/etc/lcvpn.conf", "Config file")
	local      = flag.String("local", "", "ID from \"remotes\" which idtenify this host [default: autodetect]")
	config     atomic.Value
)

func getLocalIPsMap() map[string]bool {
	result := map[string]bool{}

	ipnetlist, err := net.InterfaceAddrs()
	if nil != err {
		return result
	}

	for _, _ipnet := range ipnetlist {
		if ipnet, ok := _ipnet.(*net.IPNet); ok {
			result[ipnet.IP.String()] = true
		}
	}

	return result
}

func readConfig() error {
	var newConfig VPNState

	err := gcfg.ReadFileInto(&newConfig, *configfile)
	if nil != err {
		return fmt.Errorf("Error reading config \"%s\" %s", *configfile, err)
	}
	if newConfig.Main.Port < 1 || newConfig.Main.Port > 65535 {
		return errors.New("main.port is invalid in config")
	}
	if newConfig.Main.NetCIDR < 8 || newConfig.Main.NetCIDR > 30 {
		return errors.New("netCIDR can't be less than 8 or greater than 30")
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

	if "" != newConfig.Main.AltKey {
		key, err := hex.DecodeString(newConfig.Main.AltKey)
		if nil != err {
			return errors.New("main.altkey is not valid hex string")
		}
		if (len(key) != 16) && (len(key) != 24) && (len(key) != 32) {
			return errors.New("Length of altkey must be 16, 24 or 32 bytes (32, 48 or 64 hex symbols) to select AES-128, AES-192 or AES-256")
		}
		newConfig.Main.altblock, err = aes.NewCipher(key)
		if nil != err {
			return err
		}
		newConfig.Main.hasalt = true
	} else {
		newConfig.Main.hasalt = false
	}

	// local ip detect or select
	if "" != *local {
		host, ok := newConfig.Remote[*local]
		if !ok {
			return fmt.Errorf("Remote with id \"%s\" not found in %s", *local, *configfile)
		}
		newConfig.Main.local = fmt.Sprintf("%s/%d", host.LocIP, newConfig.Main.NetCIDR)

		// we don't need it in routes and so on
		delete(newConfig.Remote, *local)
	} else {
		ips := getLocalIPsMap()
		for name, r := range newConfig.Remote {
			if _, ok := ips[r.ExtIP]; ok {
				newConfig.Main.local = fmt.Sprintf("%s/%d", r.LocIP, newConfig.Main.NetCIDR)
				log.Printf("%s (%s) is detected as local ip\n", newConfig.Main.local, name)
				// we don't need it in routes and so on
				delete(newConfig.Remote, name)
				break
			}
		}
		if "" == newConfig.Main.local {
			return errors.New("Local ip can't be detected")
		}
	}

	newConfig.remotes = make(map[[4]byte]*net.UDPAddr, len(newConfig.Remote))
	newConfig.routes = map[*net.IPNet]*net.UDPAddr{}

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

		for _, routestr := range r.Route {
			_, route, err := net.ParseCIDR(routestr)
			if nil != err {
				return fmt.Errorf("Invalid route %s for %s", routestr, name)
			}
			newConfig.routes[route] = rmtAddr
		}
	}

	xBcastIP := net.ParseIP(newConfig.Main.Broadcast)
	if nil != xBcastIP {
		newConfig.Main.bcastIP = [4]byte{xBcastIP[12], xBcastIP[13], xBcastIP[14], xBcastIP[15]}
	}

	if newConfig.Main.RecvThreads < 1 {
		newConfig.Main.RecvThreads = 1
	}

	if newConfig.Main.SendThreads < 1 {
		newConfig.Main.SendThreads = 1
	}

	config.Store(newConfig)

	return nil
}

func initConfig(routeReload chan bool) {
	err := readConfig()
	if nil != err {
		log.Fatalln("Error loading config:", err)
	}
	routeReload <- true

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
				routeReload <- true
			}
		}
	}()
}
