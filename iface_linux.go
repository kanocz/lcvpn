//go:build linux
// +build linux

package main

import (
	"log"
	"net"

	"github.com/kanocz/lcvpn/netlink"
	"github.com/milosgajdos/tenus"
	"github.com/songgao/water"
)

const (
	// MTU used for tunneled packets
	MTU = 1300
)

// ifaceSetup returns new interface OR PANIC!
func ifaceSetup(localCIDR string) *water.Interface {

	lIP, lNet, err := net.ParseCIDR(localCIDR)
	if nil != err {
		log.Fatalln("\nlocal ip is not in ip/cidr format")
		panic("invalid local ip")
	}

	iface, err := water.New(water.Config{DeviceType: water.TUN})

	if nil != err {
		log.Println("Unable to allocate TUN interface:", err)
		panic(err)
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

	return iface
}

func routesThread(ifaceName string, refresh chan bool) {
	currentRoutes := map[string]bool{}
	for {
		<-refresh
		log.Println("Reloading routes...")
		conf := config.Load().(VPNState)
		reconcileRoutes(
			currentRoutes,
			configuredRouteSet(conf.routes),
			func(route string) error { return netlink.AddRoute(route, "", "", ifaceName) },
			func(route string) error { return netlink.DelRoute(route, "", "", ifaceName) },
		)
	}
}
