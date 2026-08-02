//go:build darwin
// +build darwin

package main

import (
	"log"
	"os/exec"
	"strconv"

	"github.com/songgao/water"
)

const (
	// MTU used for tunneled packets
	MTU = 1300
)

// ifaceSetup returns new interface OR PANIC!
func ifaceSetup(localCIDR string) *water.Interface {

	iface, err := water.New(water.Config{DeviceType: water.TUN})

	if nil != err {
		log.Println("Unable to allocate TUN interface:", err)
		panic(err)
	}

	log.Println("Interface allocated:", iface.Name())

	if err := exec.Command("ifconfig", iface.Name(), "inet", localCIDR, "mtu", strconv.FormatInt(MTU, 10), "up").Run(); err != nil {
		log.Fatalln("Unable to setup interface:", err)
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
			func(route string) error {
				return exec.Command("route", "add", "-net", route, "-interface", ifaceName).Run()
			},
			func(route string) error {
				return exec.Command("route", "delete", "-net", route, "-interface", ifaceName).Run()
			},
		)
	}
}
