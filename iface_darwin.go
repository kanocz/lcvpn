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

				if err := exec.Command("route", "add", "-net", rs, "-interface", ifaceName).Run(); err != nil {
					log.Println("Adding route", rs, "failed:", err)
				}
			}
		}

		for r := range routes2Del {
			delete(currentRoutes, r)
			log.Println("Removing route:", r)
			if err := exec.Command("route", "delete", "-net", r, "-interface", ifaceName).Run(); err != nil {
				log.Printf("Error removeing route \"%s\": %s", r, err.Error())
			}
		}
	}
}
