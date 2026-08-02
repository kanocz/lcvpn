package main

import (
	"log"
	"net"
)

func configuredRouteSet(routes map[*net.IPNet]*net.UDPAddr) map[string]bool {
	result := make(map[string]bool, len(routes))
	for route := range routes {
		result[route.String()] = true
	}
	return result
}

// reconcileRoutes changes bookkeeping only after the corresponding OS
// operation succeeds. Failed operations remain pending for the next reload.
func reconcileRoutes(
	current map[string]bool,
	desired map[string]bool,
	addRoute func(string) error,
	deleteRoute func(string) error,
) {
	for route := range desired {
		if current[route] {
			continue
		}
		log.Println("Adding route:", route)
		if err := addRoute(route); err != nil {
			log.Println("Adding route", route, "failed:", err)
			continue
		}
		current[route] = true
	}

	for route := range current {
		if desired[route] {
			continue
		}
		log.Println("Removing route:", route)
		if err := deleteRoute(route); err != nil {
			log.Printf("Removing route %q failed: %s", route, err)
			continue
		}
		delete(current, route)
	}
}
