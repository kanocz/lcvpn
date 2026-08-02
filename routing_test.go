package main

import (
	"net"
	"testing"
)

func mustIPv4Network(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatal(err)
	}
	return network
}

func TestVPNStateRouteForUsesLongestPrefix(t *testing.T) {
	defaultRemote := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1}
	wideRemote := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 2}
	mediumRemote := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 3), Port: 3}
	narrowRemote := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 4), Port: 4}
	state := VPNState{
		routes: map[*net.IPNet]*net.UDPAddr{
			mustIPv4Network(t, "0.0.0.0/0"):   defaultRemote,
			mustIPv4Network(t, "10.0.0.0/8"):  wideRemote,
			mustIPv4Network(t, "10.1.0.0/16"): mediumRemote,
			mustIPv4Network(t, "10.1.2.0/24"): narrowRemote,
		},
	}

	tests := []struct {
		name string
		ip   string
		want *net.UDPAddr
	}{
		{name: "narrow", ip: "10.1.2.99", want: narrowRemote},
		{name: "medium", ip: "10.1.9.1", want: mediumRemote},
		{name: "wide", ip: "10.9.1.1", want: wideRemote},
		{name: "default", ip: "203.0.113.9", want: defaultRemote},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i := 0; i < 100; i++ {
				got, ok := state.routeFor(net.ParseIP(tt.ip))
				if !ok || got != tt.want {
					t.Fatalf("routeFor(%s) = %v, %v; want %v, true", tt.ip, got, ok, tt.want)
				}
			}
		})
	}
}

func TestVPNStateRouteForReturnsFalseWithoutMatch(t *testing.T) {
	state := VPNState{routes: map[*net.IPNet]*net.UDPAddr{
		mustIPv4Network(t, "10.0.0.0/8"): {IP: net.IPv4(192, 0, 2, 1), Port: 1},
	}}
	if got, ok := state.routeFor(net.ParseIP("192.168.1.1")); ok || got != nil {
		t.Fatalf("routeFor() = %v, %v; want nil, false", got, ok)
	}
}
