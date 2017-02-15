package main

import (
	"net"
)

// IPPacket offers some functions working with IPv4 (!) IP packets
type IPPacket []byte

// IPver retrusn 4 or 6 for IPv4 or IPv6
func (p *IPPacket) IPver() int {
	if 4 == ((*p)[2] >> 4) {
		return 4
	}
	if 6 == ((*p)[2] >> 4) {
		return 6
	}
	return 0

}

// Dst returns [4]byte for destination of package
func (p *IPPacket) Dst() [4]byte {
	return [4]byte{(*p)[18], (*p)[19], (*p)[20], (*p)[21]}
}

// DstV4 returns net.IP for destination of package
func (p *IPPacket) DstV4() net.IP {
	return net.IPv4((*p)[18], (*p)[19], (*p)[20], (*p)[21])
}

// Src returns [4]byte for source address of package
func (p *IPPacket) Src() [4]byte {
	return [4]byte{(*p)[14], (*p)[15], (*p)[16], (*p)[17]}
}

// IsMulticast returns if IP destination looks like multicast
func (p *IPPacket) IsMulticast() bool {
	return ((*p)[18] > 223) && ((*p)[18] < 240)
}
