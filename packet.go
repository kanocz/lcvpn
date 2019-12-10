package main

import (
	"net"
)

// IPPacket offers some functions working with IPv4 (!) IP packets
// packed for transmission wrapped into UDP
type IPPacket []byte

func (p *IPPacket) GetSize() int {
	return int((*p)[3]) | (int((*p)[2]) << 8)
}

// IPver returns 4 or 6 for IPv4 or IPv6
func (p *IPPacket) IPver() int {
	if 4 == ((*p)[0] >> 4) {
		return 4
	}
	if 6 == ((*p)[0] >> 4) {
		return 6
	}
	return 0

}

// Dst returns [4]byte for destination of package
func (p *IPPacket) Dst() [4]byte {
	return [4]byte{(*p)[16], (*p)[17], (*p)[18], (*p)[19]}
}

// DstV4 returns net.IP for destination of package
func (p *IPPacket) DstV4() net.IP {
	return net.IPv4((*p)[16], (*p)[17], (*p)[18], (*p)[19])
}

// Src returns [4]byte for source address of package
func (p *IPPacket) Src() [4]byte {
	return [4]byte{(*p)[12], (*p)[13], (*p)[14], (*p)[15]}
}

// IsMulticast returns if IP destination looks like multicast
func (p *IPPacket) IsMulticast() bool {
	return ((*p)[16] > 223) && ((*p)[16] < 240)
}
