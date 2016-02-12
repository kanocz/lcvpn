package main

type IPPacket []byte

func (p *IPPacket) IPver() int {
	if 4 == ((*p)[2] >> 4) {
		return 4
	}
	if 6 == ((*p)[2] >> 4) {
		return 6
	}
	return 0

}

func (p *IPPacket) Dst() [4]byte {
	return [4]byte{(*p)[18], (*p)[19], (*p)[20], (*p)[21]}
}

func (p *IPPacket) Src() [4]byte {
	return [4]byte{(*p)[14], (*p)[15], (*p)[16], (*p)[17]}
}

func (p *IPPacket) IsMulticast() bool {
	return ((*p)[18] > 223) && ((*p)[18] < 240)
}
