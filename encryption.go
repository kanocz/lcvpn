package main

import (
	"errors"
)

// PacketEncrypter represents wrapper for encryption alg
type PacketEncrypter interface {
	Encrypt(input []byte, output []byte, iv []byte) int
	Decrypt(input []byte, output []byte) (int, error)

	CheckSize(size int) bool
	AdjustInputSize(size int) int

	// OutputAdd returns number of bytes will be added after encryption
	OutputAdd() int

	// IVLen returns bytes needed to store IV or other state
	IVLen() int
}

type newEncrypterFunc func(string) (PacketEncrypter, error)

var (
	registeredEncrypters = make(map[string]newEncrypterFunc)

	// predefined errors
	ePacketSmall       = errors.New("Packet too small")
	ePacketNonIPv4     = errors.New("Non IPv4 packet")
	ePacketInvalidHdr  = errors.New("Invalid IPv4 header")
	ePacketInvalidSize = errors.New("Stored packet size bigger then packet itself")
)

func validateIPv4Packet(packet IPPacket) (int, error) {
	if len(packet) < 20 {
		return 0, ePacketSmall
	}
	if packet.IPver() != 4 {
		return 0, ePacketNonIPv4
	}

	headerLen := int(packet[0]&0x0f) * 4
	if headerLen < 20 || headerLen > len(packet) {
		return 0, ePacketInvalidHdr
	}

	size := packet.GetSize()
	if size < headerLen {
		return 0, ePacketInvalidHdr
	}
	if size > len(packet) {
		return 0, ePacketInvalidSize
	}
	return size, nil
}

func DecryptV4Chk(
	e PacketEncrypter,
	src []byte,
	dst []byte,
	replay *replayProtector,
	recipient [packetRecipientSize]byte,
) (int, error) {
	num, err := e.Decrypt(src, dst)
	if nil != err {
		return 0, err
	}

	frame, err := parsePacketFrame(dst[:num])
	if nil != err {
		return 0, err
	}
	if frame.recipient != recipient {
		return 0, errPacketRecipient
	}
	payload := IPPacket(frame.payload)

	size, err := validateIPv4Packet(payload)
	if nil != err {
		return 0, err
	}
	if replay != nil && !replay.Accept(frame.session, frame.sequence) {
		return 0, errPacketReplay
	}

	copy(dst[:size], payload[:size])
	return size, nil
}
