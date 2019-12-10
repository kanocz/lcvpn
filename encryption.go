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
	ePacketInvalidSize = errors.New("Stored packet size bigger then packet itself")
)

func DecryptV4Chk(e PacketEncrypter, src []byte, dst []byte) (int, error) {
	num, err := e.Decrypt(src, dst)
	if nil != err {
		return 0, err
	}

	// 2 bytes size + 20 bytes ip header
	if num < 22 {
		return 0, ePacketSmall
	}

	if (*IPPacket)(&dst).IPver() != 4 {
		return 0, ePacketNonIPv4
	}

	size := (*IPPacket)(&dst).GetSize()
	if size > num {
		return 0, ePacketInvalidSize
	}

	return size, nil
}
