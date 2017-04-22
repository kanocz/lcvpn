package main

// PacketEncrypter represents wraper for encryption alg
type PacketEncrypter interface {
	Encrypt(input []byte, output []byte, iv []byte) int
	Decrypt(input []byte, output []byte) int

	CheckSize(size int) bool
	AdjustInputSize(size int) int

	// OutputAdd returns number of bytes will be added after encryption
	OutputAdd() int

	// IVLen returs bytes needed to store IV or other state
	IVLen() int
}

type newEncrypterFunc func(string) (PacketEncrypter, error)

var (
	registredEncrypters = make(map[string]newEncrypterFunc)
)
