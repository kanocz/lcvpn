package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
)

const legacyAesCbcUnsafeName = "legacy-aescbc-unsafe"

// legacyAesCbcUnsafe implements unauthenticated AES-CBC encryption-decryption.
// It is retained only for wire compatibility with legacy deployments.
type legacyAesCbcUnsafe struct {
	c cipher.Block
}

func newLegacyAesCbcUnsafe(key string) (PacketEncrypter, error) {

	if "" == key {
		return nil, errors.New("key is empty")
	}

	bkey, err := hex.DecodeString(key)
	if nil != err {
		return nil, errors.New("not valid hex string")
	}

	if (len(bkey) != 16) && (len(bkey) != 24) && (len(bkey) != 32) {
		return nil, errors.New(`Length of key must be 16, 24 or 32 bytes
		(32, 48 or 64 hex symbols)
		to select AES-128, AES-192 or AES-256`)
	}

	a := legacyAesCbcUnsafe{}
	a.c, err = aes.NewCipher(bkey)
	if nil != err {
		return nil, err
	}

	return &a, nil
}

func (a *legacyAesCbcUnsafe) CheckSize(size int) bool {
	return size > aes.BlockSize && size%aes.BlockSize == 0
}

func (a *legacyAesCbcUnsafe) AdjustInputSize(size int) int {
	if size%aes.BlockSize != 0 {
		return size + (aes.BlockSize - (size % aes.BlockSize))
	}
	return size
}

func (a *legacyAesCbcUnsafe) Encrypt(input []byte, output []byte, iv []byte) int {
	copy(output[:aes.BlockSize], iv)
	cipher.NewCBCEncrypter(a.c, iv).CryptBlocks(output[aes.BlockSize:], input)

	inputLen := len(input)
	// whole len of output is len(input) + aes.BlockSize,
	// so copy of last aes.BlockSize
	copy(iv, output[inputLen:])
	return inputLen + aes.BlockSize
}

func (a *legacyAesCbcUnsafe) Decrypt(input []byte, output []byte) (int, error) {
	resultLen := len(input) - aes.BlockSize
	cipher.NewCBCDecrypter(a.c, input[:aes.BlockSize]).
		CryptBlocks(output, input[aes.BlockSize:])
	return resultLen, nil
}

func (a *legacyAesCbcUnsafe) OutputAdd() int {
	// adding IV to each message
	return aes.BlockSize
}

func (a *legacyAesCbcUnsafe) IVLen() int {
	return aes.BlockSize
}

func init() {
	registeredEncrypters[legacyAesCbcUnsafeName] = newLegacyAesCbcUnsafe
}
