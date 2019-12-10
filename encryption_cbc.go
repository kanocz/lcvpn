package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
)

// aescbc implements plain AES-CBC encryption-decryption
type aescbc struct {
	c cipher.Block
}

func newAesCbc(key string) (PacketEncrypter, error) {

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

	a := aescbc{}
	a.c, err = aes.NewCipher(bkey)
	if nil != err {
		return nil, err
	}

	return &a, nil
}

func (a *aescbc) CheckSize(size int) bool {
	return size > aes.BlockSize && size%aes.BlockSize == 0
}

func (a *aescbc) AdjustInputSize(size int) int {
	if size%aes.BlockSize != 0 {
		return size + (aes.BlockSize - (size % aes.BlockSize))
	}
	return size
}

func (a *aescbc) Encrypt(input []byte, output []byte, iv []byte) int {
	copy(output[:aes.BlockSize], iv)
	cipher.NewCBCEncrypter(a.c, iv).CryptBlocks(output[aes.BlockSize:], input)

	inputLen := len(input)
	// whole len of output is len(input) + aes.BlockSize,
	// so copy of last aes.BlockSize
	copy(iv, output[inputLen:])
	return inputLen + aes.BlockSize
}

func (a *aescbc) Decrypt(input []byte, output []byte) (int, error) {
	resultLen := len(input) - aes.BlockSize
	cipher.NewCBCDecrypter(a.c, input[:aes.BlockSize]).
		CryptBlocks(output, input[aes.BlockSize:])
	return resultLen, nil
}

func (a *aescbc) OutputAdd() int {
	// adding IV to each message
	return aes.BlockSize
}

func (a *aescbc) IVLen() int {
	return aes.BlockSize
}

func init() {
	registeredEncrypters["aescbc"] = newAesCbc
}
