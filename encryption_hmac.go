package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
)

// aescbchmac implements plain AES-CBC+HMAC encryption-decryption
type aescbchmac struct {
	c        cipher.Block
	h        hash.Hash
	hashsize int
}

var (
	HMACError = errors.New("HMAC validation failed")
)

func newAesCbcHmac(key string) (PacketEncrypter, error) {

	if "" == key {
		return nil, errors.New("key is empty")
	}

	bkey, err := hex.DecodeString(key)
	if nil != err {
		return nil, errors.New("not valid hex string")
	}

	lbkey := len(bkey)
	if (lbkey != 48) && (lbkey != 56) && (lbkey != 64) {
		return nil, errors.New(`Length of key must be 48, 56 or 64 bytes
		(96, 112 or 128 hex symbols)
		to select AES-128, AES-192 or AES-256 (+ 32 for HMAC sha256 key)`)
	}

	a := aescbchmac{}
	a.c, err = aes.NewCipher(bkey[0 : lbkey-32])
	if nil != err {
		return nil, err
	}
	a.h = hmac.New(sha256.New, bkey[lbkey-32:])

	a.hashsize = a.h.Size()

	return &a, nil
}

func (a *aescbchmac) CheckSize(size int) bool {
	return size > (aes.BlockSize+a.hashsize) && size%aes.BlockSize == 0
}

func (a *aescbchmac) AdjustInputSize(size int) int {
	if size%aes.BlockSize != 0 {
		return size + (aes.BlockSize - (size % aes.BlockSize))
	}
	return size
}

func (a *aescbchmac) Encrypt(input []byte, output []byte, iv []byte) int {
	copy(output[:aes.BlockSize], iv)
	cipher.NewCBCEncrypter(a.c, iv).CryptBlocks(output[aes.BlockSize:], input)

	inputLen := len(input)
	// whole len of output is len(input) + aes.BlockSize,
	// so copy of last aes.BlockSize
	copy(iv, output[inputLen:])
	sum := a.h.Sum(output[:inputLen+aes.BlockSize])
	copy(output[inputLen+aes.BlockSize:], sum[:a.hashsize])

	return inputLen + aes.BlockSize + a.hashsize
}

func (a *aescbchmac) Decrypt(input []byte, output []byte) (int, error) {
	msgLen := len(input) - a.hashsize
	test := a.h.Sum(input[:msgLen])
	if !hmac.Equal(input[msgLen:], test[len(test)-a.hashsize:]) {
		return 0, HMACError
	}

	resultLen := msgLen - aes.BlockSize
	cipher.NewCBCDecrypter(a.c, input[:aes.BlockSize]).
		CryptBlocks(output, input[aes.BlockSize:aes.BlockSize+resultLen])
	return resultLen, nil
}

func (a *aescbchmac) OutputAdd() int {
	// adding IV and HMAC-SHA256 to each message
	return aes.BlockSize + a.hashsize
}

func (a *aescbchmac) IVLen() int {
	return aes.BlockSize
}

func init() {
	registeredEncrypters["aescbchmac"] = newAesCbcHmac
}
