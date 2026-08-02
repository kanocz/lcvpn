package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

type failingPacketInterface struct {
	err error
}

func (f failingPacketInterface) Read([]byte) (int, error) {
	return 0, f.err
}

func (f failingPacketInterface) Write(packet []byte) (int, error) {
	return len(packet), nil
}

func TestRefreshIVHandlesEncryptionModeChanges(t *testing.T) {
	none := &encnone{}
	aesEncrypter, err := newLegacyAesCbcUnsafe(strings.Repeat("00", 16))
	if err != nil {
		t.Fatal(err)
	}
	entropy := append(bytes.Repeat([]byte{0x11}, 16), bytes.Repeat([]byte{0x22}, 16)...)
	random := bytes.NewReader(entropy)

	iv, err := refreshIV(none, nil, random)
	if err != nil || len(iv) != 0 {
		t.Fatalf("none IV = %x, %v; want empty, nil", iv, err)
	}
	iv, err = refreshIV(aesEncrypter, iv, random)
	if err != nil || !bytes.Equal(iv, bytes.Repeat([]byte{0x11}, 16)) {
		t.Fatalf("first AES IV = %x, %v", iv, err)
	}
	iv, err = refreshIV(aesEncrypter, iv, random)
	if err != nil || !bytes.Equal(iv, bytes.Repeat([]byte{0x22}, 16)) {
		t.Fatalf("second AES IV = %x, %v", iv, err)
	}
	iv, err = refreshIV(none, iv, random)
	if err != nil || len(iv) != 0 {
		t.Fatalf("AES to none IV = %x, %v; want empty, nil", iv, err)
	}
}

func TestRefreshIVReturnsEntropyError(t *testing.T) {
	aesEncrypter, err := newLegacyAesCbcUnsafe(strings.Repeat("00", 16))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := refreshIV(aesEncrypter, nil, bytes.NewReader([]byte{1})); err == nil {
		t.Fatal("refreshIV() accepted insufficient entropy")
	}
}

func TestSenderThreadReturnsInterfaceReadError(t *testing.T) {
	want := errors.New("TUN read failed")
	err := sndrThread(nil, failingPacketInterface{err: want}, newPacketSender())
	if !errors.Is(err, want) {
		t.Fatalf("sndrThread() error = %v, want %v", err, want)
	}
}
