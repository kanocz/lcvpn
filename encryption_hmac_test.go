package main

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"testing"
)

const testAesCbcHmacKey = "00112233445566778899aabbccddeeff" +
	"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

func encryptHMACTestPacket(t *testing.T, input []byte) (PacketEncrypter, []byte) {
	t.Helper()

	e, err := newAesCbcHmac(testAesCbcHmacKey)
	if err != nil {
		t.Fatal(err)
	}
	if e.AdjustInputSize(len(input)) != len(input) {
		t.Fatal("test input must already be block aligned")
	}

	iv := bytes.Repeat([]byte{0x42}, e.IVLen())
	output := make([]byte, len(input)+e.OutputAdd())
	size := e.Encrypt(input, output, iv)
	return e, output[:size]
}

func TestAesCbcHmacRoundTrip(t *testing.T) {
	plain := bytes.Repeat([]byte{0x23}, 32)
	e, encrypted := encryptHMACTestPacket(t, plain)
	decrypted := make([]byte, len(plain))

	size, err := e.Decrypt(encrypted, decrypted)
	if err != nil {
		t.Fatal(err)
	}
	if size != len(plain) {
		t.Fatalf("Decrypt() size = %d, want %d", size, len(plain))
	}
	if !bytes.Equal(decrypted[:size], plain) {
		t.Fatal("decrypted plaintext differs from input")
	}
}

func TestAesCbcHmacRejectsTampering(t *testing.T) {
	plain := bytes.Repeat([]byte{0x23}, 32)
	tests := []struct {
		name  string
		index int
	}{
		{name: "iv", index: 0},
		{name: "ciphertext", index: 20},
		{name: "tag", index: len(plain) + 16},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, encrypted := encryptHMACTestPacket(t, plain)
			encrypted[tt.index] ^= 0xff
			_, err := e.Decrypt(encrypted, make([]byte, len(plain)))
			if !errors.Is(err, HMACError) {
				t.Fatalf("Decrypt() error = %v, want %v", err, HMACError)
			}
		})
	}
}

func TestAesCbcHmacRejectsWrongKey(t *testing.T) {
	plain := bytes.Repeat([]byte{0x23}, 32)
	_, encrypted := encryptHMACTestPacket(t, plain)

	other, err := newAesCbcHmac(strings.Repeat("ff", 48))
	if err != nil {
		t.Fatal(err)
	}
	_, err = other.Decrypt(encrypted, make([]byte, len(plain)))
	if !errors.Is(err, HMACError) {
		t.Fatalf("Decrypt() error = %v, want %v", err, HMACError)
	}
}

func TestAesCbcHmacConcurrentUse(t *testing.T) {
	e, err := newAesCbcHmac(testAesCbcHmacKey)
	if err != nil {
		t.Fatal(err)
	}
	plain := bytes.Repeat([]byte{0x23}, 32)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(marker byte) {
			defer wg.Done()
			iv := bytes.Repeat([]byte{marker}, e.IVLen())
			encrypted := make([]byte, len(plain)+e.OutputAdd())
			size := e.Encrypt(plain, encrypted, iv)
			decrypted := make([]byte, len(plain))
			got, err := e.Decrypt(encrypted[:size], decrypted)
			if err != nil {
				t.Errorf("Decrypt() error = %v", err)
				return
			}
			if !bytes.Equal(decrypted[:got], plain) {
				t.Error("decrypted plaintext differs from input")
			}
		}(byte(i))
	}
	wg.Wait()
}
