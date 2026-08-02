package main

import (
	"bytes"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func TestPacketSenderUsesPerPeerSequenceSpaces(t *testing.T) {
	sender := newPacketSender()
	packet := []byte{1, 2, 3}
	output := make([]byte, packetFrameHeaderSize+len(packet))
	recipient := [packetRecipientSize]byte{192, 0, 2, 1}

	n, err := sender.Frame("peer-a", recipient, packet, output)
	if err != nil {
		t.Fatal(err)
	}
	first, err := parsePacketFrame(output[:n])
	if err != nil {
		t.Fatal(err)
	}

	n, err = sender.Frame("peer-a", recipient, packet, output)
	if err != nil {
		t.Fatal(err)
	}
	second, err := parsePacketFrame(output[:n])
	if err != nil {
		t.Fatal(err)
	}
	if first.session != second.session || first.sequence != 1 || second.sequence != 2 {
		t.Fatalf("same-peer stream = (%x, %d), (%x, %d)", first.session, first.sequence, second.session, second.sequence)
	}

	n, err = sender.Frame("peer-b", recipient, packet, output)
	if err != nil {
		t.Fatal(err)
	}
	other, err := parsePacketFrame(output[:n])
	if err != nil {
		t.Fatal(err)
	}
	if other.sequence != 1 {
		t.Fatalf("other peer sequence = %d, want 1", other.sequence)
	}
	if other.session == first.session {
		t.Fatal("different peers unexpectedly share a session")
	}
	if !bytes.Equal(other.payload, packet) {
		t.Fatal("frame payload differs from packet")
	}
}

func TestReplayProtectorWindow(t *testing.T) {
	protector := newReplayProtector()
	var session [packetSessionSize]byte
	session[0] = 1

	tests := []struct {
		sequence uint64
		want     bool
	}{
		{sequence: 0, want: false},
		{sequence: 2000, want: true},
		{sequence: 2000, want: false},
		{sequence: 1998, want: true},
		{sequence: 1999, want: true},
		{sequence: 1998, want: false},
		{sequence: 1937, want: true},
		{sequence: 2001, want: true},
		{sequence: 1937, want: false},
		{sequence: 978, want: true},
		{sequence: 977, want: false},
		{sequence: 3025, want: true},
		{sequence: 2001, want: false},
	}

	for _, tt := range tests {
		if got := protector.Accept(session, tt.sequence); got != tt.want {
			t.Fatalf("Accept(%d) = %v, want %v", tt.sequence, got, tt.want)
		}
	}
}

func TestReplayProtectorAcceptsDuplicateOnceConcurrently(t *testing.T) {
	protector := newReplayProtector()
	var session [packetSessionSize]byte
	session[0] = 2

	var accepted atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if protector.Accept(session, 1) {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()

	if got := accepted.Load(); got != 1 {
		t.Fatalf("accepted duplicate %d times, want 1", got)
	}
}

func TestAuthenticatedPacketReplayIsRejected(t *testing.T) {
	sender := newPacketSender()
	protector := newReplayProtector()
	framed := make([]byte, BUFFERSIZE)
	recipient := [packetRecipientSize]byte{192, 168, 3, 3}
	frameLen, err := sender.Frame("peer", recipient, testICMPPing, framed)
	if err != nil {
		t.Fatal(err)
	}

	e, err := newAesCbcHmac(testAesCbcHmacKey)
	if err != nil {
		t.Fatal(err)
	}
	plainLen := e.AdjustInputSize(frameLen)
	clear(framed[frameLen:plainLen])
	iv := bytes.Repeat([]byte{0x55}, e.IVLen())
	encrypted := make([]byte, plainLen+e.OutputAdd())
	encryptedLen := e.Encrypt(framed[:plainLen], encrypted, iv)
	decrypted := make([]byte, BUFFERSIZE)

	size, err := DecryptV4Chk(e, encrypted[:encryptedLen], decrypted, protector, recipient)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted[:size], testICMPPing) {
		t.Fatal("decrypted IP packet differs from input")
	}

	reloaded, err := newAesCbcHmac(testAesCbcHmacKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecryptV4Chk(reloaded, encrypted[:encryptedLen], decrypted, protector, recipient)
	if !errors.Is(err, errPacketReplay) {
		t.Fatalf("second DecryptV4Chk() error = %v, want %v", err, errPacketReplay)
	}
}

func TestAuthenticatedPacketRejectsWrongRecipient(t *testing.T) {
	sender := newPacketSender()
	recipient := [packetRecipientSize]byte{192, 0, 2, 1}
	framed := make([]byte, BUFFERSIZE)
	frameLen, err := sender.Frame("peer", recipient, testICMPPing, framed)
	if err != nil {
		t.Fatal(err)
	}

	e, err := newAesCbcHmac(testAesCbcHmacKey)
	if err != nil {
		t.Fatal(err)
	}
	plainLen := e.AdjustInputSize(frameLen)
	clear(framed[frameLen:plainLen])
	iv := bytes.Repeat([]byte{0x66}, e.IVLen())
	encrypted := make([]byte, plainLen+e.OutputAdd())
	encryptedLen := e.Encrypt(framed[:plainLen], encrypted, iv)

	otherRecipient := [packetRecipientSize]byte{192, 0, 2, 2}
	_, err = DecryptV4Chk(e, encrypted[:encryptedLen], make([]byte, BUFFERSIZE), newReplayProtector(), otherRecipient)
	if !errors.Is(err, errPacketRecipient) {
		t.Fatalf("DecryptV4Chk() error = %v, want %v", err, errPacketRecipient)
	}
}
