package main

import (
	"encoding/binary"
	"errors"
	"testing"
)

func makeIPv4Packet(bufferSize, totalLength int, ihl byte) IPPacket {
	packet := make(IPPacket, bufferSize)
	if bufferSize > 0 {
		packet[0] = 4<<4 | ihl
	}
	if bufferSize >= 4 {
		binary.BigEndian.PutUint16(packet[2:4], uint16(totalLength))
	}
	return packet
}

func TestValidateIPv4Packet(t *testing.T) {
	tests := []struct {
		name    string
		packet  IPPacket
		want    int
		wantErr error
	}{
		{name: "minimum header", packet: makeIPv4Packet(20, 20, 5), want: 20},
		{name: "one byte payload", packet: makeIPv4Packet(21, 21, 5), want: 21},
		{name: "header options", packet: makeIPv4Packet(24, 24, 6), want: 24},
		{name: "ignores encryption padding", packet: makeIPv4Packet(32, 20, 5), want: 20},
		{name: "short buffer", packet: makeIPv4Packet(19, 19, 5), wantErr: ePacketSmall},
		{name: "non IPv4", packet: makeIPv4Packet(20, 20, 5), wantErr: ePacketNonIPv4},
		{name: "IHL below minimum", packet: makeIPv4Packet(20, 20, 4), wantErr: ePacketInvalidHdr},
		{name: "IHL exceeds buffer", packet: makeIPv4Packet(20, 24, 6), wantErr: ePacketInvalidHdr},
		{name: "total below IHL", packet: makeIPv4Packet(20, 19, 5), wantErr: ePacketInvalidHdr},
		{name: "total exceeds buffer", packet: makeIPv4Packet(20, 21, 5), wantErr: ePacketInvalidSize},
	}
	tests[5].packet[0] = 6 << 4

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateIPv4Packet(tt.packet)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("validateIPv4Packet() error = %v, want %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("validateIPv4Packet() size = %d, want %d", got, tt.want)
			}
		})
	}
}
