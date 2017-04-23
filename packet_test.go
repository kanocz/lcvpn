package main

import (
	"net"
	"reflect"
	"testing"
)

var (
	testICMPPing = IPPacket([]byte{0x45, 0x00, 0x00, 0x54, 0x0e, 0xe1, 0x40, 0x00, 0x40, 0x01, 0xa4, 0x65, 0xc0, 0xa8, 0x03, 0x0f, 0xc0, 0xa8, 0x03, 0x03, 0x08, 0x00, 0xad, 0xf2, 0x6a, 0x8c, 0x00, 0x08, 0x4c, 0xee, 0xfc, 0x58, 0xab, 0x2e, 0x00, 0x00, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37})
	testICMPPong = IPPacket([]byte{0x45, 0x00, 0x00, 0x54, 0xed, 0x4e, 0x00, 0x00, 0x40, 0x01, 0x05, 0xf8, 0xc0, 0xa8, 0x03, 0x03, 0xc0, 0xa8, 0x03, 0x0f, 0x00, 0x00, 0xb5, 0xf2, 0x6a, 0x8c, 0x00, 0x08, 0x4c, 0xee, 0xfc, 0x58, 0xab, 0x2e, 0x00, 0x00, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37})
)

func TestIPPacket_IPver(t *testing.T) {
	tests := []struct {
		name string
		p    IPPacket
		want int
	}{
		{
			name: "ping",
			p:    testICMPPing,
			want: 4,
		},
		{
			name: "pong",
			p:    testICMPPong,
			want: 4,
		},
		{
			name: "ipv6",
			p:    IPPacket([]byte{6 << 4, 0}),
			want: 6,
		},
		{
			name: "invalid",
			p:    IPPacket([]byte{3 << 4, 0}),
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.IPver(); got != tt.want {
				t.Errorf("IPPacket.IPver() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIPPacket_Dst(t *testing.T) {
	tests := []struct {
		name string
		p    IPPacket
		want [4]byte
	}{
		{
			name: "ping",
			p:    testICMPPing,
			want: [4]byte{192, 168, 3, 3},
		},
		{
			name: "pong",
			p:    testICMPPong,
			want: [4]byte{192, 168, 3, 15},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.Dst(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("IPPacket.Dst() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIPPacket_DstV4(t *testing.T) {
	tests := []struct {
		name string
		p    IPPacket
		want net.IP
	}{
		{
			name: "ping",
			p:    testICMPPing,
			want: net.ParseIP("192.168.3.3"),
		},
		{
			name: "pong",
			p:    testICMPPong,
			want: net.ParseIP("192.168.3.15"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.DstV4(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("IPPacket.DstV4() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIPPacket_Src(t *testing.T) {
	tests := []struct {
		name string
		p    IPPacket
		want [4]byte
	}{
		{
			name: "ping",
			p:    testICMPPing,
			want: [4]byte{192, 168, 3, 15},
		},
		{
			name: "pong",
			p:    testICMPPong,
			want: [4]byte{192, 168, 3, 3},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.Src(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("IPPacket.Src() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIPPacket_IsMulticast(t *testing.T) {
	tests := []struct {
		name string
		p    IPPacket
		want bool
	}{
		{
			name: "230.0.0.1",
			p:    IPPacket([]byte{4 << 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 230, 0, 0, 1, 0}),
			want: true,
		},
		{
			name: "ping",
			p:    testICMPPing,
			want: false,
		},
		{
			name: "pong",
			p:    testICMPPong,
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.IsMulticast(); got != tt.want {
				t.Errorf("IPPacket.IsMulticast() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIPPacket_GetSize(t *testing.T) {
	tests := []struct {
		name string
		p    IPPacket
		want int
	}{
		{
			name: "ping",
			p:    testICMPPing,
			want: 84,
		},
		{
			name: "pong",
			p:    testICMPPong,
			want: 84,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.GetSize(); got != tt.want {
				t.Errorf("IPPacket.GetSize() = %v, want %v", got, tt.want)
			}
		})
	}
}
