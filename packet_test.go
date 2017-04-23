package main

import (
	"net"
	"reflect"
	"testing"
)

func TestIPPacket_GetOrigSize(t *testing.T) {
	tests := []struct {
		name string
		p    IPPacket
		want int
	}{
		{
			name: "zero",
			p:    IPPacket([]byte{0, 0, 0, 0}),
			want: 0,
		},
		{
			name: "100",
			p:    IPPacket([]byte{100, 0, 0, 0}),
			want: 100,
		},
		{
			name: "258",
			p:    IPPacket([]byte{2, 1, 0, 0}),
			want: 258,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.GetOrigSize(); got != tt.want {
				t.Errorf("IPPacket.GetOrigSize() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIPPacket_SetOrigSize(t *testing.T) {
	tests := []struct {
		name string
		val  int
	}{
		{
			name: "1 byte",
			val:  15,
		},
		{
			name: "2 byte",
			val:  258,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var p IPPacket = make([]byte, 1500)
			p.SetOrigSize(tt.val)
			if got := p.GetOrigSize(); got != tt.val {
				t.Errorf("IPPacket.GetOrigSize() = %v, want %v", got, tt.val)
			}
		})
	}
}

func TestIPPacket_IPver(t *testing.T) {
	tests := []struct {
		name string
		p    IPPacket
		want int
	}{
		{
			name: "ipv4",
			p:    IPPacket([]byte{2, 0, 4 << 4, 0}),
			want: 4,
		},
		{
			name: "ipv6",
			p:    IPPacket([]byte{2, 0, 6 << 4, 0}),
			want: 6,
		},
		{
			name: "invalid",
			p:    IPPacket([]byte{2, 0, 3 << 4, 0}),
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
			name: "212.9.224.1",
			p:    IPPacket([]byte{2, 0, 4 << 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 212, 9, 224, 1, 0}),
			want: [4]byte{212, 9, 224, 1},
		},
		{
			name: "127.0.0.1",
			p:    IPPacket([]byte{2, 0, 4 << 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1, 0}),
			want: [4]byte{127, 0, 0, 1},
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
			name: "212.9.224.1",
			p:    IPPacket([]byte{2, 0, 4 << 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 212, 9, 224, 1, 0}),
			want: net.ParseIP("212.9.224.1"),
		},
		{
			name: "127.0.0.1",
			p:    IPPacket([]byte{2, 0, 4 << 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1, 0}),
			want: net.ParseIP("127.0.0.1"),
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
			name: "212.9.224.1",
			p:    IPPacket([]byte{2, 0, 4 << 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 212, 9, 224, 1, 0}),
			want: [4]byte{212, 9, 224, 1},
		},
		{
			name: "127.0.0.1",
			p:    IPPacket([]byte{2, 0, 4 << 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1, 0}),
			want: [4]byte{127, 0, 0, 1},
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
			name: "212.9.224.1",
			p:    IPPacket([]byte{2, 0, 4 << 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 212, 9, 224, 1, 0}),
			want: false,
		},
		{
			name: "127.0.0.1",
			p:    IPPacket([]byte{2, 0, 4 << 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1, 0}),
			want: false,
		},
		{
			name: "230.0.0.1",
			p:    IPPacket([]byte{2, 0, 4 << 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 230, 0, 0, 1, 0}),
			want: true,
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
