package main

import (
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

func makeConfig(localIP, peerExtIP, peerLocIP, broadcast, route string) string {
	routeLine := ""
	if route != "" {
		routeLine = "route = " + route + "\n"
	}
	return fmt.Sprintf(`[main]
port = 23456
encryption = none
broadcast = %s
netcidr = 24
recvThreads = 1
sendThreads = 1

[remote "local"]
ExtIP = 127.0.0.1
LocIP = %s

[remote "peer"]
ExtIP = %s
LocIP = %s
%s`, broadcast, localIP, peerExtIP, peerLocIP, routeLine)
}

func readTestConfig(t *testing.T, contents string) error {
	t.Helper()
	path := t.TempDir() + "/lcvpn.conf"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}

	oldConfigFile, oldLocal := *configfile, *local
	*configfile, *local = path, "local"
	t.Cleanup(func() {
		*configfile, *local = oldConfigFile, oldLocal
	})
	return readConfig()
}

func TestReadConfigRejectsNonIPv4Values(t *testing.T) {
	tests := []struct {
		name      string
		localIP   string
		peerExtIP string
		peerLocIP string
		broadcast string
		route     string
	}{
		{name: "valid IPv4", localIP: "192.168.3.1", peerExtIP: "127.0.0.2", peerLocIP: "192.168.3.2", broadcast: "192.168.3.255", route: "10.0.0.0/8"},
		{name: "local IPv6", localIP: "2001:db8::1", peerExtIP: "127.0.0.2", peerLocIP: "192.168.3.2", broadcast: "192.168.3.255", route: "10.0.0.0/8"},
		{name: "external IPv6", localIP: "192.168.3.1", peerExtIP: "2001:db8::2", peerLocIP: "192.168.3.2", broadcast: "192.168.3.255", route: "10.0.0.0/8"},
		{name: "peer IPv6", localIP: "192.168.3.1", peerExtIP: "127.0.0.2", peerLocIP: "2001:db8::2", broadcast: "192.168.3.255", route: "10.0.0.0/8"},
		{name: "broadcast IPv6", localIP: "192.168.3.1", peerExtIP: "127.0.0.2", peerLocIP: "192.168.3.2", broadcast: "2001:db8::ffff", route: "10.0.0.0/8"},
		{name: "route IPv6", localIP: "192.168.3.1", peerExtIP: "127.0.0.2", peerLocIP: "192.168.3.2", broadcast: "192.168.3.255", route: "2001:db8::/32"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := readTestConfig(t, makeConfig(tt.localIP, tt.peerExtIP, tt.peerLocIP, tt.broadcast, tt.route))
			if tt.name == "valid IPv4" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil {
				t.Fatal("readConfig() accepted a non-IPv4 value")
			}
		})
	}
}

func TestReadConfigRejectsRouteAssignedToMultiplePeers(t *testing.T) {
	contents := makeConfig("192.168.3.1", "127.0.0.2", "192.168.3.2", "192.168.3.255", "10.0.0.0/8") + `

[remote "other"]
ExtIP = 127.0.0.3
LocIP = 192.168.3.3
route = 10.1.2.3/8
`
	err := readTestConfig(t, contents)
	if err == nil || !strings.Contains(err.Error(), "assigned to both") {
		t.Fatalf("readConfig() error = %v, want conflicting-route error", err)
	}
}

func TestReadConfigFailureKeepsPreviousState(t *testing.T) {
	valid := makeConfig("192.168.3.1", "127.0.0.2", "192.168.3.2", "192.168.3.255", "10.0.0.0/8")
	if err := readTestConfig(t, valid); err != nil {
		t.Fatal(err)
	}
	before := config.Load().(VPNState)

	invalid := makeConfig("192.168.3.1", "127.0.0.2", "2001:db8::2", "192.168.3.255", "10.0.0.0/8")
	if err := readTestConfig(t, invalid); err == nil {
		t.Fatal("readConfig() accepted invalid reload")
	}
	after := config.Load().(VPNState)
	if !reflect.DeepEqual(after, before) {
		t.Fatal("failed reload replaced the active configuration")
	}
}

func TestLegacyAesCbcUnsafeConfigName(t *testing.T) {
	const key = "4A34E352D7C32FC42F1CEB0CAA54D40E"
	base := makeConfig("192.168.3.1", "127.0.0.2", "192.168.3.2", "192.168.3.255", "")

	legacy := strings.Replace(base, "encryption = none", "encryption = legacy-aescbc-unsafe\nmainkey = "+key, 1)
	if err := readTestConfig(t, legacy); err != nil {
		t.Fatalf("readConfig() rejected legacy-aescbc-unsafe: %v", err)
	}
	if _, ok := config.Load().(VPNState).Main.main.(*legacyAesCbcUnsafe); !ok {
		t.Fatalf("legacy-aescbc-unsafe constructed %T", config.Load().(VPNState).Main.main)
	}

	oldName := strings.Replace(base, "encryption = none", "encryption = aescbc\nmainkey = "+key, 1)
	err := readTestConfig(t, oldName)
	if err == nil || !strings.Contains(err.Error(), `renamed to "legacy-aescbc-unsafe"`) {
		t.Fatalf("readConfig() error = %v, want migration error", err)
	}
}

func TestReadConfigRejectsDuplicatePeerAddresses(t *testing.T) {
	base := makeConfig("192.168.3.1", "127.0.0.2", "192.168.3.2", "192.168.3.255", "")
	tests := []struct {
		name  string
		extra string
		want  string
	}{
		{name: "LocIP", extra: "[remote \"other\"]\nExtIP = 127.0.0.3\nLocIP = 192.168.3.2\n", want: "LocIP 192.168.3.2"},
		{name: "ExtIP", extra: "[remote \"other\"]\nExtIP = 127.0.0.2\nLocIP = 192.168.3.3\n", want: "ExtIP 127.0.0.2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := readTestConfig(t, base+"\n"+tt.extra)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("readConfig() error = %v, want duplicate %s error", err, tt.name)
			}
		})
	}
}

func TestReadConfigBuildsSourceSet(t *testing.T) {
	if err := readTestConfig(t, makeConfig("192.168.3.1", "127.0.0.2", "192.168.3.2", "192.168.3.255", "")); err != nil {
		t.Fatal(err)
	}
	conf := config.Load().(VPNState)
	if !conf.sources[[4]byte{127, 0, 0, 2}] {
		t.Fatal("peer ExtIP is missing from sources")
	}
	if conf.sources[[4]byte{127, 0, 0, 1}] {
		t.Fatal("local host must not be in sources")
	}
}

func TestReadConfigAllowFrom(t *testing.T) {
	base := makeConfig("192.168.3.1", "127.0.0.2", "192.168.3.2", "192.168.3.255", "")
	contents := base + "AllowFrom = 203.0.113.0/24\nAllowFrom = 198.51.100.7\n"
	if err := readTestConfig(t, contents); err != nil {
		t.Fatal(err)
	}
	conf := config.Load().(VPNState)
	for _, tt := range []struct {
		src  [4]byte
		want bool
	}{
		{[4]byte{127, 0, 0, 2}, true},
		{[4]byte{203, 0, 113, 9}, true},
		{[4]byte{198, 51, 100, 7}, true},
		{[4]byte{198, 51, 100, 8}, false},
		{[4]byte{10, 0, 0, 1}, false},
	} {
		if got := conf.allowedSource(tt.src); got != tt.want {
			t.Errorf("allowedSource(%v) = %v, want %v", tt.src, got, tt.want)
		}
	}

	if err := readTestConfig(t, base+"AllowFrom = 2001:db8::/32\n"); err == nil {
		t.Fatal("readConfig() accepted an IPv6 AllowFrom")
	}
	if err := readTestConfig(t, base+"AllowFrom = not-an-address\n"); err == nil {
		t.Fatal("readConfig() accepted an invalid AllowFrom")
	}
}
