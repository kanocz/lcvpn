package main

import (
	"bytes"
	"log"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestLogLimitedCollapsesBurst(t *testing.T) {
	var out bytes.Buffer
	log.SetOutput(&out)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	now := time.Unix(100, 0)
	l := &logLimiter{name: "test", now: func() time.Time { return now }}
	for i := 0; i < 5; i++ {
		l.Printf("bad packet %d", i)
	}
	now = now.Add(2 * time.Second)
	l.Printf("bad packet %d", 5)

	got := out.String()
	if strings.Count(got, "bad packet") != 2 {
		t.Fatalf("want 2 log lines, got:\n%s", got)
	}
	if !strings.Contains(got, "bad packet 5 (4 earlier test messages suppressed)") {
		t.Fatalf("missing suppressed counter:\n%s", got)
	}
}

func TestSourceID(t *testing.T) {
	v4 := &net.UDPAddr{IP: net.ParseIP("10.1.2.3"), Port: 5}
	if id, ok := sourceID(v4); !ok || id != [4]byte{10, 1, 2, 3} {
		t.Fatalf("sourceID() = %v, %v", id, ok)
	}
	v6 := &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 5}
	if _, ok := sourceID(v6); ok {
		t.Fatal("sourceID() accepted an IPv6 address")
	}
}
