package main

import (
	"log"
	"net"
	"sync"
	"time"
)

// logLimiter writes at most one message per second and reports how many
// it dropped in between. Anyone on the Internet can reach the UDP port,
// so a log line per bad packet would let them fill the disk.
// The suppressed count is reported in the next line that gets through, so
// a burst that stops for good leaves its count unreported.
type logLimiter struct {
	name       string
	mu         sync.Mutex
	last       time.Time
	suppressed int
	now        func() time.Time
}

func (l *logLimiter) Printf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now
	if l.now != nil {
		now = l.now
	}
	t := now()
	if t.Sub(l.last) < time.Second {
		l.suppressed++
		return
	}
	l.last = t
	if l.suppressed > 0 {
		format += " (%d earlier %s messages suppressed)"
		args = append(args, l.suppressed, l.name)
		l.suppressed = 0
	}
	log.Printf(format, args...)
}

// Separate limiters, so Internet noise on the UDP port cannot drown out
// diagnostics about known peers (key mismatch, replay) or the local TUN.
var (
	badPacketLog   = &logLimiter{name: "unknown-source"}
	peerPacketLog  = &logLimiter{name: "peer"}
	localPacketLog = &logLimiter{name: "local"}
)

// sourceID returns the IPv4 address of a UDP peer as a map key.
func sourceID(addr net.Addr) ([4]byte, bool) {
	udp, ok := addr.(*net.UDPAddr)
	if !ok {
		return [4]byte{}, false
	}
	ip := udp.IP.To4()
	if ip == nil {
		return [4]byte{}, false
	}
	return [4]byte{ip[0], ip[1], ip[2], ip[3]}, true
}
