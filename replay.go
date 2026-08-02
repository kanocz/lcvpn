package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync"
)

const (
	packetSessionSize     = 16
	packetSequenceSize    = 8
	packetRecipientSize   = 4
	packetFrameHeaderSize = len(packetFrameMagic) + packetRecipientSize + packetSessionSize + packetSequenceSize
	replayWindowSize      = 1024
	replayWindowWords     = replayWindowSize / 64
	maxReplaySessions     = 4096
)

var (
	// The high nibble deliberately differs from IPv4 and IPv6 so an old peer
	// rejects the new frame instead of injecting it into its TUN interface.
	packetFrameMagic = [...]byte{0xa5, 'L', 'C', 2}

	errPacketFrameSmall   = errors.New("packet frame is too small")
	errPacketFrameVersion = errors.New("unknown packet frame version")
	errPacketRecipient    = errors.New("packet is intended for another peer")
	errPacketReplay       = errors.New("packet replay detected")
)

type packetSendStream struct {
	session  [packetSessionSize]byte
	sequence uint64
}

// packetSender keeps a separate session and sequence space for each peer.
// This avoids treating traffic sent to other peers as gaps in the local
// receiver's anti-replay window.
type packetSender struct {
	mu      sync.Mutex
	streams map[string]*packetSendStream
}

func newPacketSender() *packetSender {
	return &packetSender{streams: make(map[string]*packetSendStream)}
}

func (s *packetSender) next(destination string) ([packetSessionSize]byte, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	stream := s.streams[destination]
	if stream == nil {
		stream = &packetSendStream{}
		if _, err := rand.Read(stream.session[:]); err != nil {
			return [packetSessionSize]byte{}, 0, err
		}
		s.streams[destination] = stream
	}

	// Start a new authenticated session instead of ever reusing a sequence.
	if stream.sequence == ^uint64(0) {
		if _, err := rand.Read(stream.session[:]); err != nil {
			return [packetSessionSize]byte{}, 0, err
		}
		stream.sequence = 0
	}
	stream.sequence++

	return stream.session, stream.sequence, nil
}

func (s *packetSender) Frame(destination string, recipient [packetRecipientSize]byte, packet, output []byte) (int, error) {
	frameLen := packetFrameHeaderSize + len(packet)
	if len(output) < frameLen {
		return 0, errPacketFrameSmall
	}

	session, sequence, err := s.next(destination)
	if err != nil {
		return 0, err
	}

	copy(output[:len(packetFrameMagic)], packetFrameMagic[:])
	recipientStart := len(packetFrameMagic)
	sessionStart := recipientStart + packetRecipientSize
	sequenceStart := sessionStart + packetSessionSize
	copy(output[recipientStart:sessionStart], recipient[:])
	copy(output[sessionStart:sequenceStart], session[:])
	binary.BigEndian.PutUint64(output[sequenceStart:packetFrameHeaderSize], sequence)
	copy(output[packetFrameHeaderSize:frameLen], packet)

	return frameLen, nil
}

type packetFrame struct {
	recipient [packetRecipientSize]byte
	session   [packetSessionSize]byte
	sequence  uint64
	payload   []byte
}

func parsePacketFrame(input []byte) (packetFrame, error) {
	if len(input) < packetFrameHeaderSize {
		return packetFrame{}, errPacketFrameSmall
	}
	for i := range packetFrameMagic {
		if input[i] != packetFrameMagic[i] {
			return packetFrame{}, errPacketFrameVersion
		}
	}

	var frame packetFrame
	recipientStart := len(packetFrameMagic)
	sessionStart := recipientStart + packetRecipientSize
	sequenceStart := sessionStart + packetSessionSize
	copy(frame.recipient[:], input[recipientStart:sessionStart])
	copy(frame.session[:], input[sessionStart:sequenceStart])
	frame.sequence = binary.BigEndian.Uint64(input[sequenceStart:packetFrameHeaderSize])
	frame.payload = input[packetFrameHeaderSize:]
	return frame, nil
}

type replayWindow struct {
	highest  uint64
	seen     [replayWindowWords]uint64
	lastUsed uint64
}

type replayProtector struct {
	mu       sync.Mutex
	windows  map[[packetSessionSize]byte]replayWindow
	useClock uint64
}

func newReplayProtector() *replayProtector {
	return &replayProtector{windows: make(map[[packetSessionSize]byte]replayWindow)}
}

func (p *replayProtector) evictOldest() {
	var oldestSession [packetSessionSize]byte
	var oldestUse uint64
	first := true
	for session, window := range p.windows {
		if first || window.lastUsed < oldestUse {
			oldestSession = session
			oldestUse = window.lastUsed
			first = false
		}
	}
	if !first {
		delete(p.windows, oldestSession)
	}
}

func (w *replayWindow) advance(shift uint64) {
	if shift >= replayWindowSize {
		clear(w.seen[:])
		w.seen[0] = 1
		return
	}

	wordShift := int(shift / 64)
	bitShift := uint(shift % 64)
	var shifted [replayWindowWords]uint64
	for destination := replayWindowWords - 1; destination >= 0; destination-- {
		source := destination - wordShift
		if source < 0 {
			continue
		}
		shifted[destination] |= w.seen[source] << bitShift
		if bitShift != 0 && source > 0 {
			shifted[destination] |= w.seen[source-1] >> (64 - bitShift)
		}
	}
	w.seen = shifted
	w.seen[0] |= 1
}

// Accept implements a 1024-packet sliding window. It accepts limited UDP
// reordering while rejecting duplicates and packets older than the window.
func (p *replayProtector) Accept(session [packetSessionSize]byte, sequence uint64) bool {
	if sequence == 0 {
		return false
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.useClock++
	window, exists := p.windows[session]
	if !exists {
		if len(p.windows) >= maxReplaySessions {
			p.evictOldest()
		}
		window = replayWindow{highest: sequence, lastUsed: p.useClock}
		window.seen[0] = 1
		p.windows[session] = window
		return true
	}

	window.lastUsed = p.useClock
	if sequence > window.highest {
		shift := sequence - window.highest
		window.advance(shift)
		window.highest = sequence
		p.windows[session] = window
		return true
	}

	distance := window.highest - sequence
	if distance >= replayWindowSize {
		return false
	}
	word := distance / 64
	mask := uint64(1) << (distance % 64)
	if window.seen[word]&mask != 0 {
		return false
	}

	window.seen[word] |= mask
	p.windows[session] = window
	return true
}
