// Package relay lets two peers that can't reach each other directly (strict
// NATs) exchange QUIC packets through tariond.
//
// A relayed packet is a 12-byte header followed by an unchanged QUIC packet:
//
//	0x00 'T' 'R' 'L' | 8-byte session ID | QUIC packet
//
// The first byte has the QUIC "fixed bit" cleared, so QUIC stacks treat it
// as a non-QUIC datagram. Peers still run their own TLS 1.3 handshake inside
// the relayed QUIC connection, so the server only ever forwards ciphertext.
package relay

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"sync"
	"time"
)

const HeaderLen = 12

var magic = [4]byte{0x00, 'T', 'R', 'L'}

// ID names one relay session between two peers.
type ID [8]byte

func NewID() ID {
	var id ID
	_, _ = rand.Read(id[:])
	return id
}

func (id ID) String() string { return hex.EncodeToString(id[:]) }

func ParseID(s string) (ID, bool) {
	var id ID
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(id) {
		return id, false
	}
	copy(id[:], b)
	return id, true
}

// Wrap prefixes payload with the relay header.
func Wrap(id ID, payload []byte) []byte {
	pkt := make([]byte, HeaderLen+len(payload))
	copy(pkt, magic[:])
	copy(pkt[4:], id[:])
	copy(pkt[HeaderLen:], payload)
	return pkt
}

// Unwrap splits a relay packet; ok is false for anything else.
func Unwrap(pkt []byte) (id ID, payload []byte, ok bool) {
	if len(pkt) <= HeaderLen || [4]byte(pkt[:4]) != magic {
		return id, nil, false
	}
	copy(id[:], pkt[4:HeaderLen])
	return id, pkt[HeaderLen:], true
}

// Addr is the address QUIC sees for a peer reached through the relay.
type Addr struct{ ID ID }

func (a Addr) Network() string { return "tarion-relay" }
func (a Addr) String() string  { return "relay:" + a.ID.String() }

// IsAddr reports whether s is a relay address (never stored or dialed
// directly: it only means something during its session).
func IsAddr(s string) bool { return strings.HasPrefix(s, "relay:") }

func ParseAddr(s string) (Addr, bool) {
	if !IsAddr(s) {
		return Addr{}, false
	}
	id, ok := ParseID(strings.TrimPrefix(s, "relay:"))
	return Addr{ID: id}, ok
}

const sessionIdle = 10 * time.Minute

// Conn wraps the chat socket for quic-go. Writes to an Addr go to the relay
// server with a header; relay packets from the server for a known session
// come back out with the header stripped and that Addr as the source.
// Everything else passes through unchanged.
type Conn struct {
	pc *net.UDPConn

	mu       sync.RWMutex
	server   *net.UDPAddr
	sessions map[ID]time.Time
	strict   bool
}

func NewConn(pc *net.UDPConn) *Conn {
	return &Conn{pc: pc, sessions: map[ID]time.Time{}}
}

// SetServer sets where relay packets go (the directory server).
func (c *Conn) SetServer(addr *net.UDPAddr) {
	c.mu.Lock()
	c.server = addr
	c.mu.Unlock()
}

// Allow accepts relay packets for a session the server told us about.
func (c *Conn) Allow(id ID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for k, t := range c.sessions {
		if now.Sub(t) > sessionIdle {
			delete(c.sessions, k)
		}
	}
	c.sessions[id] = now
}

// SimulateStrictNAT drops every incoming direct packet except the server's,
// as a symmetric NAT would for peers. It exists to test the relay path.
func (c *Conn) SimulateStrictNAT(on bool) {
	c.mu.Lock()
	c.strict = on
	c.mu.Unlock()
}

func (c *Conn) fromServer(addr net.Addr) bool {
	c.mu.RLock()
	srv := c.server
	c.mu.RUnlock()
	u, ok := addr.(*net.UDPAddr)
	return ok && srv != nil && u.Port == srv.Port && u.IP.Equal(srv.IP)
}

func (c *Conn) known(id ID) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.sessions[id]; !ok {
		return false
	}
	c.sessions[id] = time.Now()
	return true
}

func (c *Conn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.pc.ReadFrom(p)
		if err != nil {
			return n, addr, err
		}
		if id, payload, ok := Unwrap(p[:n]); ok {
			if !c.fromServer(addr) || !c.known(id) {
				continue
			}
			return copy(p, payload), Addr{ID: id}, nil
		}
		c.mu.RLock()
		strict := c.strict
		c.mu.RUnlock()
		if strict && !c.fromServer(addr) {
			continue
		}
		return n, addr, nil
	}
}

var errNoServer = errors.New("relay: no server")

func (c *Conn) WriteTo(p []byte, addr net.Addr) (int, error) {
	a, ok := addr.(Addr)
	if !ok {
		return c.pc.WriteTo(p, addr)
	}
	c.mu.RLock()
	srv := c.server
	c.mu.RUnlock()
	if srv == nil {
		return 0, errNoServer
	}
	if _, err := c.pc.WriteTo(Wrap(a.ID, p), srv); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *Conn) Close() error                       { return c.pc.Close() }
func (c *Conn) LocalAddr() net.Addr                { return c.pc.LocalAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.pc.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.pc.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.pc.SetWriteDeadline(t) }
func (c *Conn) SetReadBuffer(n int) error          { return c.pc.SetReadBuffer(n) }
func (c *Conn) SetWriteBuffer(n int) error         { return c.pc.SetWriteBuffer(n) }
