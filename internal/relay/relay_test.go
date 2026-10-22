package relay

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func listen(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestWrapUnwrap(t *testing.T) {
	id := NewID()
	pkt := Wrap(id, []byte("quic"))
	got, payload, ok := Unwrap(pkt)
	if !ok || got != id || string(payload) != "quic" {
		t.Fatalf("unwrap: %v %q %v", got, payload, ok)
	}
	for _, bad := range [][]byte{nil, []byte("hello"), pkt[:HeaderLen], append([]byte{0x40}, pkt[1:]...)} {
		if _, _, ok := Unwrap(bad); ok {
			t.Fatalf("accepted %q", bad)
		}
	}
	if a, ok := ParseAddr(Addr{ID: id}.String()); !ok || a.ID != id {
		t.Fatal("addr round trip")
	}
	if _, ok := ParseAddr("relay:zz"); ok {
		t.Fatal("bad addr accepted")
	}
}

func TestConnRelaysThroughServer(t *testing.T) {
	server := listen(t)
	c := NewConn(listen(t))
	c.SetServer(server.LocalAddr().(*net.UDPAddr))
	id := NewID()
	buf := make([]byte, 1500)

	// Writes to a relay Addr reach the server with the header added.
	if n, err := c.WriteTo([]byte("hello"), Addr{ID: id}); err != nil || n != 5 {
		t.Fatalf("write: %d %v", n, err)
	}
	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, from, err := server.ReadFrom(buf)
	if err != nil || !bytes.Equal(buf[:n], Wrap(id, []byte("hello"))) {
		t.Fatalf("server got %q %v", buf[:n], err)
	}

	// A reply for an unknown session is dropped; once allowed it comes out
	// with the header stripped and the relay Addr as source.
	_, _ = server.WriteTo(Wrap(id, []byte("dropped")), from)
	_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, _, err := c.ReadFrom(buf); err == nil {
		t.Fatalf("unknown session delivered %q", buf[:n])
	}
	c.Allow(id)
	_, _ = server.WriteTo(Wrap(id, []byte("reply")), from)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, addr, err := c.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "reply" || addr != (Addr{ID: id}) {
		t.Fatalf("read: %q %v %v", buf[:n], addr, err)
	}

	// Relay packets from anyone but the server are ignored.
	stranger := listen(t)
	_, _ = stranger.WriteTo(Wrap(id, []byte("spoofed")), c.LocalAddr())
	_, _ = stranger.WriteTo([]byte("direct"), c.LocalAddr())
	n, addr, err = c.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "direct" {
		t.Fatalf("expected the spoofed relay packet skipped, got %q from %v (%v)", buf[:n], addr, err)
	}

	// A simulated strict NAT drops direct packets from peers.
	c.SimulateStrictNAT(true)
	_, _ = stranger.WriteTo([]byte("blocked"), c.LocalAddr())
	_, _ = server.WriteTo([]byte("from server"), c.LocalAddr())
	n, _, err = c.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "from server" {
		t.Fatalf("strict NAT: got %q (%v)", buf[:n], err)
	}
}
