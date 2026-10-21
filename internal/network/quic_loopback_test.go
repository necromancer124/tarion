package network

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/necromancer124/tarion/internal/identity"
)

func freeUDPPort(t *testing.T) int {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

func startPeer(t *testing.T) (*NetworkManager, string) {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	port := freeUDPPort(t)
	nm := NewNetworkManager(port, id)
	if err := nm.StartListener(); err != nil {
		t.Fatalf("StartListener: %v", err)
	}
	t.Cleanup(func() { _ = nm.Close() })
	return nm, fmt.Sprintf("127.0.0.1:%d", port)
}

func receive(t *testing.T, nm *NetworkManager) IncomingMessage {
	t.Helper()
	select {
	case got := <-nm.MessageChan:
		return got
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for message")
	}
	return IncomingMessage{}
}

func expectPeer(want string) func(string) error {
	return func(got string) error {
		if got != want {
			return errors.New("identity mismatch")
		}
		return nil
	}
}

func TestLoopbackSelfMessage(t *testing.T) {
	nm, addr := startPeer(t)

	const body = "hello myself over QUIC"
	peerID, err := nm.Send(addr, "PC178", body, nil)
	if err != nil {
		t.Fatalf("Send loopback: %v", err)
	}
	if peerID != nm.ID() {
		t.Fatalf("peer id: got %q want own id %q", peerID, nm.ID())
	}

	got := receive(t, nm)
	if got.Body != body || got.Name != "PC178" || got.PeerID != nm.ID() {
		t.Fatalf("unexpected message: %+v", got)
	}
	if got.Addr == "" {
		t.Fatal("expected observed sender address")
	}
}

func TestReplyAddressIsListeningPort(t *testing.T) {
	alice, _ := startPeer(t)
	bob, bobAddr := startPeer(t)

	if _, err := alice.Send(bobAddr, "alice", "hi bob", nil); err != nil {
		t.Fatal(err)
	}
	got := receive(t, bob)
	_, port, _ := net.SplitHostPort(got.Addr)
	if port != fmt.Sprint(alice.Port) {
		t.Fatalf("reply address %s should use alice's listening port %d", got.Addr, alice.Port)
	}
	if got.PeerID != alice.ID() {
		t.Fatalf("sender id: got %q want %q", got.PeerID, alice.ID())
	}
}

func TestPinnedIdentityMismatchIsRefused(t *testing.T) {
	alice, _ := startPeer(t)
	bob, bobAddr := startPeer(t)
	mallory, _ := startPeer(t)

	if _, err := alice.Send(bobAddr, "alice", "pinned ok", expectPeer(bob.ID())); err != nil {
		t.Fatalf("send with correct pin: %v", err)
	}
	receive(t, bob)

	if _, err := alice.Send(bobAddr, "alice", "should not arrive", expectPeer(mallory.ID())); err == nil {
		t.Fatal("expected send to fail when the peer key does not match the pin")
	}
	select {
	case got := <-bob.MessageChan:
		t.Fatalf("message delivered despite pin mismatch: %+v", got)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestConnectionIsReused(t *testing.T) {
	alice, _ := startPeer(t)
	bob, bobAddr := startPeer(t)

	for i := 0; i < 3; i++ {
		if _, err := alice.Send(bobAddr, "alice", fmt.Sprintf("msg %d", i), nil); err != nil {
			t.Fatal(err)
		}
		if got := receive(t, bob); got.Body != fmt.Sprintf("msg %d", i) {
			t.Fatalf("out of order or wrong body: %q", got.Body)
		}
	}
	alice.mu.Lock()
	n := len(alice.conns)
	alice.mu.Unlock()
	if n != 1 {
		t.Fatalf("expected 1 cached connection, got %d", n)
	}
}

func TestBusyReceiverRejects(t *testing.T) {
	alice, _ := startPeer(t)
	bob, bobAddr := startPeer(t)
	bob.MessageChan = make(chan IncomingMessage) // nobody reads it

	_, err := alice.Send(bobAddr, "alice", "dropped?", nil)
	var rejected *RejectedError
	if !errors.As(err, &rejected) || !strings.Contains(rejected.Reason, "busy") {
		t.Fatalf("expected busy rejection, got %v", err)
	}
}

func TestOversizedMessageRefused(t *testing.T) {
	alice, _ := startPeer(t)
	_, bobAddr := startPeer(t)
	if _, err := alice.Send(bobAddr, "alice", strings.Repeat("x", MaxBodyBytes+1), nil); err == nil {
		t.Fatal("expected oversized message to be refused")
	}
}


func TestDuplicateMessageDeliveredOnce(t *testing.T) {
	nm := NewNetworkManager(0, nil)
	if !nm.markSeen("peer/1") {
		t.Fatal("first sighting should be new")
	}
	if nm.markSeen("peer/1") {
		t.Fatal("second sighting should be a duplicate")
	}
}
