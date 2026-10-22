package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/necromancer124/tarion/internal/directory"
	"github.com/necromancer124/tarion/internal/identity"
	"github.com/necromancer124/tarion/internal/network"
	"github.com/necromancer124/tarion/internal/relay"
)

func TestRelayWhenDirectPathBlocked(t *testing.T) {
	server, _ := startServer(t)
	alice := startClient(t, server, "alice", "correct-horse-1", "", nil)
	bob := startClient(t, server, "bob", "battery-staple-2", "", nil)
	waitFor(t, "both online", func() bool { return alice.dir.Connected() && bob.dir.Connected() })

	// bob is behind a "strict NAT": only the server can reach him.
	bob.nm.Relay().SimulateStrictNAT(true)
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	if _, err := alice.nm.SendContext(ctx, fmt.Sprintf("127.0.0.1:%d", bob.nm.Port), "alice", "direct?", nil); err == nil {
		t.Fatal("direct send should fail behind the simulated strict NAT")
	}

	addr, peerID, err := alice.dir.Relay("bob")
	if err != nil || !relay.IsAddr(addr) || peerID != bob.nm.ID() {
		t.Fatalf("relay: %q %q %v", addr, peerID, err)
	}
	if _, err := alice.nm.Send(addr, "alice", "via relay", func(id string) error {
		if id != peerID {
			return errors.New("relayed peer has the wrong key")
		}
		return nil
	}); err != nil {
		t.Fatalf("send via relay: %v", err)
	}
	got := receive(t, bob)
	if got.Body != "via relay" || got.PeerID != alice.nm.ID() || !relay.IsAddr(got.Addr) {
		t.Fatalf("bob got %+v", got)
	}

	// bob answers through the same session.
	if _, err := bob.nm.Send(got.Addr, "bob", "reply via relay", nil); err != nil {
		t.Fatalf("reply via relay: %v", err)
	}
	if back := receive(t, alice); back.Body != "reply via relay" || back.PeerID != bob.nm.ID() {
		t.Fatalf("alice got %+v", back)
	}
}

func TestRelayCanBeDisabled(t *testing.T) {
	opts := DefaultOptions()
	opts.Relay = false
	server, _ := startServerWith(t, opts)
	alice := startClient(t, server, "alice", "correct-horse-1", "", nil)
	bob := startClient(t, server, "bob", "battery-staple-2", "", nil)
	waitFor(t, "both online", func() bool { return alice.dir.Connected() && bob.dir.Connected() })
	if _, _, err := alice.dir.Relay("bob"); err == nil || !strings.Contains(err.Error(), "relay_disabled") {
		t.Fatalf("expected relay_disabled, got %v", err)
	}
}

func receive(t *testing.T, c *testClient) incomingMsg {
	t.Helper()
	select {
	case m := <-c.nm.MessageChan:
		return incomingMsg{Body: m.Body, PeerID: m.PeerID, Addr: m.Addr}
	case <-time.After(10 * time.Second):
		t.Fatal("no message")
	}
	return incomingMsg{}
}

type incomingMsg struct{ Body, PeerID, Addr string }

// A client behind a strict NAT accepts packets only from the server, so it
// must know the server's address before its very first handshake.
func TestStrictNATClientCanLogIn(t *testing.T) {
	server, _ := startServer(t)
	id, _ := identity.Generate()
	nm := network.NewNetworkManager(freePort(t), id)
	if err := nm.StartListener(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nm.Close() })
	nm.Relay().SimulateStrictNAT(true)
	c := directory.NewClient(nm, directory.ClientConfig{Server: server, User: "bob", Pass: "battery-staple-2"})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go c.Run(ctx)
	waitFor(t, "strict-NAT client logged in", c.Connected)
}
