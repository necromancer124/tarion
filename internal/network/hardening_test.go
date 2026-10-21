package network

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/necromancer124/tarion/internal/identity"
	"github.com/quic-go/quic-go"
)

// A cached connection whose peer vanished (like a router dropping the UDP
// mapping) must not eat the whole deadline: the redial still delivers.
func TestDeadCachedConnectionRecovers(t *testing.T) {
	alice, _ := startPeer(t)
	bobID, _ := identity.Generate()
	port := freeUDPPort(t)
	bobAddr := fmt.Sprintf("127.0.0.1:%d", port)

	bob := NewNetworkManager(port, bobID)
	if err := bob.StartListener(); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.Send(bobAddr, "alice", "first", nil); err != nil {
		t.Fatal(err)
	}
	receive(t, bob)

	// Bob restarts on the same port; alice's cached connection is now dead
	// and nothing tells her (no stateless reset is configured).
	_ = bob.Close()
	bob2 := NewNetworkManager(port, bobID)
	if err := bob2.StartListener(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bob2.Close() })

	start := time.Now()
	if _, err := alice.Send(bobAddr, "alice", "after restart", nil); err != nil {
		t.Fatalf("send after peer restart: %v", err)
	}
	if took := time.Since(start); took > sendTimeout-time.Second {
		t.Fatalf("recovery took %s; the cached attempt should be cut short", took)
	}
	if got := receive(t, bob2); got.Body != "after restart" {
		t.Fatalf("got %q", got.Body)
	}
}

func TestChatHandshakeSendsNoSNI(t *testing.T) {
	alice, _ := startPeer(t)
	bobID, _ := identity.Generate()
	bob := NewNetworkManager(0, bobID)

	sni := make(chan string, 1)
	conf := bob.serverTLS()
	conf.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		sni <- hello.ServerName
		return nil, nil
	}
	ln, err := quic.ListenAddr("127.0.0.1:0", conf, quicConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(context.Background()); err == nil {
			defer c.CloseWithError(0, "")
			_, _ = c.AcceptStream(context.Background())
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := alice.conn(ctx, ln.Addr().String(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	if got := <-sni; got != "" {
		t.Fatalf("chat handshake leaked SNI %q", got)
	}
}

func TestAcceptHookRefusesSender(t *testing.T) {
	alice, _ := startPeer(t)
	bobID, _ := identity.Generate()
	port := freeUDPPort(t)
	bob := NewNetworkManager(port, bobID)
	bob.Accept = func(peerID string) error {
		if peerID == alice.ID() {
			return errors.New("not accepting messages from unknown senders")
		}
		return nil
	}
	if err := bob.StartListener(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bob.Close() })

	_, err := alice.Send(fmt.Sprintf("127.0.0.1:%d", port), "alice", "hi", nil)
	var rejected *RejectedError
	if !errors.As(err, &rejected) || !strings.Contains(rejected.Reason, "unknown senders") {
		t.Fatalf("expected refusal, got %v", err)
	}
	select {
	case m := <-bob.MessageChan:
		t.Fatalf("refused message was delivered: %+v", m)
	case <-time.After(200 * time.Millisecond):
	}
}
