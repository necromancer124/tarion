package main

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/necromancer124/tarion/internal/relay"
)

func probe(t *testing.T, c *testClient) (arrived bool, err error) {
	t.Helper()
	nonce := relay.NewID()
	got, stop := c.nm.Relay().ExpectProbe(nonce)
	defer stop()
	if err := c.dir.Probe(nonce.String()); err != nil {
		return false, err
	}
	select {
	case <-got:
		return true, nil
	case <-time.After(1500 * time.Millisecond):
		return false, nil
	}
}

func TestProbeReachesAdvertisedAddress(t *testing.T) {
	server, _ := startServer(t)
	alice := startClient(t, server, "alice", "correct-horse-1", "", nil)
	bob := startClient(t, server, "bob", "battery-staple-2", "", nil)
	waitFor(t, "online", func() bool { return alice.dir.Connected() && bob.dir.Connected() })

	addr := fmt.Sprintf("127.0.0.1:%d", alice.nm.Port)
	if err := alice.dir.SetPublicAddr(addr); err != nil {
		t.Fatal(err)
	}
	if resp, err := bob.dir.Lookup("alice"); err != nil || resp.PublicAddr != addr {
		t.Fatalf("advertised address not in lookup: %+v %v", resp, err)
	}
	if ok, err := probe(t, alice); err != nil || !ok {
		t.Fatalf("probe should arrive: ok=%v err=%v", ok, err)
	}

	// Behind a (simulated) strict NAT, a packet from the server's other
	// port is unsolicited and dropped, which is exactly what the probe
	// is there to find out.
	alice.nm.Relay().SimulateStrictNAT(true)
	if ok, _ := probe(t, alice); ok {
		t.Fatal("probe must not get through a strict NAT")
	}
}

func TestProbeOnlyToYourOwnIP(t *testing.T) {
	server, _ := startServer(t)
	alice := startClient(t, server, "alice", "correct-horse-1", "", nil)
	waitFor(t, "online", alice.dir.Connected)
	if err := alice.dir.SetPublicAddr("203.0.113.9:4000"); err != nil {
		t.Fatal(err)
	}
	if _, err := probe(t, alice); err == nil || !strings.Contains(err.Error(), "probe_not_yours") {
		t.Fatalf("probing someone else's IP must be refused, got %v", err)
	}
}
