package storage

import (
	"errors"
	"testing"
)

func TestResolveIncomingPinsAndBlocksImpostors(t *testing.T) {
	t.Setenv("TARION_HOME", t.TempDir())

	name, err := ResolveIncoming("bobkey000000", "bob", "1.2.3.4:1")
	if err != nil || name != "bob" {
		t.Fatalf("first contact: got %q, %v", name, err)
	}
	// Same key, new claimed name: keeps the pinned name.
	if name, _ := ResolveIncoming("bobkey000000", "alice", "1.2.3.4:2"); name != "bob" {
		t.Fatalf("known key renamed itself to %q", name)
	}
	// Different key claiming "bob": gets a distinct chat.
	name, _ = ResolveIncoming("evilkey00000", "bob", "6.6.6.6:1")
	if name != "bob~evilkey0" {
		t.Fatalf("impostor got name %q", name)
	}
	if p, ok := PeerByName("bob"); !ok || p.Addr != "1.2.3.4:2" {
		t.Fatalf("pinned address not updated: %+v", p)
	}
}

func TestPinOutgoingRefusesChangedKey(t *testing.T) {
	t.Setenv("TARION_HOME", t.TempDir())

	if err := PinOutgoing("bob", "bobkey000000", "1.2.3.4:1"); err != nil {
		t.Fatal(err)
	}
	var mismatch *IdentityMismatchError
	if err := PinOutgoing("bob", "otherkey0000", "1.2.3.4:1"); !errors.As(err, &mismatch) {
		t.Fatalf("expected identity mismatch, got %v", err)
	}
	if ok, err := ForgetPeer("bob"); !ok || err != nil {
		t.Fatalf("forget: %v %v", ok, err)
	}
	if err := PinOutgoing("bob", "otherkey0000", "1.2.3.4:1"); err != nil {
		t.Fatalf("after forget, new key should pin: %v", err)
	}
}

func TestPinOutgoingRenamesKnownKey(t *testing.T) {
	t.Setenv("TARION_HOME", t.TempDir())

	_, _ = ResolveIncoming("selfkey00000", "PC178", "127.0.0.1:1")
	if err := PinOutgoing("Myself", "selfkey00000", "127.0.0.1:1"); err != nil {
		t.Fatal(err)
	}
	if name, _ := ResolveIncoming("selfkey00000", "PC178", "127.0.0.1:1"); name != "Myself" {
		t.Fatalf("incoming should use the user's chosen name, got %q", name)
	}
}

func TestCleanTextAndName(t *testing.T) {
	if got := CleanText("hi\x1b[2J\nthere\r\n"); got != "hi[2J⏎there⏎" {
		t.Fatalf("CleanText: %q", got)
	}
	if got := CleanName("  \x1b]0;evil\a bob/../x  "); got != "__0_evil_ bob_.._x" {
		t.Fatalf("CleanName: %q", got)
	}
	if got := CleanName("שלום"); got != "שלום" {
		t.Fatalf("CleanName should keep Hebrew: %q", got)
	}
	if got := safeName("CON"); got != "_CON" {
		t.Fatalf("safeName reserved: %q", got)
	}
}

func TestRelayAddressesAreNeverStored(t *testing.T) {
	t.Setenv("TARION_HOME", t.TempDir())
	if _, err := ResolveIncoming("bobkey000000", "bob", "1.2.3.4:5"); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveIncoming("bobkey000000", "bob", "relay:0011223344556677"); err != nil {
		t.Fatal(err)
	}
	if err := PinOutgoing("bob", "bobkey000000", "relay:0011223344556677"); err != nil {
		t.Fatal(err)
	}
	if p, _ := PeerByName("bob"); p.Addr != "1.2.3.4:5" {
		t.Fatalf("relay address replaced the real one: %q", p.Addr)
	}
	if _, err := ResolveIncoming("carolkey0000", "carol", "relay:0011223344556677"); err != nil {
		t.Fatal(err)
	}
	if p, _ := PeerByName("carol"); p.Addr != "" {
		t.Fatalf("relay address stored for a new peer: %q", p.Addr)
	}
}
