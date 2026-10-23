package mailbox

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/necromancer124/tarion/internal/identity"
	"golang.org/x/crypto/nacl/box"
)

func ids(t *testing.T) (*identity.Identity, *identity.Identity, *identity.Identity) {
	t.Helper()
	a, _ := identity.Generate()
	b, _ := identity.Generate()
	c, _ := identity.Generate()
	return a, b, c
}

func TestSealOpenRoundTrip(t *testing.T) {
	alice, bob, _ := ids(t)
	bobBox, _ := BoxKeys(bob)
	sent := time.Now().Add(-time.Hour)
	sealed, err := Seal(alice, "alice", bob.ID, bobBox, "id1", sent, "שלום bob")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(sealed), "bob") {
		t.Fatal("sealed letter leaks plaintext")
	}
	l, from, err := Open(bob, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if from != alice.ID || l.Body != "שלום bob" || l.From != "alice" || l.TS != sent.Unix() {
		t.Fatalf("letter: %+v from %s", l, from)
	}
}

func TestOnlyTheRecipientCanOpen(t *testing.T) {
	alice, bob, carol := ids(t)
	bobBox, _ := BoxKeys(bob)
	sealed, _ := Seal(alice, "alice", bob.ID, bobBox, "id1", time.Now(), "for bob")
	if _, _, err := Open(carol, sealed); err == nil {
		t.Fatal("carol opened bob's letter")
	}
	sealed[len(sealed)-1] ^= 1
	if _, _, err := Open(bob, sealed); err == nil {
		t.Fatal("a damaged letter was accepted")
	}
}

func TestForgedOrRedirectedLettersAreRejected(t *testing.T) {
	alice, bob, carol := ids(t)
	bobBox, _ := BoxKeys(bob)

	// Someone changes the text but can't re-sign it as alice.
	l := &Letter{V: 1, ID: "x", TS: 1, From: "alice", FromKey: alice.Key.Public().(ed25519.PublicKey), To: bob.ID, Body: "original"}
	l.Sig = signFor(alice, l)
	l.Body = "forged"
	if _, _, err := Open(bob, reseal(t, l, bobBox)); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("forged body: %v", err)
	}

	// A letter alice signed for carol, re-sealed to bob by someone else.
	l2 := &Letter{V: 1, ID: "y", TS: 1, From: "alice", FromKey: alice.Key.Public().(ed25519.PublicKey), To: carol.ID, Body: "for carol"}
	l2.Sig = signFor(alice, l2)
	if _, _, err := Open(bob, reseal(t, l2, bobBox)); err == nil || !strings.Contains(err.Error(), "another user") {
		t.Fatalf("redirected letter: %v", err)
	}
}

func TestBoxKeySignature(t *testing.T) {
	alice, bob, _ := ids(t)
	pub, _ := BoxKeys(alice)
	sig := SignBoxKey(alice, pub)
	if !VerifyBoxKey(alice.Key.Public().(ed25519.PublicKey), pub[:], sig) {
		t.Fatal("valid box key rejected")
	}
	if VerifyBoxKey(bob.Key.Public().(ed25519.PublicKey), pub[:], sig) {
		t.Fatal("box key accepted for the wrong identity")
	}
	p2, _ := BoxKeys(alice)
	if *p2 != *pub {
		t.Fatal("box keys must be stable for one identity")
	}
}

func signFor(id *identity.Identity, l *Letter) []byte {
	return ed25519.Sign(id.Key, l.signed())
}

func reseal(t *testing.T, l *Letter, to *[32]byte) []byte {
	t.Helper()
	plain, _ := json.Marshal(l)
	sealed, err := box.SealAnonymous(nil, plain, to, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func TestLargestMessagesFitTheMailbox(t *testing.T) {
	alice, bob, _ := ids(t)
	bobBox, _ := BoxKeys(bob)
	const maxBody = 16 * 1024   // network.MaxBodyBytes
	const maxSealed = 40 * 1024 // directory.MaxSealedLetter
	for name, body := range map[string]string{
		"angle brackets": strings.Repeat("<", maxBody),
		"hebrew":         strings.Repeat("ש", maxBody/2),
		"emoji":          strings.Repeat("👋", maxBody/4),
	} {
		sealed, err := Seal(alice, "alice", bob.ID, bobBox, "id", time.Now(), body)
		if err != nil || len(sealed) > maxSealed {
			t.Errorf("%s: %d bytes sealed (max %d), err %v", name, len(sealed), maxSealed, err)
			continue
		}
		if l, _, err := Open(bob, sealed); err != nil || l.Body != body {
			t.Errorf("%s: round trip failed: %v", name, err)
		}
	}
}
