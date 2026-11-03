package devices

import (
	"crypto/ed25519"
	"sort"
	"strings"
	"testing"

	"github.com/necromancer124/tarion/internal/identity"
)

func newID(t *testing.T) *identity.Identity {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func cert(id *identity.Identity, name string) Cert {
	return Cert{Account: "bob", PeerID: id.ID, PubKey: id.Key.Public().(ed25519.PublicKey), Name: name, Added: 1}
}

func sorted(s []string) string { sort.Strings(s); return strings.Join(s, ",") }

func TestChainFromRoot(t *testing.T) {
	phone, laptop, tablet := newID(t), newID(t), newID(t)
	root := cert(phone, "phone")
	l := cert(laptop, "laptop")
	Sign(phone, &l)
	tb := cert(tablet, "tablet")
	Sign(laptop, &tb) // approved by a non-root device
	certs := []Cert{root, l, tb}

	got, err := Verify("bob", certs, phone.ID)
	if err != nil || sorted(got) != sorted([]string{phone.ID, laptop.ID, tablet.ID}) {
		t.Fatalf("from the root: %v %v", got, err)
	}
	// Pinning a device only trusts what it approved, never what claims to
	// have approved it.
	if got, _ := Verify("bob", certs, laptop.ID); sorted(got) != sorted([]string{laptop.ID, tablet.ID}) {
		t.Fatalf("from the laptop: %v", got)
	}

	// Removing the laptop keeps the tablet it approved.
	certs[1].Removed = true
	if got, _ := Verify("bob", certs, phone.ID); sorted(got) != sorted([]string{phone.ID, tablet.ID}) {
		t.Fatalf("after removing the laptop: %v", got)
	}
}

func TestServerCantSlipInAKey(t *testing.T) {
	phone, laptop, evil := newID(t), newID(t), newID(t)
	root := cert(phone, "phone")
	l := cert(laptop, "laptop")
	Sign(phone, &l)

	// A device "approved" by a key that isn't on the account.
	fake := cert(evil, "evil")
	Sign(newID(t), &fake)
	// A device claiming the phone approved it, without the phone's signature.
	forged := cert(evil, "evil")
	forged.By, forged.Sig = phone.ID, l.Sig
	// A cert whose key doesn't match its ID.
	swapped := cert(evil, "evil")
	swapped.PubKey = laptop.Key.Public().(ed25519.PublicKey)
	Sign(phone, &swapped)

	for name, extra := range map[string]Cert{"unknown approver": fake, "forged signature": forged, "key swapped": swapped} {
		got, err := Verify("bob", []Cert{root, l, extra}, phone.ID)
		if err != nil || sorted(got) != sorted([]string{phone.ID, laptop.ID}) {
			t.Errorf("%s got in: %v %v", name, got, err)
		}
	}

	// The server claims the evil key approved the real laptop: trust must
	// not flow up to it.
	l2 := cert(laptop, "laptop")
	Sign(evil, &l2)
	evilRoot := cert(evil, "evil")
	evilRoot.By = ""
	if got, _ := Verify("bob", []Cert{evilRoot, l2}, laptop.ID); sorted(got) != laptop.ID {
		t.Fatalf("trust flowed up to the forged approver: %v", got)
	}
}

func TestAccountResetIsAKeyChange(t *testing.T) {
	phone, newPhone := newID(t), newID(t)
	if _, err := Verify("bob", []Cert{cert(newPhone, "new")}, phone.ID); err == nil {
		t.Fatal("a reset account must not verify against the old pin")
	}
	if _, err := Verify("alice", []Cert{cert(phone, "phone")}, phone.ID); err == nil {
		t.Fatal("another account's devices were accepted")
	}
}

func TestCheckBeforeAdding(t *testing.T) {
	phone, laptop := newID(t), newID(t)
	certs := []Cert{cert(phone, "phone")}
	l := cert(laptop, "laptop")
	Sign(phone, &l)
	if err := Check(certs, l); err != nil {
		t.Fatalf("valid approval refused: %v", err)
	}
	if err := Check(append(certs, l), l); err == nil {
		t.Fatal("the same device was added twice")
	}
	bad := l
	bad.Name = "renamed"
	if err := Check(certs, bad); err == nil {
		t.Fatal("a changed cert passed")
	}
	certs[0].Removed = true
	if err := Check(certs, l); err == nil {
		t.Fatal("a removed device approved another")
	}
	full := []Cert{cert(phone, "phone")}
	for i := 1; i < MaxActive; i++ {
		full = append(full, cert(newID(t), "x"))
	}
	if err := Check(full, l); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Fatalf("device limit: %v", err)
	}
}
