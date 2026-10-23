package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/necromancer124/tarion/internal/directory"
	"github.com/necromancer124/tarion/internal/identity"
	"github.com/necromancer124/tarion/internal/mailbox"
	"github.com/necromancer124/tarion/internal/wire"
)

func mailboxServer(t *testing.T) (string, string) {
	t.Helper()
	opts := DefaultOptions()
	opts.Mailbox = true
	opts.MailboxDir = filepath.Join(t.TempDir(), "mailbox")
	server, _ := startServerWith(t, opts)
	return server, opts.MailboxDir
}

// mailClient logs in with the mailbox on (or off) and counts "mail" signals.
func mailClient(t *testing.T, server, user, pass string, id *identity.Identity, on bool, mail *atomic.Int32) *testClient {
	t.Helper()
	cfg := directory.ClientConfig{Server: server, User: user, Pass: pass, AcceptMailbox: on}
	if on {
		pub, _ := mailbox.BoxKeys(id)
		cfg.BoxKey, cfg.BoxSig = pub[:], mailbox.SignBoxKey(id, pub)
	}
	if mail != nil {
		cfg.OnMail = func() { mail.Add(1) }
	}
	c := startClientCfg(t, cfg, id)
	waitFor(t, user+" online", c.dir.Connected)
	return c
}

// seal does what a client does before leaving a letter: check the key the
// server returned, then seal to it.
func seal(t *testing.T, from *testClient, fromID *identity.Identity, to, body string) []byte {
	t.Helper()
	resp, err := from.dir.MailboxKey(to)
	if err != nil {
		t.Fatalf("mailbox key for %s: %v", to, err)
	}
	if identity.PeerID(resp.PubKey) != resp.PeerID || !mailbox.VerifyBoxKey(resp.PubKey, resp.BoxKey, resp.BoxSig) {
		t.Fatal("server returned a box key that doesn't verify")
	}
	var key [32]byte
	copy(key[:], resp.BoxKey)
	sealed, err := mailbox.Seal(fromID, "alice", resp.PeerID, &key, "m-"+body, time.Now(), body)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func TestMailboxHoldsSealedLettersUntilFetched(t *testing.T) {
	server, dir := mailboxServer(t)
	aliceID, _ := identity.Generate()
	bobID, _ := identity.Generate()

	bob := mailClient(t, server, "bob", "battery-staple-2", bobID, true, nil)
	bob.cancel() // bob goes offline; his mailbox stays
	alice := mailClient(t, server, "alice", "correct-horse-1", aliceID, true, nil)
	waitFor(t, "bob offline", func() bool { _, err := alice.dir.Lookup("bob"); return err != nil })

	if err := alice.dir.MailboxPut("bob", seal(t, alice, aliceID, "bob", "secret plans")); err != nil {
		t.Fatal(err)
	}
	// The server only holds ciphertext.
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if data, _ := os.ReadFile(path); strings.Contains(string(data), "secret plans") {
			t.Errorf("%s holds the plaintext", path)
		}
		return nil
	})

	var mail atomic.Int32
	bob = mailClient(t, server, "bob", "", bobID, true, &mail)
	waitFor(t, "mail signal at login", func() bool { return mail.Load() > 0 })
	letters, more, err := bob.dir.MailboxFetch()
	if err != nil || more || len(letters) != 1 || letters[0].From != "alice" {
		t.Fatalf("fetch: %+v more=%v err=%v", letters, more, err)
	}
	l, from, err := mailbox.Open(bobID, letters[0].Sealed)
	if err != nil || l.Body != "secret plans" || from != aliceID.ID {
		t.Fatalf("open: %+v from=%s err=%v", l, from, err)
	}
	if err := bob.dir.MailboxAck([]string{letters[0].ID}); err != nil {
		t.Fatal(err)
	}
	if letters, _, _ := bob.dir.MailboxFetch(); len(letters) != 0 {
		t.Fatalf("acknowledged letters must be gone: %+v", letters)
	}

	// While bob is online, a new letter is announced right away.
	before := mail.Load()
	if err := alice.dir.MailboxPut("bob", seal(t, alice, aliceID, "bob", "hi again")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "mail push", func() bool { return mail.Load() > before })
}

func TestMailboxIsOptInOnEveryEnd(t *testing.T) {
	// The operator didn't turn it on.
	plain, _ := startServer(t)
	aliceID, _ := identity.Generate()
	alice := mailClient(t, plain, "alice", "correct-horse-1", aliceID, true, nil)
	if _, err := alice.dir.MailboxKey("bob"); !errors.Is(err, directory.ErrNoServerMailbox) {
		t.Fatalf("server without a mailbox: %v", err)
	}

	server, _ := mailboxServer(t)
	alice = mailClient(t, server, "alice", "correct-horse-1", aliceID, true, nil)
	bobID, _ := identity.Generate()
	carolID, _ := identity.Generate()
	// bob never turned his on.
	mailClient(t, server, "bob", "battery-staple-2", bobID, false, nil)
	if _, err := alice.dir.MailboxKey("bob"); !errors.Is(err, directory.ErrRecipientNoMailbox) {
		t.Fatalf("recipient with mailbox off: %v", err)
	}
	if _, err := alice.dir.MailboxKey("nobody"); err == nil {
		t.Fatal("a mailbox key for a user who doesn't exist")
	}

	// carol had it on, then turned it off: her letters are deleted with it.
	carol := mailClient(t, server, "carol", "orange-kite-37", carolID, true, nil)
	carol.cancel()
	if err := alice.dir.MailboxPut("carol", seal(t, alice, aliceID, "carol", "one")); err != nil {
		t.Fatal(err)
	}
	carol = mailClient(t, server, "carol", "", carolID, false, nil)
	if _, err := alice.dir.MailboxKey("carol"); !errors.Is(err, directory.ErrRecipientNoMailbox) {
		t.Fatalf("after turning it off: %v", err)
	}
	// With her own mailbox off, carol doesn't use anyone else's either.
	if _, err := carol.dir.MailboxKey("alice"); err == nil {
		t.Fatal("a client with the mailbox off asked for a mailbox key")
	}
	carol.cancel()
	carol = mailClient(t, server, "carol", "", carolID, true, nil)
	if letters, _, _ := carol.dir.MailboxFetch(); len(letters) != 0 {
		t.Fatalf("turning the mailbox off must delete waiting letters: %d left", len(letters))
	}
}

func TestMailboxRefusesOversizedAndStaleKeys(t *testing.T) {
	server, _ := mailboxServer(t)
	aliceID, _ := identity.Generate()
	bobID, _ := identity.Generate()
	alice := mailClient(t, server, "alice", "correct-horse-1", aliceID, true, nil)
	bob := mailClient(t, server, "bob", "battery-staple-2", bobID, true, nil)

	if err := alice.dir.MailboxPut("bob", make([]byte, directory.MaxSealedLetter+1)); err == nil {
		t.Fatal("an oversized letter was accepted")
	}

	// A letter waits for bob's current device; then he moves to a new one.
	bob.cancel()
	waitFor(t, "bob offline", func() bool { _, err := alice.dir.Lookup("bob"); return err != nil })
	if err := alice.dir.MailboxPut("bob", seal(t, alice, aliceID, "bob", "for the old device")); err != nil {
		t.Fatal(err)
	}
	newID, _ := identity.Generate()
	bob = mailClient(t, server, "bob", "battery-staple-2", newID, true, nil)
	resp, err := alice.dir.MailboxKey("bob")
	if err != nil || resp.PeerID != newID.ID {
		t.Fatalf("after a key change the new key must be served: %+v %v", resp, err)
	}
	if letters, _, _ := bob.dir.MailboxFetch(); len(letters) != 0 {
		t.Fatalf("the new device got letters it can't open: %d", len(letters))
	}

	// A box key signed by a different identity than the one logging in is
	// never published.
	malloryID, _ := identity.Generate()
	otherID, _ := identity.Generate()
	pub, _ := mailbox.BoxKeys(otherID)
	c := startClientCfg(t, directory.ClientConfig{Server: server, User: "mallory", Pass: "orange-kite-37",
		AcceptMailbox: true, BoxKey: pub[:], BoxSig: mailbox.SignBoxKey(otherID, pub)}, malloryID)
	waitFor(t, "mallory online", c.dir.Connected)
	if _, err := alice.dir.MailboxKey("mallory"); !errors.Is(err, directory.ErrRecipientNoMailbox) {
		t.Fatalf("a box key signed by someone else was published: %v", err)
	}
}

func TestMailboxStoreLimitsAndExpiry(t *testing.T) {
	m := &mailboxStore{dir: t.TempDir(), maxItems: 3, maxBytes: 1000, perPeer: 2, keep: time.Hour}
	if _, err := m.Put("bob", "alice", "K1", []byte("x"), time.Now()); !errors.Is(err, errNoBox) {
		t.Fatalf("no key published yet: %v", err)
	}
	_ = m.SetKey("Bob", boxRecord{PeerID: "K1"})
	now := time.Now()
	for i, from := range []string{"alice", "alice", "alice"} {
		_, err := m.Put("bob", from, "K1", []byte("x"), now)
		if (i < 2) != (err == nil) {
			t.Fatalf("letter %d from alice: %v", i, err)
		}
	}
	if _, err := m.Put("bob", "carol", "K1", []byte("x"), now.Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Put("bob", "dave", "K1", []byte("x"), now); !errors.Is(err, errMailboxFull) {
		t.Fatalf("over the item limit: %v", err)
	}
	if _, err := m.Put("eve", "alice", "K9", make([]byte, 2000), now); err == nil {
		t.Fatal("put without a key")
	}
	if letters, _ := m.Fetch("bob", "K2"); len(letters) != 0 {
		t.Fatal("letters sealed to another key were handed out")
	}
	if letters, _ := m.Fetch("BOB", "K1"); len(letters) != 3 || letters[0].From != "carol" {
		t.Fatalf("fetch oldest first: %+v", letters)
	}
	if n := m.Expire(now); n != 1 {
		t.Fatalf("expired %d, want 1", n)
	}
	m.Ack("bob", []string{"../../etc/passwd", "zz"})
	letters, _ := m.Fetch("bob", "K1")
	ids := []string{}
	for _, l := range letters {
		ids = append(ids, l.ID)
	}
	m.Ack("bob", ids)
	if letters, _ := m.Fetch("bob", "K1"); len(letters) != 0 {
		t.Fatalf("ack left %d", len(letters))
	}
	if err := m.Remove("bob"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Key("bob"); !errors.Is(err, errNoBox) {
		t.Fatalf("removed mailbox still has a key: %v", err)
	}
}

func TestMailboxFetchFitsOneFrame(t *testing.T) {
	m := &mailboxStore{dir: t.TempDir(), maxItems: 1000, maxBytes: 1 << 30, perPeer: 1000, keep: time.Hour}
	_ = m.SetKey("bob", boxRecord{PeerID: "K1"})
	sender := strings.Repeat("ש", 32) // the longest name, in bytes
	put := func(size int) {
		if _, err := m.Put("bob", sender, "K1", make([]byte, size), time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 200; i++ {
		put(100)
	}
	for i := 0; i < 3; i++ {
		put(directory.MaxSealedLetter)
	}
	got := 0
	for round := 0; round < 100; round++ {
		letters, more := m.Fetch("bob", "K1")
		data, _ := json.Marshal(directory.Response{OK: true, Letters: letters, More: more})
		if len(data) > wire.MaxFrameSize {
			t.Fatalf("fetch response is %d bytes, over the %d frame limit", len(data), wire.MaxFrameSize)
		}
		got += len(letters)
		var ids []string
		for _, l := range letters {
			ids = append(ids, l.ID)
		}
		m.Ack("bob", ids)
		if !more {
			break
		}
	}
	if got != 203 {
		t.Fatalf("fetched %d of 203 letters", got)
	}
}
