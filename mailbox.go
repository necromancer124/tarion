package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/necromancer124/tarion/internal/directory"
	"github.com/necromancer124/tarion/internal/identity"
	"github.com/necromancer124/tarion/internal/mailbox"
	"github.com/necromancer124/tarion/internal/network"
	"github.com/necromancer124/tarion/internal/storage"
)

// The server mailbox (opt-in on both ends) holds messages for contacts who
// are offline. A message is signed with our key and sealed to the
// recipient's, so the server stores bytes it can neither read nor forge.

const mailboxPoll = 2 * time.Minute // fallback; the server also pushes "mail"

// mailboxOn reports whether this client uses the server mailbox.
func (n *node) mailboxOn() bool { return n.dir != nil && n.cfg.MailboxEnabled() }

// mailboxGrace is how long a message to someone online but unreachable is
// retried directly (and through the relay, if on) before it goes to their
// mailbox.
const mailboxGrace = time.Minute

// useMailbox reports whether a message queued at since, whose last attempt
// failed with err, goes to the recipient's mailbox: right away when the
// server says they're offline, and after mailboxGrace of failed retries
// when they're online but can't be reached.
func (n *node) useMailbox(err error, since time.Time) bool {
	return n.mailboxOn() && (errors.Is(err, errOffline) || time.Since(since) >= mailboxGrace)
}

// mailboxLogin returns the box key and its signature to publish at login.
func mailboxLogin(id *identity.Identity) (key, sig []byte) {
	pub, _ := mailbox.BoxKeys(id)
	return pub[:], mailbox.SignBoxKey(id, pub)
}

// depositMail seals a message for each of to's devices and leaves it in
// their mailbox. Each device's box key must be signed by that device's
// identity key, and the device must belong to to (their device chain,
// checked against your pin), just as for a direct message. One device
// taking it is enough.
func (n *node) depositMail(id string, sent time.Time, to, body string) error {
	if !directory.ValidUsername(to) {
		return errors.New("not a server account name")
	}
	if !n.dir.Connected() {
		return errors.New("not connected to server")
	}
	resp, err := n.dir.MailboxKey(to)
	if err != nil {
		return err
	}
	verified, err := n.verifiedDevices(to, resp.Certs)
	if err != nil {
		return err
	}
	var lastErr error = errors.New("the server sent no mailbox key")
	sent1 := false
	for _, b := range resp.Boxes {
		if err := n.sealFor(id, sent, to, body, b, verified); err != nil {
			lastErr = err
			continue
		}
		sent1 = true
	}
	if !sent1 {
		return lastErr
	}
	return nil
}

// sealFor checks one device's box key and leaves the letter for it.
func (n *node) sealFor(id string, sent time.Time, to, body string, b directory.Box, verified map[string]bool) error {
	if len(b.PubKey) != ed25519.PublicKeySize || !strings.EqualFold(identity.PeerID(b.PubKey), b.PeerID) ||
		!mailbox.VerifyBoxKey(b.PubKey, b.BoxKey, b.BoxSig) {
		return errors.New("the server sent a mailbox key that doesn't check out")
	}
	if n.isRevoked(b.PeerID) {
		return fmt.Errorf("%s is %w", to, errRevoked)
	}
	if verified != nil {
		if !verified[b.PeerID] {
			p, _ := storage.PeerByName(to)
			return &storage.IdentityMismatchError{Name: to, Expected: p.ID, Got: b.PeerID}
		}
	} else {
		// A server without device chains: one key, checked the old way.
		if configured := configuredID(n.cfg, to); configured != "" && !strings.EqualFold(configured, b.PeerID) {
			return &storage.IdentityMismatchError{Name: to, Expected: configured, Got: b.PeerID}
		}
		if err := storage.PinOutgoing(to, b.PeerID, ""); err != nil {
			return err
		}
	}
	var boxKey [32]byte
	copy(boxKey[:], b.BoxKey)
	sealed, err := mailbox.Seal(n.nm.Identity(), senderName(n.cfg), b.PeerID, &boxKey, id, sent, body)
	if err != nil {
		return err
	}
	if len(sealed) > directory.MaxSealedLetter {
		return errors.New("message too large for the mailbox")
	}
	return n.dir.MailboxPut(to, b.PeerID, sealed)
}

// mailWhenOffline moves a queued message to the contact's mailbox if the
// server confirms they are offline. It checks each message at most once a
// minute. Called with outboxMu held.
func (n *node) mailWhenOffline(it storage.OutboxItem, now time.Time) bool {
	if n.mailTried == nil {
		n.mailTried = map[string]time.Time{}
	}
	if now.Sub(n.mailTried[it.ID]) < time.Minute || !n.dir.Connected() || !directory.ValidUsername(it.To) {
		return false
	}
	n.mailTried[it.ID] = now
	if len(n.mailTried) > 1000 {
		n.mailTried = map[string]time.Time{it.ID: now}
	}
	// A lookup of someone offline signals nobody; of someone online it
	// asks them to punch, which a retry would do anyway.
	if _, err := n.dir.Lookup(it.To); !errors.Is(err, directory.ErrUserOffline) {
		return false
	}
	if n.mailItem(it, fmt.Errorf("%s is %w", it.To, errOffline)) != nil {
		return false
	}
	delete(n.mailTried, it.ID)
	return true
}

// wakeMail asks the mailbox loop to fetch now.
func (n *node) wakeMail() {
	select {
	case n.mailWake <- struct{}{}:
	default:
	}
}

func (n *node) runMailbox(ctx context.Context) {
	ticker := time.NewTicker(mailboxPoll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-n.mailWake:
		}
		n.fetchMail()
	}
}

// fetchMail receives the letters waiting on the server. Each is opened,
// checked like a direct message, handed on, and only then deleted from the
// server, so nothing is lost if this process stops halfway.
func (n *node) fetchMail() {
	n.mailMu.Lock()
	defer n.mailMu.Unlock()
	for round := 0; round < 100 && n.dir.Connected(); round++ {
		letters, more, err := n.dir.MailboxFetch()
		if err != nil || len(letters) == 0 {
			return
		}
		var done []string
		busy := false
		for _, l := range letters {
			if err := n.openLetter(l); errors.Is(err, network.ErrReceiverBusy) {
				busy = true
				break
			}
			done = append(done, l.ID)
		}
		if err := n.dir.MailboxAck(done); err != nil || busy || !more {
			return
		}
	}
}

// openLetter delivers one letter. Letters that can never be delivered (not
// sealed for this device, forged, refused) are logged as dropped and count
// as handled; only a busy receiver leaves a letter on the server.
func (n *node) openLetter(sl directory.Letter) error {
	from := "peer " + storage.CleanName(sl.From)
	l, peerID, err := mailbox.Open(n.nm.Identity(), sl.Sealed)
	if err != nil {
		n.logDrop(storage.DroppedMessage{Dir: "in", Peer: from, Reason: "mailbox letter rejected: " + err.Error()})
		return nil
	}
	if err := n.accept(peerID, l.From); err != nil {
		return nil // accept logged it
	}
	err = n.nm.Deliver(network.IncomingMessage{ID: l.ID, PeerID: peerID, Name: l.From, Body: l.Body,
		Sent: time.Unix(l.TS, 0)}, 5*time.Second)
	if err != nil && !errors.Is(err, network.ErrReceiverBusy) {
		n.logDrop(storage.DroppedMessage{Dir: "in", Peer: from, Reason: "mailbox letter rejected: " + err.Error()})
		return nil
	}
	return err
}
