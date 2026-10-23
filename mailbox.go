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

// mailboxLogin returns the box key and its signature to publish at login.
func mailboxLogin(id *identity.Identity) (key, sig []byte) {
	pub, _ := mailbox.BoxKeys(id)
	return pub[:], mailbox.SignBoxKey(id, pub)
}

// depositMail seals a message for to and leaves it in their mailbox. The
// key the server hands out must be signed by to's identity key, and that
// key must match the one pinned for to, just as a direct message would.
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
	if len(resp.PubKey) != ed25519.PublicKeySize || !strings.EqualFold(identity.PeerID(resp.PubKey), resp.PeerID) ||
		!mailbox.VerifyBoxKey(resp.PubKey, resp.BoxKey, resp.BoxSig) {
		return errors.New("the server sent a mailbox key that doesn't check out")
	}
	peerID := resp.PeerID
	if n.isRevoked(peerID) {
		return fmt.Errorf("%s is %w", to, errRevoked)
	}
	if configured := configuredID(n.cfg, to); configured != "" && !strings.EqualFold(configured, peerID) {
		return &storage.IdentityMismatchError{Name: to, Expected: configured, Got: peerID}
	}
	if err := storage.PinOutgoing(to, peerID, ""); err != nil {
		return err
	}
	var boxKey [32]byte
	copy(boxKey[:], resp.BoxKey)
	sealed, err := mailbox.Seal(n.nm.Identity(), senderName(n.cfg), peerID, &boxKey, id, sent, body)
	if err != nil {
		return err
	}
	if len(sealed) > directory.MaxSealedLetter {
		return errors.New("message too large for the mailbox")
	}
	return n.dir.MailboxPut(to, sealed)
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
	if err := n.accept(peerID); err != nil {
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
