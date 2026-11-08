// Package devices lets one account use several devices, each with its own
// identity key, without trusting the server to say which keys are yours.
//
// An account's devices form a chain of certificates. The first device is
// the root. Every later device is approved by one already on the account,
// which signs a certificate for it. Contacts check the chain back to the
// key they pinned on first contact, so the server can't add a key of its
// own: it can't produce an approved device's signature.
//
// A removed device stays in the chain, marked removed: devices it approved
// earlier stay valid, but it no longer counts as one of yours.
package devices

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"

	"github.com/necromancer124/tarion/internal/identity"
)

// MaxActive caps the active devices per account.
const MaxActive = 8

// MaxNameRunes caps a device's name.
const MaxNameRunes = 40

// Cert is one device of an account.
type Cert struct {
	Account string `json:"account"` // account name key (lower case)
	PeerID  string `json:"peer_id"`
	PubKey  []byte `json:"pub_key,omitempty"` // may be missing for a root migrated from an old server
	Name    string `json:"name"`
	Added   int64  `json:"added"`         // unix seconds
	By      string `json:"by,omitempty"`  // approving device's peer ID; "" for the root
	Sig     []byte `json:"sig,omitempty"` // by's signature over signed()
	Removed bool   `json:"removed,omitempty"`
}

func (c *Cert) signed() []byte {
	return []byte(strings.Join([]string{"tarion-device-v1", c.Account, c.PeerID,
		fmt.Sprintf("%x", c.PubKey), c.Name, fmt.Sprint(c.Added), c.By}, "\n"))
}

// Sign makes approver vouch for c (approver must be a device on c.Account).
func Sign(approver *identity.Identity, c *Cert) {
	c.By = approver.ID
	c.Sig = ed25519.Sign(approver.Key, c.signed())
}

// selfConsistent checks that a cert's key matches its peer ID.
func (c *Cert) selfConsistent() bool {
	return len(c.PubKey) == ed25519.PublicKeySize && identity.PeerID(c.PubKey) == c.PeerID
}

// Verify checks certs against trusted, a device key you already trust for
// this account (your pin). It returns the active devices that chain back
// to it, trusted itself included if it is still active. It fails when
// trusted isn't part of the account any more: the account was reset, which
// contacts must see as a key change.
func Verify(account string, certs []Cert, trusted string) ([]string, error) {
	byID := map[string]*Cert{}
	for i := range certs {
		c := &certs[i]
		if c.Account != account || c.PeerID == "" {
			return nil, errors.New("device list belongs to another account")
		}
		byID[c.PeerID] = c
	}
	if byID[trusted] == nil {
		return nil, errors.New("the key you know for this account is no longer one of its devices")
	}
	ok := map[string]bool{trusted: true}
	for changed := true; changed; {
		changed = false
		for id, c := range byID {
			if ok[id] || c.By == "" || !ok[c.By] {
				continue
			}
			approver := byID[c.By]
			if !approver.selfConsistent() || !c.selfConsistent() || !ed25519.Verify(approver.PubKey, c.signed(), c.Sig) {
				continue
			}
			ok[id], changed = true, true
		}
	}
	// Trust only flows down from trusted, never up to whoever claims to
	// have approved it: a server could forge such a claim with a key of its
	// own. That is why contacts pin the account's root (see Root).
	var active []string
	for id := range ok {
		if !byID[id].Removed {
			active = append(active, id)
		}
	}
	return active, nil
}

// Root returns the account's first device. Contacts pin it as the account's
// trust anchor, since every approved device descends from it.
func Root(certs []Cert) (Cert, bool) {
	for _, c := range certs {
		if c.By == "" {
			return c, true
		}
	}
	return Cert{}, false
}

// Check is what the server verifies before adding a device: c is a fresh,
// well-formed cert signed by an active device of the account.
func Check(certs []Cert, c Cert) error {
	if !c.selfConsistent() {
		return errors.New("the device's key doesn't match its ID")
	}
	if n := len([]rune(c.Name)); n == 0 || n > MaxNameRunes {
		return fmt.Errorf("device name must be 1-%d characters", MaxNameRunes)
	}
	active := 0
	var approver *Cert
	for i := range certs {
		if certs[i].PeerID == c.PeerID {
			return errors.New("this device is already on the account")
		}
		if !certs[i].Removed {
			active++
			if certs[i].PeerID == c.By {
				approver = &certs[i]
			}
		}
	}
	if active >= MaxActive {
		return fmt.Errorf("an account can have at most %d devices; remove one first", MaxActive)
	}
	if approver == nil || !approver.selfConsistent() {
		return errors.New("the approving device isn't an active device of this account")
	}
	if !ed25519.Verify(approver.PubKey, c.signed(), c.Sig) {
		return errors.New("bad approval signature")
	}
	return nil
}
