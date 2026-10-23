// Package mailbox seals messages for a recipient who is offline, so a
// server can hold them without being able to read or forge them.
//
// Each identity derives a "box" key pair (X25519) from its Ed25519 seed and
// signs the public half, proving the box key belongs to that identity. A
// letter is signed by the sender's Ed25519 key, then sealed to the
// recipient's box key (NaCl anonymous box: X25519 + XSalsa20-Poly1305).
// Only the recipient can open it, and the recipient can check who wrote it.
package mailbox

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/necromancer124/tarion/internal/identity"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// BoxKeys derives this identity's X25519 key pair from its Ed25519 seed.
func BoxKeys(id *identity.Identity) (pub, priv *[32]byte) {
	h := sha512.Sum512(id.Key.Seed())
	priv = new([32]byte)
	copy(priv[:], h[:32])
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	p, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		panic(err) // only fails for a low-order point, impossible for a clamped scalar
	}
	pub = new([32]byte)
	copy(pub[:], p)
	return pub, priv
}

const boxKeyContext = "tarion-mailbox-key-v1:"

// SignBoxKey proves that boxPub belongs to id.
func SignBoxKey(id *identity.Identity, boxPub *[32]byte) []byte {
	return ed25519.Sign(id.Key, append([]byte(boxKeyContext), boxPub[:]...))
}

// VerifyBoxKey checks a box key against the identity key that signed it.
func VerifyBoxKey(edPub ed25519.PublicKey, boxPub, sig []byte) bool {
	return len(edPub) == ed25519.PublicKeySize && len(boxPub) == 32 &&
		ed25519.Verify(edPub, append([]byte(boxKeyContext), boxPub...), sig)
}

// Letter is the signed content inside a sealed message.
type Letter struct {
	V       int    `json:"v"`
	ID      string `json:"id"`
	TS      int64  `json:"ts"`
	From    string `json:"from"`     // display name the sender claims
	FromKey []byte `json:"from_key"` // sender's Ed25519 public key
	To      string `json:"to"`       // recipient's peer ID
	Body    string `json:"body"`
	Sig     []byte `json:"sig"`
}

func (l *Letter) signed() []byte {
	return []byte(strings.Join([]string{"tarion-letter-v1", l.ID, fmt.Sprint(l.TS), l.From,
		fmt.Sprintf("%x", l.FromKey), l.To, l.Body}, "\n"))
}

// Seal signs a letter as sender and seals it to the recipient's box key.
func Seal(sender *identity.Identity, fromName, toPeerID string, toBoxKey *[32]byte, id string, sent time.Time, body string) ([]byte, error) {
	l := &Letter{V: 1, ID: id, TS: sent.Unix(), From: fromName,
		FromKey: sender.Key.Public().(ed25519.PublicKey), To: toPeerID, Body: body}
	l.Sig = ed25519.Sign(sender.Key, l.signed())
	// No HTML escaping: a message full of "<" must not grow sixfold.
	var plain bytes.Buffer
	enc := json.NewEncoder(&plain)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(l); err != nil {
		return nil, err
	}
	return box.SealAnonymous(nil, plain.Bytes(), toBoxKey, rand.Reader)
}

// Open unseals a letter addressed to recipient and checks its signature.
// It returns the letter and the sender's peer ID.
func Open(recipient *identity.Identity, sealed []byte) (*Letter, string, error) {
	pub, priv := BoxKeys(recipient)
	plain, ok := box.OpenAnonymous(nil, sealed, pub, priv)
	if !ok {
		return nil, "", errors.New("not sealed for this device, or damaged")
	}
	var l Letter
	if err := json.Unmarshal(plain, &l); err != nil {
		return nil, "", fmt.Errorf("malformed letter: %w", err)
	}
	if l.V != 1 || len(l.FromKey) != ed25519.PublicKeySize || !ed25519.Verify(l.FromKey, l.signed(), l.Sig) {
		return nil, "", errors.New("bad signature: the sender can't be verified")
	}
	if l.To != recipient.ID {
		// Signed for someone else and re-sealed to us: refuse.
		return nil, "", errors.New("addressed to another user")
	}
	return &l, identity.PeerID(l.FromKey), nil
}
