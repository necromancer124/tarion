package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/necromancer124/tarion/internal/directory"
)

// mailboxStore keeps letters for users who are offline, one folder per
// account: key.json (the box key the user published) and one file per
// letter. Letters are sealed by the sender; the server only stores bytes.
type mailboxStore struct {
	dir      string
	maxItems int // letters waiting per recipient
	maxBytes int // sealed bytes waiting per recipient
	perPeer  int // letters waiting from one sender to one recipient
	keep     time.Duration

	mu sync.Mutex
}

// boxRecord is what a user published at login with the mailbox on.
type boxRecord struct {
	PeerID string `json:"peer_id"`
	PubKey []byte `json:"pub_key"`
	BoxKey []byte `json:"box_key"`
	BoxSig []byte `json:"box_sig"`
}

// storedLetter is one letter on disk. PeerID is the recipient key it was
// sealed to: after a key change only the old device could open it.
type storedLetter struct {
	directory.Letter
	PeerID string `json:"peer_id"`
}

var (
	errMailboxFull = errors.New("mailbox full")
	errNoBox       = errors.New("no mailbox")
)

func (m *mailboxStore) userDir(name string) string {
	// Hex keeps any script's letters (and case) out of file names.
	return filepath.Join(m.dir, hex.EncodeToString([]byte(directory.NameKey(name))))
}

// validPeerID keeps a peer ID (base32) safe to use in a file name.
func validPeerID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= '2' && r <= '7') {
			return false
		}
	}
	return true
}

// SetKey publishes one device's box key (one file per device).
func (m *mailboxStore) SetKey(name string, rec boxRecord) error {
	if !validPeerID(rec.PeerID) {
		return errors.New("bad peer ID")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	dir := m.userDir(name)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, "key-"+rec.PeerID+".json"), data)
}

// Keys returns the box keys name's devices published.
func (m *mailboxStore) Keys(name string) []boxRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.keys(name)
}

func (m *mailboxStore) keys(name string) []boxRecord {
	entries, _ := os.ReadDir(m.userDir(name))
	var out []boxRecord
	for _, e := range entries {
		// key.json is the single key of a server from before multi-device.
		if !isKeyFile(e.Name()) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(m.userDir(name), e.Name()))
		var rec boxRecord
		if err == nil && json.Unmarshal(data, &rec) == nil && rec.PeerID != "" {
			out = append(out, rec)
		}
	}
	return out
}

func isKeyFile(name string) bool {
	return name == "key.json" || strings.HasPrefix(name, "key-") && strings.HasSuffix(name, ".json")
}

// key returns the box key of one device.
func (m *mailboxStore) key(name, peerID string) (boxRecord, error) {
	for _, rec := range m.keys(name) {
		if rec.PeerID == peerID {
			return rec, nil
		}
	}
	return boxRecord{}, errNoBox
}

// RemoveDevice deletes one device's box key and the letters sealed to it.
func (m *mailboxStore) RemoveDevice(name, peerID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	dir := m.userDir(name)
	for _, rec := range m.keys(name) {
		if rec.PeerID != peerID {
			continue
		}
		_ = os.Remove(filepath.Join(dir, "key-"+peerID+".json"))
		if legacy, err := os.ReadFile(filepath.Join(dir, "key.json")); err == nil && strings.Contains(string(legacy), `"`+peerID+`"`) {
			_ = os.Remove(filepath.Join(dir, "key.json"))
		}
	}
	for _, l := range m.letters(name) {
		if l.PeerID == peerID {
			_ = os.Remove(filepath.Join(dir, l.ID+".json"))
		}
	}
	return nil
}

// Remove deletes name's mailbox: its key and every letter waiting.
func (m *mailboxStore) Remove(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return os.RemoveAll(m.userDir(name))
}

// letters reads name's letters, oldest first. Unreadable files are skipped.
func (m *mailboxStore) letters(name string) []storedLetter {
	entries, _ := os.ReadDir(m.userDir(name))
	var out []storedLetter
	for _, e := range entries {
		if e.IsDir() || isKeyFile(e.Name()) || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(m.userDir(name), e.Name()))
		if err != nil {
			continue
		}
		var l storedLetter
		if json.Unmarshal(data, &l) == nil && l.ID != "" {
			out = append(out, l)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Received != out[j].Received {
			return out[i].Received < out[j].Received
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Put leaves a sealed letter from sender for name's device peerID. The
// limits count per device: a message to someone with three devices is
// three letters.
func (m *mailboxStore) Put(name, sender, peerID string, sealed []byte, now time.Time) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, err := m.key(name, peerID); err != nil {
		return "", err
	}
	total, waiting, fromSender := len(sealed), 0, 0
	for _, l := range m.letters(name) {
		if l.PeerID != peerID {
			continue
		}
		waiting++
		total += len(l.Sealed)
		if directory.NameKey(l.From) == directory.NameKey(sender) {
			fromSender++
		}
	}
	if waiting >= m.maxItems || total > m.maxBytes || fromSender >= m.perPeer {
		return "", errMailboxFull
	}
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	l := storedLetter{Letter: directory.Letter{ID: hex.EncodeToString(b[:]), From: sender, Received: now.Unix(), Sealed: sealed}, PeerID: peerID}
	data, err := json.Marshal(l)
	if err != nil {
		return "", err
	}
	return l.ID, writeAtomic(filepath.Join(m.userDir(name), l.ID+".json"), data)
}

// Fetch returns letters for name sealed to peerID, oldest first, up to
// directory.MaxFetchBytes (at least one), and whether more are waiting.
func (m *mailboxStore) Fetch(name, peerID string) ([]directory.Letter, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []directory.Letter
	size := 0
	for _, l := range m.letters(name) {
		if l.PeerID != peerID {
			continue
		}
		// As it will be encoded: base64 plus the other fields.
		cost := (len(l.Sealed)+2)/3*4 + len(l.From) + len(l.ID) + 64
		if len(out) > 0 && size+cost > directory.MaxFetchBytes {
			return out, true
		}
		out = append(out, l.Letter)
		size += cost
	}
	return out, false
}

// Count is how many letters for name are sealed to peerID.
func (m *mailboxStore) Count(name, peerID string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, l := range m.letters(name) {
		if l.PeerID == peerID {
			n++
		}
	}
	return n
}

// Ack deletes letters the recipient has received.
func (m *mailboxStore) Ack(name string, ids []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range ids {
		if _, err := hex.DecodeString(id); err != nil || len(id) != 24 {
			continue // never a path
		}
		_ = os.Remove(filepath.Join(m.userDir(name), id+".json"))
	}
}

// Expire deletes letters older than the keep time.
func (m *mailboxStore) Expire(now time.Time) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	users, _ := os.ReadDir(m.dir)
	removed := 0
	for _, u := range users {
		if !u.IsDir() {
			continue
		}
		name, err := hex.DecodeString(u.Name())
		if err != nil {
			continue
		}
		for _, l := range m.letters(string(name)) {
			if now.Sub(time.Unix(l.Received, 0)) > m.keep {
				if os.Remove(filepath.Join(m.dir, u.Name(), l.ID+".json")) == nil {
					removed++
				}
			}
		}
	}
	return removed
}
