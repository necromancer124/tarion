package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"
)

// Peer pins a display name to the Ed25519 peer ID first seen for it
// (trust on first use). After that, a different key using the same name is
// treated as a different person.
type Peer struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Addr      string    `json:"addr,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// IdentityMismatchError means a pinned contact answered with a different key.
type IdentityMismatchError struct {
	Name     string
	Expected string
	Got      string
}

func (e *IdentityMismatchError) Error() string {
	return fmt.Sprintf("identity of %s changed (pinned %s, got %s); refusing to send. "+
		"If they really reinstalled, verify the new ID with them and run: tarion forget %s",
		e.Name, short(e.Expected), short(e.Got), e.Name)
}

var peersMu sync.Mutex

func GetPeersPath() string { return filepath.Join(GetBaseConfigDir(), "peers.json") }

func short(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func loadPeers() ([]Peer, error) {
	data, err := os.ReadFile(GetPeersPath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var peers []Peer
	return peers, json.Unmarshal(data, &peers)
}

func savePeers(peers []Peer) error {
	data, err := json.MarshalIndent(peers, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(GetPeersPath(), data)
}

func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ListPeers returns every pinned peer.
func ListPeers() ([]Peer, error) {
	peersMu.Lock()
	defer peersMu.Unlock()
	return loadPeers()
}

// PeerByName returns the pinned peer for a display name.
func PeerByName(name string) (Peer, bool) {
	peers, err := ListPeers()
	if err != nil {
		return Peer{}, false
	}
	for _, p := range peers {
		if strings.EqualFold(p.Name, name) {
			return p, true
		}
	}
	return Peer{}, false
}

func GetRevokedPath() string { return filepath.Join(GetBaseConfigDir(), "revoked.json") }

// LoadRevoked returns the banned keys last received from the server, so
// bans still apply before (or without) a server connection.
func LoadRevoked() map[string]bool {
	set := map[string]bool{}
	data, err := os.ReadFile(GetRevokedPath())
	if err != nil {
		return set
	}
	var keys []string
	if json.Unmarshal(data, &keys) == nil {
		for _, k := range keys {
			set[strings.ToLower(k)] = true
		}
	}
	return set
}

func SaveRevoked(keys []string) error {
	if keys == nil {
		keys = []string{}
	}
	data, err := json.Marshal(keys)
	if err != nil {
		return err
	}
	return writeFileAtomic(GetRevokedPath(), data)
}

// PeerByID returns the pinned peer for a key.
func PeerByID(id string) (Peer, bool) {
	peers, err := ListPeers()
	if err != nil {
		return Peer{}, false
	}
	for _, p := range peers {
		if strings.EqualFold(p.ID, id) {
			return p, true
		}
	}
	return Peer{}, false
}

// ResolveIncoming picks the chat name for a message whose sender key was
// proven by TLS. A known key keeps its pinned name whatever it claims now; a
// new key that claims a name already pinned to someone else gets a visibly
// different name ("bob~1a2b3c4d") so it cannot pose as that contact.
func ResolveIncoming(peerID, claimedName, addr string) (string, error) {
	peersMu.Lock()
	defer peersMu.Unlock()
	peers, err := loadPeers()
	if err != nil {
		return "", err
	}
	now := time.Now()
	for i := range peers {
		if peers[i].ID == peerID {
			if addr != "" {
				peers[i].Addr = addr
			}
			peers[i].LastSeen = now
			return peers[i].Name, savePeers(peers)
		}
	}

	name := CleanName(claimedName)
	if name == "" {
		name = "peer-" + short(peerID)
	}
	for _, p := range peers {
		if strings.EqualFold(p.Name, name) {
			name = name + "~" + short(peerID)
			break
		}
	}
	peers = append(peers, Peer{ID: peerID, Name: name, Addr: addr, FirstSeen: now, LastSeen: now})
	return name, savePeers(peers)
}

// PinOutgoing is called after the handshake with the contact the user chose
// to message. It refuses a key that differs from the pinned one, pins the key
// on first contact, and renames a known key to the name the user picked.
func PinOutgoing(name, peerID, addr string) error {
	peersMu.Lock()
	defer peersMu.Unlock()
	peers, err := loadPeers()
	if err != nil {
		return err
	}
	now := time.Now()
	for i := range peers {
		if strings.EqualFold(peers[i].Name, name) {
			if peers[i].ID != peerID {
				return &IdentityMismatchError{Name: name, Expected: peers[i].ID, Got: peerID}
			}
			peers[i].Addr, peers[i].LastSeen = addr, now
			return savePeers(peers)
		}
	}
	for i := range peers {
		if peers[i].ID == peerID {
			peers[i].Name, peers[i].Addr, peers[i].LastSeen = name, addr, now
			return savePeers(peers)
		}
	}
	peers = append(peers, Peer{ID: peerID, Name: name, Addr: addr, FirstSeen: now, LastSeen: now})
	return savePeers(peers)
}

// ForgetPeer removes the pin for a name so its next key is trusted again.
func ForgetPeer(name string) (bool, error) {
	peersMu.Lock()
	defer peersMu.Unlock()
	peers, err := loadPeers()
	if err != nil {
		return false, err
	}
	for i := range peers {
		if strings.EqualFold(peers[i].Name, name) {
			peers = append(peers[:i], peers[i+1:]...)
			return true, savePeers(peers)
		}
	}
	return false, nil
}

const maxNameRunes = 32

// CleanName turns an untrusted display name into something safe to show in a
// terminal and use as a file name.
func CleanName(name string) string {
	var b strings.Builder
	n := 0
	for _, r := range strings.TrimSpace(name) {
		if n >= maxNameRunes {
			break
		}
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' || r == '.':
			b.WriteRune(r)
		case r == ' ':
			b.WriteRune(' ')
		default:
			b.WriteRune('_')
		}
		n++
	}
	return strings.Trim(b.String(), " .")
}

// CleanText strips terminal control characters (escape sequences could
// otherwise rewrite the screen) and flattens newlines so each history entry
// stays on one line.
func CleanText(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n':
			return '⏎'
		case r == '\t':
			return ' '
		case unicode.IsControl(r), r == ' ', r == ' ':
			return -1
		}
		return r
	}, s)
}
