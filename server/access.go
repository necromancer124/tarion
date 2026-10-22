package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/necromancer124/tarion/internal/directory"
)

// Registration modes.
const (
	RegOpen   = "open"   // anyone can create an account
	RegInvite = "invite" // a one-time invite code is required
	RegClosed = "closed" // no new accounts
)

// banList is a text file of usernames and/or peer IDs, one per line, "#"
// for comments. It is re-read whenever it changes, so an operator can ban
// someone without restarting the server.
type banList struct {
	path string

	mu    sync.Mutex
	mod   time.Time
	size  int64
	names map[string]bool
	keys  map[string]bool
}

func newBanList(path string) *banList {
	b := &banList{path: path, names: map[string]bool{}, keys: map[string]bool{}}
	b.refresh()
	return b
}

// normalizeKey turns "abcd efgh ..." (as `tarion id` prints it) into a peer
// ID, or returns "" if the entry is not shaped like one.
func normalizeKey(s string) string {
	k := strings.ToLower(strings.ReplaceAll(s, " ", ""))
	if len(k) != 32 {
		return ""
	}
	for _, r := range k {
		if !(r >= 'a' && r <= 'z' || r >= '2' && r <= '7') {
			return ""
		}
	}
	return k
}

// refresh reloads the file if it changed and reports whether it did.
func (b *banList) refresh() bool {
	if b.path == "" {
		return false
	}
	info, err := os.Stat(b.path)
	b.mu.Lock()
	defer b.mu.Unlock()
	if err != nil {
		changed := len(b.names)+len(b.keys) > 0
		b.names, b.keys, b.mod, b.size = map[string]bool{}, map[string]bool{}, time.Time{}, 0
		return changed
	}
	if info.ModTime().Equal(b.mod) && info.Size() == b.size {
		return false
	}
	names, keys, err := readBans(b.path)
	if err != nil {
		return false
	}
	b.names, b.keys, b.mod, b.size = names, keys, info.ModTime(), info.Size()
	return true
}

func readBans(path string) (map[string]bool, map[string]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	names, keys := map[string]bool{}, map[string]bool{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k := normalizeKey(line); k != "" {
			keys[k] = true
		}
		names[directory.NameKey(line)] = true
	}
	return names, keys, scanner.Err()
}

// snapshot returns copies of the banned name keys and peer IDs.
func (b *banList) snapshot() (names, keys []string) {
	b.refresh()
	b.mu.Lock()
	defer b.mu.Unlock()
	for n := range b.names {
		names = append(names, n)
	}
	for k := range b.keys {
		keys = append(keys, k)
	}
	return names, keys
}

func (b *banList) Banned(name, peerID string) bool {
	b.refresh()
	b.mu.Lock()
	defer b.mu.Unlock()
	return (name != "" && b.names[directory.NameKey(name)]) || (peerID != "" && b.keys[strings.ToLower(peerID)])
}

// editBans adds or removes one entry (used by `tariond ban` / `unban`).
func editBans(path, entry string, add bool) (bool, error) {
	entry = strings.TrimSpace(entry)
	if entry == "" || strings.ContainsAny(entry, "\r\n") {
		return false, errors.New("empty or multi-line entry")
	}
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	var lines []string
	found := false
	for _, l := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		l = strings.TrimRight(l, "\r")
		if strings.EqualFold(strings.TrimSpace(l), entry) {
			found = true
			if !add {
				continue
			}
		}
		if l != "" || len(lines) > 0 {
			lines = append(lines, l)
		}
	}
	if add == found {
		return false, nil // already banned / not banned
	}
	if add {
		lines = append(lines, entry)
	}
	return true, writeAtomic(path, []byte(strings.Join(lines, "\n")+"\n"))
}

func writeAtomic(path string, data []byte) error {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// invites keeps one file per unused code in a directory. Using a code is a
// single os.Remove, which succeeds for exactly one caller, so codes can be
// created while the server runs without any locking.
type invites struct{ dir string }

var inviteEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

const inviteLen = 16 // 80 bits

// normalizeInvite accepts "ABCD-EFGH-..." in any case and returns the bare
// code, or "" when it cannot be one (which also rules out path tricks).
func normalizeInvite(code string) string {
	c := strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(code))
	if len(c) != inviteLen {
		return ""
	}
	for _, r := range c {
		if !(r >= 'A' && r <= 'Z' || r >= '2' && r <= '7') {
			return ""
		}
	}
	return c
}

func formatInvite(c string) string {
	return c[0:4] + "-" + c[4:8] + "-" + c[8:12] + "-" + c[12:16]
}

func (i invites) Create(n int) ([]string, error) {
	if err := os.MkdirAll(i.dir, 0700); err != nil {
		return nil, err
	}
	var out []string
	for len(out) < n {
		b := make([]byte, 10)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		code := inviteEncoding.EncodeToString(b)
		f, err := os.OpenFile(filepath.Join(i.dir, code), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			if os.IsExist(err) {
				continue
			}
			return nil, err
		}
		_, _ = fmt.Fprintf(f, "created %s\n", time.Now().UTC().Format(time.RFC3339))
		_ = f.Close()
		out = append(out, formatInvite(code))
	}
	return out, nil
}

// Consume uses up a code, reporting whether it was valid.
func (i invites) Consume(code string) bool {
	c := normalizeInvite(code)
	return c != "" && os.Remove(filepath.Join(i.dir, c)) == nil
}

// Restore puts back a code that was consumed for a registration that then
// failed (for example the name was taken a moment earlier).
func (i invites) Restore(code string) {
	if c := normalizeInvite(code); c != "" {
		_ = os.WriteFile(filepath.Join(i.dir, c), []byte("restored\n"), 0600)
	}
}

// deletions holds operator requests to delete accounts, one file per name
// (hex-encoded, so no name can be an unsafe or reserved file name). The
// running server is the only writer of users.json; it picks requests up
// within seconds, or at its next start.
type deletions struct{ dir string }

func (d deletions) Request(name string) error {
	if err := os.MkdirAll(d.dir, 0700); err != nil {
		return err
	}
	f := filepath.Join(d.dir, hex.EncodeToString([]byte(directory.NameKey(name))))
	return os.WriteFile(f, []byte(name+"\n"), 0600)
}

// Pending returns the names waiting to be deleted.
func (d deletions) Pending() []string {
	entries, err := os.ReadDir(d.dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		raw, err := hex.DecodeString(e.Name())
		if err != nil || !directory.ValidUsername(string(raw)) {
			continue
		}
		names = append(names, string(raw))
	}
	return names
}

func (d deletions) Done(name string) {
	_ = os.Remove(filepath.Join(d.dir, hex.EncodeToString([]byte(directory.NameKey(name)))))
}

// passwordProblem explains why a new password is not acceptable, or "".
func passwordProblem(user, pass string, minLen int) string {
	runes := []rune(pass)
	switch {
	case len(runes) == 0 || len(runes) < minLen:
		return fmt.Sprintf("use at least %d characters", minLen)
	case len(pass) > directory.MaxPasswordLen:
		return fmt.Sprintf("use at most %d bytes", directory.MaxPasswordLen)
	case len(user) >= 3 && strings.Contains(strings.ToLower(pass), strings.ToLower(user)):
		return "it must not contain your username"
	case strings.Count(pass, string(runes[0])) == len(runes):
		return "it must not repeat one character"
	}
	return ""
}
