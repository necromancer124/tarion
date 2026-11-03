package storage

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/necromancer124/tarion/internal/vault"
)

// The data key, once unlocked (see package vault). While it is set, every
// file written here is encrypted; files are read in either form, so data
// from before encryption was turned on still opens.
var (
	keyMu   sync.RWMutex
	dataKey []byte
)

// SetDataKey turns encryption on (key) or off (nil) for this process.
func SetDataKey(key []byte) {
	keyMu.Lock()
	dataKey = append([]byte(nil), key...)
	if key == nil {
		dataKey = nil
	}
	keyMu.Unlock()
}

// DataKey returns the unlocked data key, or nil.
func DataKey() []byte { return currentKey() }

func currentKey() []byte {
	keyMu.RLock()
	defer keyMu.RUnlock()
	return dataKey
}

// ErrLocked means a file is encrypted and the data key isn't unlocked.
var ErrLocked = errors.New("your Tarion data is encrypted and not unlocked")

func GetVaultPath() string { return filepath.Join(GetBaseConfigDir(), "vault.json") }

// readSealed reads a whole file, decrypting it if it is sealed.
func readSealed(path, kind string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil || !vault.IsSealed(data) {
		return data, err
	}
	key := currentKey()
	if key == nil {
		return nil, ErrLocked
	}
	return vault.Open(key, kind, data)
}

// writeSealed writes a whole file atomically, sealed while a key is set.
func writeSealed(path, kind string, data []byte) error {
	if key := currentKey(); key != nil {
		data = vault.Seal(key, kind, data)
	}
	return writeFileAtomic(path, data)
}

// sealLine prepares one line of an append-only file for writing.
func sealLine(kind, line string) string {
	if key := currentKey(); key != nil {
		return vault.SealLine(key, kind, line)
	}
	return line
}

// unreadableLine replaces a line that can't be decrypted.
const unreadableLine = "[this line can't be read: it is encrypted with a different key, or damaged]"

// openLine reads one line of an append-only file.
func openLine(kind, line string) (string, error) {
	if !vault.IsSealedLine(line) {
		return line, nil
	}
	key := currentKey()
	if key == nil {
		return "", ErrLocked
	}
	plain, err := vault.OpenLine(key, kind, line)
	if err != nil {
		return unreadableLine, nil
	}
	return plain, nil
}

// Kinds of sealed files: authenticated, so one can't be passed off as another.
const (
	kindIdentity = "identity"
	kindPeers    = "peers"
	kindOutbox   = "outbox"
	kindHistory  = "history"
	kindDropped  = "dropped"
)

// Reseal rewrites every file in the current mode: sealed while a key is
// set, plain after SetDataKey(nil). It is used when encryption is turned
// on (encrypting old files) or off, and when the key changes (call it with
// the old key set via from). Nothing else may write these files meanwhile.
func Reseal(from []byte) error {
	to := currentKey()
	SetDataKey(from)
	defer SetDataKey(to)

	type whole struct{ path, kind string }
	wholes := []whole{{GetIdentityPath(), kindIdentity}, {GetPeersPath(), kindPeers}, {GetOutboxPath(), kindOutbox}}
	for _, w := range wholes {
		data, err := readSealed(w.path, w.kind)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		SetDataKey(to)
		err = writeSealed(w.path, w.kind, data)
		SetDataKey(from)
		if err != nil {
			return err
		}
	}

	lineFiles := []whole{{GetDroppedPath(), kindDropped}}
	entries, _ := os.ReadDir(GetHistoryDir())
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".txt") {
			lineFiles = append(lineFiles, whole{filepath.Join(GetHistoryDir(), e.Name()), kindHistory})
		}
	}
	for _, f := range lineFiles {
		raw, err := readRawLines(f.path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		plain := make([]string, 0, len(raw))
		for _, l := range raw {
			p, err := openLine(f.kind, l)
			if err != nil {
				return err
			}
			plain = append(plain, p)
		}
		SetDataKey(to)
		out := make([]string, len(plain))
		for i, p := range plain {
			out[i] = sealLine(f.kind, p)
		}
		SetDataKey(from)
		body := ""
		if len(out) > 0 {
			body = strings.Join(out, "\n") + "\n"
		}
		if err := writeFileAtomic(f.path, []byte(body)); err != nil {
			return err
		}
	}
	return nil
}

// readRawLines reads a file's non-empty lines unchanged (history lines are
// indented, so readLines' trimming would alter them).
func readRawLines(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, l := range strings.Split(string(data), "\n") {
		if l = strings.TrimRight(l, "\r"); l != "" {
			out = append(out, l)
		}
	}
	return out, nil
}

// NeedsSealing reports whether some file is still plain while a key is set.
func NeedsSealing() bool {
	if currentKey() == nil {
		return false
	}
	for _, p := range []string{GetIdentityPath(), GetPeersPath(), GetOutboxPath()} {
		if data, err := os.ReadFile(p); err == nil && len(data) > 0 && !vault.IsSealed(data) {
			return true
		}
	}
	files := []string{GetDroppedPath()}
	entries, _ := os.ReadDir(GetHistoryDir())
	for _, e := range entries {
		if !e.IsDir() {
			files = append(files, filepath.Join(GetHistoryDir(), e.Name()))
		}
	}
	for _, p := range files {
		lines, _ := readRawLines(p)
		for _, l := range lines {
			if !vault.IsSealedLine(l) {
				return true
			}
		}
	}
	return false
}
