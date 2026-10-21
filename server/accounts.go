package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/necromancer124/tarion/internal/directory"
	"golang.org/x/crypto/argon2"
)

var (
	errNoSuchUser       = errors.New("no such user")
	errAuthFailed       = errors.New("wrong password")
	errNameTaken        = errors.New("name taken")
	errPasswordRequired = errors.New("password required")
)

// account is one user. Hash is "argon2id$..." or, for accounts imported from
// the old users.db, "sha256$salt$hex" until the next password login upgrades it.
type account struct {
	Name    string    `json:"name"`
	Hash    string    `json:"hash"`
	PeerID  string    `json:"peer_id,omitempty"`
	Created time.Time `json:"created"`
}

type accountsFile struct {
	Version int       `json:"version"`
	Users   []account `json:"users"`
}

// Accounts is the user database, saved as JSON with atomic replace so a
// crash mid-write cannot lose it, and so no field can inject a record.
type Accounts struct {
	mu    sync.Mutex
	path  string
	byKey map[string]*account
}

// LoadAccounts reads path. If it does not exist yet and legacyPath (the old
// "name:salt:sha256" users.db) does, those accounts are imported.
func LoadAccounts(path, legacyPath string) (*Accounts, error) {
	a := &Accounts{path: path, byKey: map[string]*account{}}
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		var f accountsFile
		if err := json.Unmarshal(data, &f); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		for i := range f.Users {
			u := f.Users[i]
			key := directory.NameKey(u.Name)
			if !directory.ValidUsername(u.Name) || a.byKey[key] != nil {
				log.Printf("accounts: skipping invalid or duplicate account %q", u.Name)
				continue
			}
			a.byKey[key] = &u
		}
		return a, nil
	case !os.IsNotExist(err):
		return nil, err
	}

	if legacyPath == "" {
		return a, nil
	}
	n, err := a.importLegacy(legacyPath)
	if err != nil {
		return nil, err
	}
	if n > 0 {
		log.Printf("accounts: imported %d accounts from %s into %s", n, legacyPath, path)
		a.mu.Lock()
		defer a.mu.Unlock()
		return a, a.saveLocked()
	}
	return a, nil
}

// importLegacy reads the old flat file. The old server let a username contain
// newlines, which could plant a second record for someone else's name, so a
// name that appears more than once is dropped entirely (that user registers
// again) rather than guessing which record is genuine.
func (a *Accounts) importLegacy(path string) (int, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer f.Close()

	type rec struct{ name, salt, hash string }
	var recs []rec
	seen := map[string]int{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) != 3 || !directory.ValidUsername(parts[0]) || len(parts[2]) != 64 {
			log.Printf("accounts: skipping malformed legacy record")
			continue
		}
		recs = append(recs, rec{parts[0], parts[1], parts[2]})
		seen[directory.NameKey(parts[0])]++
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	n := 0
	for _, r := range recs {
		key := directory.NameKey(r.name)
		if seen[key] > 1 {
			if seen[key] != -1 {
				log.Printf("accounts: WARNING legacy name %q appears %d times (possible injected record); dropping it, the user must register again", r.name, seen[key])
				seen[key] = -1
			}
			continue
		}
		if seen[key] == -1 {
			continue
		}
		a.byKey[key] = &account{Name: r.name, Hash: "sha256$" + r.salt + "$" + r.hash, Created: time.Now()}
		n++
	}
	return n, nil
}

func (a *Accounts) saveLocked() error {
	users := make([]account, 0, len(a.byKey))
	for _, u := range a.byKey {
		users = append(users, *u)
	}
	sort.Slice(users, func(i, j int) bool { return directory.NameKey(users[i].Name) < directory.NameKey(users[j].Name) })
	data, err := json.MarshalIndent(accountsFile{Version: 1, Users: users}, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(a.path); dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	tmp := a.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, a.path)
}

func (a *Accounts) get(name string) (account, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	u, ok := a.byKey[directory.NameKey(name)]
	if !ok {
		return account{}, false
	}
	return *u, true
}

// Create registers a new account bound to peerID and returns its name.
func (a *Accounts) Create(name, pass, peerID string) (string, error) {
	if _, ok := a.get(name); ok {
		return "", errNameTaken
	}
	hash, err := hashPassword(pass) // slow on purpose; done outside the lock
	if err != nil {
		return "", err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	key := directory.NameKey(name)
	if a.byKey[key] != nil {
		return "", errNameTaken
	}
	a.byKey[key] = &account{Name: name, Hash: hash, PeerID: peerID, Created: time.Now()}
	return name, a.saveLocked()
}

// LoginWithPassword checks the password, upgrades a legacy hash, and binds
// peerID to the account (a new device or reinstall). It returns the
// canonical name and whether the bound key changed.
func (a *Accounts) LoginWithPassword(name, pass, peerID string) (string, bool, error) {
	u, ok := a.get(name)
	if !ok {
		return "", false, errNoSuchUser
	}
	match, legacy := verifyPassword(u.Hash, pass)
	if !match {
		return "", false, errAuthFailed
	}
	var newHash string
	if legacy {
		h, err := hashPassword(pass)
		if err != nil {
			return "", false, err
		}
		newHash = h
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	cur := a.byKey[directory.NameKey(name)]
	if cur == nil || cur.Hash != u.Hash {
		return "", false, errAuthFailed // changed underneath us; make the client retry
	}
	changed := cur.PeerID != peerID
	if newHash != "" {
		cur.Hash = newHash
	}
	if changed || newHash != "" {
		cur.PeerID = peerID
		if err := a.saveLocked(); err != nil {
			return "", false, err
		}
	}
	return cur.Name, changed && u.PeerID != "", nil
}

// LoginWithKey succeeds when peerID is the key bound to the account.
func (a *Accounts) LoginWithKey(name, peerID string) (string, error) {
	u, ok := a.get(name)
	if !ok {
		return "", errNoSuchUser
	}
	if u.PeerID == "" || subtle.ConstantTimeCompare([]byte(u.PeerID), []byte(peerID)) != 1 {
		return "", errPasswordRequired
	}
	return u.Name, nil
}

// argon2id parameters (OWASP minimum: 19 MiB, 2 passes, 1 lane).
const (
	argonTime    = 2
	argonMemory  = 19 * 1024
	argonThreads = 1
	argonKeyLen  = 32
)

var b64 = base64.RawStdEncoding

func hashPassword(pass string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	sum := argon2.IDKey([]byte(pass), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("argon2id$%d$%d$%d$%s$%s", argonMemory, argonTime, argonThreads, b64.EncodeToString(salt), b64.EncodeToString(sum)), nil
}

// verifyPassword compares in constant time. legacy is true for an old
// SHA-256 hash that should be upgraded.
func verifyPassword(stored, pass string) (match, legacy bool) {
	parts := strings.Split(stored, "$")
	switch {
	case len(parts) == 6 && parts[0] == "argon2id":
		var mem, t uint32
		var threads uint8
		if _, err := fmt.Sscanf(parts[1]+" "+parts[2]+" "+parts[3], "%d %d %d", &mem, &t, &threads); err != nil {
			return false, false
		}
		salt, err1 := b64.DecodeString(parts[4])
		want, err2 := b64.DecodeString(parts[5])
		if err1 != nil || err2 != nil {
			return false, false
		}
		got := argon2.IDKey([]byte(pass), salt, t, mem, threads, uint32(len(want)))
		return subtle.ConstantTimeCompare(got, want) == 1, false
	case len(parts) == 3 && parts[0] == "sha256":
		sum := sha256.Sum256([]byte(parts[1] + ":" + pass))
		got := hex.EncodeToString(sum[:])
		return subtle.ConstantTimeCompare([]byte(got), []byte(parts[2])) == 1, true
	}
	return false, false
}
