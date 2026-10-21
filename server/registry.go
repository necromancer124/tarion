package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type UserEntry struct {
	Username     string
	PublicAddr   string
	PasswordHash string
	Salt         string
	LastSeen     time.Time
}

type Registry struct {
	mu       sync.RWMutex
	users    map[string]*UserEntry
	usersDB  string
	leaseTTL time.Duration
}

func NewRegistry(usersDB string, leaseTTL time.Duration) (*Registry, error) {
	r := &Registry{
		users:    make(map[string]*UserEntry),
		usersDB:  usersDB,
		leaseTTL: leaseTTL,
	}
	return r, r.loadUsersFromDisk()
}

func hashPassword(password, salt string) string {
	sum := sha256.Sum256([]byte(salt + ":" + password))
	return hex.EncodeToString(sum[:])
}

func newSalt() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(buf), nil
}

func (r *Registry) RegisterOrUpdate(username, password, addr string) error {
	username = strings.TrimSpace(username)
	addr = strings.TrimSpace(addr)
	if username == "" || password == "" || addr == "" {
		return fmt.Errorf("invalid user lease")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if existing, ok := r.users[username]; ok {
		if existing.PasswordHash != hashPassword(password, existing.Salt) {
			return fmt.Errorf("authentication failed")
		}
		existing.PublicAddr = addr
		existing.LastSeen = time.Now()
		return nil
	}

	salt, err := newSalt()
	if err != nil {
		return err
	}
	r.users[username] = &UserEntry{
		Username:     username,
		PublicAddr:   addr,
		Salt:         salt,
		PasswordHash: hashPassword(password, salt),
		LastSeen:     time.Now(),
	}
	log.Printf("registered new user %q from %s", username, addr)
	return r.saveUsersToDiskLocked()
}

func (r *Registry) ReapStaleUsers() {
	r.mu.Lock()
	defer r.mu.Unlock()

	cutoff := time.Now().Add(-r.leaseTTL)
	for name, entry := range r.users {
		if entry.PublicAddr != "" && entry.LastSeen.Before(cutoff) {
			log.Printf("lease expired for %q", name)
			entry.PublicAddr = ""
		}
	}
}

func (r *Registry) GetUserAddr(username string) (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	entry, ok := r.users[username]
	if !ok || entry.PublicAddr == "" {
		return "", fmt.Errorf("offline")
	}
	return entry.PublicAddr, nil
}

func (r *Registry) GetUser(username string) (UserEntry, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	entry, ok := r.users[username]
	if !ok || entry.PublicAddr == "" {
		return UserEntry{}, fmt.Errorf("offline")
	}
	return *entry, nil
}

func (r *Registry) ListOnline(exclude string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	items := make([]string, 0, len(r.users))
	for name, entry := range r.users {
		if name == exclude || entry.PublicAddr == "" {
			continue
		}
		items = append(items, name+"="+entry.PublicAddr)
	}
	sort.Strings(items)
	return strings.Join(items, ",")
}

func (r *Registry) loadUsersFromDisk() error {
	f, err := os.Open(r.usersDB)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) != 3 {
			log.Printf("skipping malformed user record")
			continue
		}
		r.users[parts[0]] = &UserEntry{Username: parts[0], Salt: parts[1], PasswordHash: parts[2]}
	}
	return scanner.Err()
}

func (r *Registry) saveUsersToDiskLocked() error {
	if err := os.MkdirAll(filepath.Dir(r.usersDB), 0700); err != nil && filepath.Dir(r.usersDB) != "." {
		return err
	}
	f, err := os.OpenFile(r.usersDB, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	names := make([]string, 0, len(r.users))
	for name := range r.users {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		entry := r.users[name]
		if _, err := fmt.Fprintf(w, "%s:%s:%s\n", entry.Username, entry.Salt, entry.PasswordHash); err != nil {
			return err
		}
	}
	return w.Flush()
}
