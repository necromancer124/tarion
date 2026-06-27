package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// UserEntry holds the network and auth state of a connected client
type UserEntry struct {
	Username     string
	PublicAddr   string
	PasswordHash string
	LastSeen     time.Time
}

// Registry is the central CAM-table for Tarion
type Registry struct {
	mu    sync.RWMutex
	users map[string]*UserEntry
}

func NewRegistry() *Registry {
	return &Registry{
		users: make(map[string]*UserEntry),
	}
}

// HashPassword creates a simple SHA-256 hash of the password
func HashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

// RegisterOrUpdate handles the first-time connection and subsequent heartbeats
func (r *Registry) RegisterOrUpdate(username, password, addr string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	pwdHash := HashPassword(password)
	existing, exists := r.users[username]

	if !exists {
		log.Printf("[NEW USER] Registering %s from %s", username, addr)
		r.users[username] = &UserEntry{
			Username:     username,
			PublicAddr:   addr,
			PasswordHash: pwdHash,
			LastSeen:     time.Now(),
		}
		return r.saveUserToDisk(username, pwdHash)
	}

	// Authenticate existing user
	if existing.PasswordHash != pwdHash {
		return fmt.Errorf("authentication failed for user %s", username)
	}

	// Update address and timestamp
	existing.PublicAddr = addr
	existing.LastSeen = time.Now()
	return nil
}

// saveUserToDisk persists the username and hash to a flat file for authentication on restart
func (r *Registry) saveUserToDisk(username, hash string) error {
	filename := "users.db"
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(fmt.Sprintf("%s:%s\n", username, hash))
	return err
}

// ReapStaleUsers removes users who haven't sent a heartbeat in 60 seconds
func (r *Registry) ReapStaleUsers() {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	for name, entry := range r.users {
		if now.Sub(entry.LastSeen) > 60*time.Second {
			log.Printf("[SCAVENGER] Purging stale user: %s", name)
			delete(r.users, name)
		}
	}
}

// GetUserAddr retrieves the IP:Port for a target user (The Signaling part)
func (r *Registry) GetUserAddr(username string) (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	entry, exists := r.users[username]
	if !exists {
		return "", fmt.Errorf("user %s is currently offline", username)
	}
	return entry.PublicAddr, nil
}
