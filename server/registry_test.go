package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestRegistry(t *testing.T, ttl time.Duration) *Registry {
	t.Helper()
	r, err := NewRegistry(filepath.Join(t.TempDir(), "users.db"), ttl)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return r
}

func TestRegistryAuthenticatesAndUpdatesAddress(t *testing.T) {
	r := newTestRegistry(t, time.Minute)
	if err := r.RegisterOrUpdate("alice", "secret", "203.0.113.10:63425"); err != nil {
		t.Fatalf("register alice: %v", err)
	}
	entry, err := r.GetUser("alice")
	if err != nil {
		t.Fatalf("get alice: %v", err)
	}
	if entry.PublicAddr != "203.0.113.10:63425" {
		t.Fatalf("addr=%q", entry.PublicAddr)
	}
	if entry.PasswordHash == "secret" || entry.PasswordHash == "" || entry.Salt == "" {
		t.Fatalf("password was not stored as salted hash: salt=%q hash=%q", entry.Salt, entry.PasswordHash)
	}
	if err := r.RegisterOrUpdate("alice", "bad", "203.0.113.99:63425"); err == nil {
		t.Fatal("wrong password unexpectedly accepted")
	}
	addr, err := r.GetUserAddr("alice")
	if err != nil {
		t.Fatalf("get addr after failed auth: %v", err)
	}
	if addr != "203.0.113.10:63425" {
		t.Fatalf("bad password changed address to %q", addr)
	}
	if err := r.RegisterOrUpdate("alice", "secret", "203.0.113.11:63425"); err != nil {
		t.Fatalf("update address: %v", err)
	}
	addr, _ = r.GetUserAddr("alice")
	if addr != "203.0.113.11:63425" {
		t.Fatalf("updated addr=%q", addr)
	}
}

func TestRegistryPersistsHashesOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users.db")
	r, err := NewRegistry(path, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.RegisterOrUpdate("alice", "secret", "203.0.113.10:63425"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, "secret") {
		t.Fatalf("users db leaked plaintext password: %q", text)
	}
	parts := strings.Split(strings.TrimSpace(text), ":")
	if len(parts) != 3 || parts[0] != "alice" || parts[1] == "" || len(parts[2]) != 64 {
		t.Fatalf("bad users db record: %q", text)
	}
}

func TestRegistryReapsOnlyOnlineLease(t *testing.T) {
	r := newTestRegistry(t, time.Nanosecond)
	if err := r.RegisterOrUpdate("alice", "secret", "203.0.113.10:63425"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond)
	r.ReapStaleUsers()
	if _, err := r.GetUserAddr("alice"); err == nil {
		t.Fatal("stale user still online")
	}
	if err := r.RegisterOrUpdate("alice", "secret", "203.0.113.11:63425"); err != nil {
		t.Fatalf("stale user could not re-auth/update: %v", err)
	}
}
