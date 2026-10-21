package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func legacyLine(name, salt, pass string) string {
	sum := sha256.Sum256([]byte(salt + ":" + pass))
	return name + ":" + salt + ":" + hex.EncodeToString(sum[:]) + "\n"
}

func TestCreateLoginAndKeyLogin(t *testing.T) {
	dir := t.TempDir()
	a, err := LoadAccounts(filepath.Join(dir, "users.json"), "")
	if err != nil {
		t.Fatal(err)
	}
	a.SetArgon(testArgon)
	if _, err := a.Create("Alice", "secret1", "key1"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Create("alice", "other12", "key2"); !errors.Is(err, errNameTaken) {
		t.Fatalf("case-insensitive duplicate allowed: %v", err)
	}
	if _, _, err := a.LoginWithPassword("alice", "wrong!!", "key1"); !errors.Is(err, errAuthFailed) {
		t.Fatalf("wrong password: %v", err)
	}
	if name, err := a.LoginWithKey("ALICE", "key1"); err != nil || name != "Alice" {
		t.Fatalf("key login: %q %v", name, err)
	}
	if _, err := a.LoginWithKey("alice", "key2"); !errors.Is(err, errPasswordRequired) {
		t.Fatalf("other key should need the password: %v", err)
	}
	// Password login from a new device rebinds the key.
	if _, changed, err := a.LoginWithPassword("alice", "secret1", "key2"); err != nil || !changed {
		t.Fatalf("rebind: changed=%v err=%v", changed, err)
	}
	if _, err := a.LoginWithKey("alice", "key1"); !errors.Is(err, errPasswordRequired) {
		t.Fatal("old key still accepted after rebind")
	}

	data, _ := os.ReadFile(filepath.Join(dir, "users.json"))
	if strings.Contains(string(data), "secret1") || !strings.Contains(string(data), "argon2id$") {
		t.Fatalf("users.json should hold argon2id hashes only:\n%s", data)
	}
	// Survives a reload.
	b, err := LoadAccounts(filepath.Join(dir, "users.json"), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.LoginWithKey("alice", "key2"); err != nil {
		t.Fatalf("after reload: %v", err)
	}
}

func TestLegacyImportDropsInjectedDuplicatesAndUpgrades(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, "users.db")
	// What the old server wrote after "zzz\nbob:X:<hash>\nq" registered:
	// a second "bob" record that would have won on reload.
	content := legacyLine("alice", "s1", "alicepw") +
		legacyLine("bob", "s2", "bobpw") +
		"zzz\n" +
		legacyLine("bob", "X", "evilpw") +
		legacyLine("q", "s3", "whatever") +
		"bad:name:with:colons\n"
	if err := os.WriteFile(legacy, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	a, err := LoadAccounts(filepath.Join(dir, "users.json"), legacy)
	if err != nil {
		t.Fatal(err)
	}
	a.SetArgon(testArgon)
	if _, _, err := a.LoginWithPassword("bob", "evilpw", "k"); !errors.Is(err, errNoSuchUser) {
		t.Fatalf("injected bob must be dropped, got %v", err)
	}
	if _, _, err := a.LoginWithPassword("bob", "bobpw", "k"); !errors.Is(err, errNoSuchUser) {
		t.Fatalf("ambiguous bob must be dropped entirely, got %v", err)
	}
	if _, _, err := a.LoginWithPassword("alice", "alicepw", "alicekey"); err != nil {
		t.Fatalf("legacy alice: %v", err)
	}
	u, _ := a.get("alice")
	if !strings.HasPrefix(u.Hash, "argon2id$") || u.PeerID != "alicekey" {
		t.Fatalf("legacy hash not upgraded / key not bound: %+v", u)
	}
}

func TestVerifyPasswordRejectsGarbage(t *testing.T) {
	for _, stored := range []string{"", "argon2id$x", "sha256$a", "md5$a$b"} {
		if ok, _ := verifyPassword(stored, "pw", DefaultArgon); ok {
			t.Fatalf("garbage hash %q accepted", stored)
		}
	}
}

func TestLimiter(t *testing.T) {
	l := newLimiter(time.Hour, 2)
	if !l.Allow("a") || !l.Allow("a") {
		t.Fatal("burst should allow 2")
	}
	if l.Allow("a") {
		t.Fatal("third request should be limited")
	}
	if !l.Allow("b") {
		t.Fatal("keys are independent")
	}
	fast := newLimiter(time.Millisecond, 1)
	fast.Allow("x")
	time.Sleep(5 * time.Millisecond)
	if !fast.Allow("x") {
		t.Fatal("tokens should refill")
	}
	fast.sweep()
	if len(fast.buckets) != 0 && fast.buckets["x"].tokens >= 1 {
		t.Fatal("sweep should drop full buckets")
	}
}

func TestHashUpgradesWhenCostChanges(t *testing.T) {
	a, err := LoadAccounts(filepath.Join(t.TempDir(), "users.json"), "")
	if err != nil {
		t.Fatal(err)
	}
	a.SetArgon(testArgon)
	if _, err := a.Create("alice", "correct-horse-1", "k"); err != nil {
		t.Fatal(err)
	}
	stronger := argonParams{MemoryKiB: 2048, Time: 2, Threads: 1}
	a.SetArgon(stronger)
	if _, _, err := a.LoginWithPassword("alice", "correct-horse-1", "k"); err != nil {
		t.Fatal(err)
	}
	u, _ := a.get("alice")
	if !strings.HasPrefix(u.Hash, "argon2id$2048$2$1$") {
		t.Fatalf("hash not upgraded to new cost: %s", u.Hash)
	}
	if ok, upgrade := verifyPassword(u.Hash, "correct-horse-1", stronger); !ok || upgrade {
		t.Fatalf("upgraded hash: ok=%v upgrade=%v", ok, upgrade)
	}
}

func TestPasswordProblem(t *testing.T) {
	for _, tc := range []struct {
		user, pass string
		bad        bool
	}{
		{"alice", "correct-horse-1", false},
		{"alice", "short", true},
		{"alice", "ALICE-rocks-99", true},
		{"alice", "aaaaaaaaaaaa", true},
		{"alice", "שששששששששששש", true},
		{"alice", "", true},
		{"al", "al-is-fine-123", false},
	} {
		if got := passwordProblem(tc.user, tc.pass, 10); (got != "") != tc.bad {
			t.Errorf("%q/%q: %q", tc.user, tc.pass, got)
		}
	}
}
