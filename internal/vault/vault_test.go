package vault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSealOpen(t *testing.T) {
	key := NewKey()
	sealed := Seal(key, "history", []byte("alice: שלום"))
	if !IsSealed(sealed) || bytes.Contains(sealed, []byte("alice")) {
		t.Fatal("sealed data leaks the plaintext")
	}
	plain, err := Open(key, "history", sealed)
	if err != nil || string(plain) != "alice: שלום" {
		t.Fatalf("round trip: %q %v", plain, err)
	}
	if _, err := Open(NewKey(), "history", sealed); !errors.Is(err, ErrDamaged) {
		t.Fatal("opened with another key")
	}
	if _, err := Open(key, "peers", sealed); !errors.Is(err, ErrDamaged) {
		t.Fatal("a history file was accepted as another kind")
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := Open(key, "history", sealed); !errors.Is(err, ErrDamaged) {
		t.Fatal("a damaged file was accepted")
	}
}

func TestSealLine(t *testing.T) {
	key := NewKey()
	line := SealLine(key, "dropped", `{"body":"secret"}`)
	if !IsSealedLine(line) || strings.ContainsAny(line, "\n\r") || strings.Contains(line, "secret") {
		t.Fatalf("bad sealed line: %q", line)
	}
	if got, err := OpenLine(key, "dropped", line); err != nil || got != `{"body":"secret"}` {
		t.Fatalf("round trip: %q %v", got, err)
	}
	if _, err := OpenLine(key, "history", line); err == nil {
		t.Fatal("a line was accepted as another kind")
	}
}

func TestPassphraseVault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.json")
	if f, err := Load(path); f != nil || err != nil {
		t.Fatalf("missing vault: %v %v", f, err)
	}
	key := NewKey()
	if err := Wrap(path, key, Passphrase, "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if bytes.Contains(data, key) {
		t.Fatal("vault.json holds the raw key")
	}
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.Unlock(func() (string, error) { return "correct horse battery", nil })
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("unlock: %v", err)
	}
	if _, err := f.Unlock(func() (string, error) { return "wrong", nil }); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
}

func TestWindowsVault(t *testing.T) {
	if !WindowsAvailable {
		t.Skip("Windows only")
	}
	path := filepath.Join(t.TempDir(), "vault.json")
	key := NewKey()
	if err := Wrap(path, key, Windows, ""); err != nil {
		t.Fatal(err)
	}
	f, _ := Load(path)
	got, err := f.Unlock(nil)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("unlock: %v", err)
	}
	f.Wrapped[len(f.Wrapped)-1] ^= 1
	if _, err := f.Unlock(nil); err == nil {
		t.Fatal("a damaged Windows-protected key was accepted")
	}
}
