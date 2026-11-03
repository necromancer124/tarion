package storage

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/necromancer124/tarion/internal/vault"
)

// writeSampleData fills a data folder the way a client would.
func writeSampleData(t *testing.T) string {
	t.Helper()
	id, err := LoadOrCreateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if err := PinOutgoing("bob", "BOBKEY", "203.0.113.7:63426"); err != nil {
		t.Fatal(err)
	}
	if err := Enqueue(OutboxItem{ID: "m1", To: "bob", Body: "queued secret", Created: time.Now()}); err != nil {
		t.Fatal(err)
	}
	for _, l := range []string{"Me: history secret", "  … queued: offline; will retry", "bob: שלום"} {
		if err := AppendHistory("bob", l); err != nil {
			t.Fatal(err)
		}
	}
	if err := LogDropped(DroppedMessage{Dir: "out", Peer: "bob", Reason: "gave up", Body: "dropped secret"}); err != nil {
		t.Fatal(err)
	}
	return id.ID
}

// leaks reports files in the data folder that contain plaintext secrets.
func leaks(t *testing.T) []string {
	t.Helper()
	var bad []string
	_ = filepath.Walk(GetBaseConfigDir(), func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		data, _ := os.ReadFile(path)
		for _, secret := range []string{"secret", "BOBKEY", "PRIVATE KEY", "שלום"} {
			if strings.Contains(string(data), secret) {
				bad = append(bad, filepath.Base(path)+": "+secret)
			}
		}
		return nil
	})
	return bad
}

// checkSampleData reads everything back through the normal functions.
func checkSampleData(t *testing.T, wantID string) {
	t.Helper()
	id, err := LoadOrCreateIdentity()
	if err != nil || id.ID != wantID {
		t.Fatalf("identity: %v (changed: %v)", err, id != nil && id.ID != wantID)
	}
	if p, ok := PeerByName("bob"); !ok || p.ID != "BOBKEY" {
		t.Fatalf("peers: %+v", p)
	}
	if items, err := Outbox(); err != nil || len(items) != 1 || items[0].Body != "queued secret" {
		t.Fatalf("outbox: %+v %v", items, err)
	}
	h, err := ReadHistory("bob")
	if err != nil || len(h) < 3 || h[0] != "Me: history secret" || h[1] != "  … queued: offline; will retry" || h[2] != "bob: שלום" {
		t.Fatalf("history: %q %v", h, err)
	}
	if d, err := ReadDropped(0); err != nil || len(d) != 1 || d[0].Body != "dropped secret" {
		t.Fatalf("dropped: %+v %v", d, err)
	}
}

func TestEncryptExistingDataAndBack(t *testing.T) {
	t.Setenv("TARION_HOME", t.TempDir())
	t.Cleanup(func() { SetDataKey(nil) })
	SetDataKey(nil)
	id := writeSampleData(t)
	if len(leaks(t)) == 0 {
		t.Fatal("test setup: plain data should be readable on disk")
	}

	// Turn encryption on: old plain files are converted.
	key := vault.NewKey()
	SetDataKey(key)
	if !NeedsSealing() {
		t.Fatal("plain files not noticed")
	}
	if err := Reseal(nil); err != nil {
		t.Fatal(err)
	}
	if bad := leaks(t); len(bad) > 0 {
		t.Fatalf("plaintext left on disk: %v", bad)
	}
	if NeedsSealing() {
		t.Fatal("still reported as needing encryption")
	}
	checkSampleData(t, id)

	// New writes are encrypted too.
	if err := AppendHistory("bob", "Me: another secret"); err != nil {
		t.Fatal(err)
	}
	if bad := leaks(t); len(bad) > 0 {
		t.Fatalf("new line written in plain text: %v", bad)
	}

	// Locked: a clear error, never garbage or a new identity.
	SetDataKey(nil)
	if _, err := LoadOrCreateIdentity(); !errors.Is(err, ErrLocked) {
		t.Fatalf("locked identity: %v", err)
	}
	if _, err := ReadHistory("bob"); !errors.Is(err, ErrLocked) {
		t.Fatalf("locked history: %v", err)
	}
	if _, err := Outbox(); !errors.Is(err, ErrLocked) {
		t.Fatalf("locked outbox: %v", err)
	}

	// The wrong key can't read anything.
	SetDataKey(vault.NewKey())
	if _, err := LoadOrCreateIdentity(); err == nil {
		t.Fatal("identity opened with the wrong key")
	}
	if h, _ := ReadHistory("bob"); len(h) == 0 || !strings.Contains(h[0], "can't be read") {
		t.Fatalf("history with the wrong key: %q", h)
	}

	// Turn encryption off again: everything back in plain text, intact.
	SetDataKey(nil)
	if err := Reseal(key); err != nil {
		t.Fatal(err)
	}
	if len(leaks(t)) == 0 {
		t.Fatal("decrypting left the files encrypted")
	}
	checkSampleData(t, id)
}

func TestNewInstallWithKeyIsEncryptedFromTheStart(t *testing.T) {
	t.Setenv("TARION_HOME", t.TempDir())
	t.Cleanup(func() { SetDataKey(nil) })
	SetDataKey(vault.NewKey())
	id := writeSampleData(t)
	if bad := leaks(t); len(bad) > 0 {
		t.Fatalf("plaintext on disk: %v", bad)
	}
	checkSampleData(t, id)
}
