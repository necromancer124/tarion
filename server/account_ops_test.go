package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestChangePassword(t *testing.T) {
	server, _ := startServer(t)
	alice := startClient(t, server, "alice", "correct-horse-1", "", nil)
	waitFor(t, "alice", alice.dir.Connected)

	if err := alice.dir.ChangePassword("not-my-password", "violet-moon-88"); err == nil || !strings.Contains(err.Error(), "wrong password") {
		t.Fatalf("wrong current password: %v", err)
	}
	if err := alice.dir.ChangePassword("correct-horse-1", "short"); err == nil || !strings.Contains(err.Error(), "at least") {
		t.Fatalf("weak new password: %v", err)
	}
	if err := alice.dir.ChangePassword("correct-horse-1", "violet-moon-88"); err != nil {
		t.Fatal(err)
	}
	// A new device must now use the new password.
	old := startClient(t, server, "alice", "correct-horse-1", "", nil)
	waitFor(t, "old password refused", func() bool { return strings.Contains(old.dir.Status(), "wrong password") })
	fresh := startClient(t, server, "alice", "violet-moon-88", "", nil)
	waitFor(t, "new password works", fresh.dir.Connected)
}

func TestDeleteOwnAccount(t *testing.T) {
	server, _ := startServer(t)
	alice := startClient(t, server, "alice", "correct-horse-1", "", nil)
	waitFor(t, "alice", alice.dir.Connected)

	if err := alice.dir.DeleteAccount("nope-nope-nope"); err == nil {
		t.Fatal("deleted with the wrong password")
	}
	if err := alice.dir.DeleteAccount("correct-horse-1"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "session closed", func() bool { return strings.Contains(alice.dir.Status(), "deleted") })

	// The name is free again.
	other := startClient(t, server, "alice", "brand-new-owner-2", "", nil)
	waitFor(t, "name reused", other.dir.Connected)
}

func TestOperatorDeletesAccount(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "deletions")
	opts := DefaultOptions()
	opts.DeletionsDir = dir
	server, _ := startServerWith(t, opts)
	bob := startClient(t, server, "bob", "battery-staple-2", "", nil)
	waitFor(t, "bob", bob.dir.Connected)

	if err := (deletions{dir: dir}).Request("BOB"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "bob disconnected", func() bool { return strings.Contains(bob.dir.Status(), "deleted") })
	waitFor(t, "request consumed", func() bool { return len((deletions{dir: dir}).Pending()) == 0 })
}
