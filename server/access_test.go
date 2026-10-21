package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/necromancer124/tarion/internal/identity"
)

func TestInviteOnlyRegistration(t *testing.T) {
	inv := invites{dir: filepath.Join(t.TempDir(), "invites")}
	opts := DefaultOptions()
	opts.Registration, opts.InvitesDir = RegInvite, inv.dir
	server, _ := startServerWith(t, opts)

	none := startClient(t, server, "alice", "correct-horse-1", "", nil)
	waitFor(t, "invite required", func() bool { return strings.Contains(none.dir.Status(), "invite-only") })

	wrong := startClientInvite(t, server, "alice", "correct-horse-1", "", "AAAA-BBBB-CCCC-DDDD", nil)
	waitFor(t, "bad invite", func() bool { return strings.Contains(wrong.dir.Status(), "wrong or already used") })

	codes, err := inv.Create(1)
	if err != nil {
		t.Fatal(err)
	}
	// Codes are accepted in any case, with or without dashes.
	ok := startClientInvite(t, server, "alice", "correct-horse-1", "", strings.ToLower(codes[0]), nil)
	waitFor(t, "registered with invite", ok.dir.Connected)

	reuse := startClientInvite(t, server, "bob", "battery-staple-2", "", codes[0], nil)
	waitFor(t, "used invite refused", func() bool { return strings.Contains(reuse.dir.Status(), "wrong or already used") })
}

func TestClosedRegistration(t *testing.T) {
	opts := DefaultOptions()
	opts.Registration = RegClosed
	server, _ := startServerWith(t, opts)
	c := startClient(t, server, "alice", "correct-horse-1", "", nil)
	waitFor(t, "closed", func() bool { return strings.Contains(c.dir.Status(), "not accepting new accounts") })
}

func TestBanDisconnectsAndBlocks(t *testing.T) {
	bans := filepath.Join(t.TempDir(), "bans.txt")
	opts := DefaultOptions()
	opts.BansPath = bans
	server, _ := startServerWith(t, opts)

	alice := startClient(t, server, "alice", "correct-horse-1", "", nil)
	bob := startClient(t, server, "bob", "battery-staple-2", "", nil)
	waitFor(t, "alice", alice.dir.Connected)
	waitFor(t, "bob", bob.dir.Connected)

	if changed, err := editBans(bans, "BOB", true); err != nil || !changed {
		t.Fatalf("ban: %v %v", changed, err)
	}
	waitFor(t, "bob kicked", func() bool { return strings.Contains(bob.dir.Status(), "banned") })
	waitFor(t, "bob gone from list", func() bool {
		users, err := alice.dir.List()
		return err == nil && len(users) == 0
	})

	// Banning a key blocks that device under any name.
	carolID, _ := identity.Generate()
	if _, err := editBans(bans, identity.Fingerprint(carolID.ID), true); err != nil {
		t.Fatal(err)
	}
	carol := startClient(t, server, "carol", "carol-secret-3", "", carolID)
	waitFor(t, "carol refused", func() bool { return strings.Contains(carol.dir.Status(), "banned") })

	// Unban works too.
	if changed, err := editBans(bans, "bob", false); err != nil || !changed {
		t.Fatalf("unban: %v %v", changed, err)
	}
	data, _ := os.ReadFile(bans)
	if strings.Contains(strings.ToLower(string(data)), "bob") {
		t.Fatalf("bob still in ban file:\n%s", data)
	}
}

func TestInviteCodesAreSafe(t *testing.T) {
	inv := invites{dir: filepath.Join(t.TempDir(), "invites")}
	for _, bad := range []string{"", "../../etc/passwd", "AAAA-BBBB-CCCC-DDD1", "AAAA-BBBB-CCCC-DDDDE"} {
		if inv.Consume(bad) {
			t.Fatalf("consumed %q", bad)
		}
	}
	codes, _ := inv.Create(2)
	if len(codes) != 2 || codes[0] == codes[1] {
		t.Fatalf("codes: %v", codes)
	}
	if !inv.Consume(codes[0]) || inv.Consume(codes[0]) {
		t.Fatal("a code must work exactly once")
	}
}

func TestParseInterspersed(t *testing.T) {
	for _, args := range [][]string{
		{"bob", "-data", "/srv"},
		{"-data", "/srv", "bob"},
	} {
		fs := flag.NewFlagSet("ban", flag.ContinueOnError)
		data := fs.String("data", ".", "")
		rest := parseInterspersed(fs, args)
		if len(rest) != 1 || rest[0] != "bob" || *data != "/srv" {
			t.Fatalf("%v -> rest=%v data=%q", args, rest, *data)
		}
	}
}
