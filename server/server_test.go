package main

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/necromancer124/tarion/internal/directory"
	"github.com/necromancer124/tarion/internal/identity"
	"github.com/necromancer124/tarion/internal/network"
	"github.com/quic-go/quic-go"
)

func freePort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// testArgon keeps tests fast; production defaults are much heavier.
var testArgon = argonParams{MemoryKiB: 1024, Time: 1, Threads: 1}

func startServer(t *testing.T) (string, *identity.Identity) {
	t.Helper()
	return startServerWith(t, DefaultOptions())
}

func startServerWith(t *testing.T, opts Options) (string, *identity.Identity) {
	t.Helper()
	id, _ := identity.Generate()
	accounts, err := LoadAccounts(filepath.Join(t.TempDir(), "users.json"), "")
	if err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	udp, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
	if err != nil {
		t.Fatal(err)
	}
	tr := &quic.Transport{Conn: udp}
	accounts.SetArgon(testArgon)
	srv := NewServer(id, accounts, opts)
	ln, err := tr.Listen(srv.TLSConfig(), QUICConfig())
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { ln.Close(); tr.Close(); udp.Close() })
	return fmt.Sprintf("127.0.0.1:%d", port), id
}

type testClient struct {
	nm     *network.NetworkManager
	dir    *directory.Client
	cancel context.CancelFunc

	mu       sync.Mutex
	punches  []directory.Push
	loggedIn []bool
	serverID string
}

func startClient(t *testing.T, server, user, pass, serverID string, id *identity.Identity) *testClient {
	t.Helper()
	return startClientInvite(t, server, user, pass, serverID, "", id)
}

func startClientInvite(t *testing.T, server, user, pass, serverID, invite string, id *identity.Identity) *testClient {
	t.Helper()
	if id == nil {
		id, _ = identity.Generate()
	}
	nm := network.NewNetworkManager(freePort(t), id)
	if err := nm.StartListener(); err != nil {
		t.Fatal(err)
	}
	tc := &testClient{nm: nm}
	tc.dir = directory.NewClient(nm, directory.ClientConfig{
		Server: server, User: user, Pass: pass, ServerID: serverID, Invite: invite,
		OnServerID: func(id string) { tc.mu.Lock(); tc.serverID = id; tc.mu.Unlock() },
		OnLoggedIn: func(used bool) { tc.mu.Lock(); tc.loggedIn = append(tc.loggedIn, used); tc.mu.Unlock() },
		OnPunch:    func(p directory.Push) { tc.mu.Lock(); tc.punches = append(tc.punches, p); tc.mu.Unlock() },
	})
	ctx, cancel := context.WithCancel(context.Background())
	tc.cancel = cancel
	go tc.dir.Run(ctx)
	t.Cleanup(func() { cancel(); nm.Close() })
	return tc
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestDirectoryEndToEnd(t *testing.T) {
	server, serverID := startServer(t)
	alice := startClient(t, server, "alice", "correct-horse-1", "", nil)
	bob := startClient(t, server, "bob", "battery-staple-2", "", nil)
	waitFor(t, "alice online", alice.dir.Connected)
	waitFor(t, "bob online", bob.dir.Connected)

	// Server key was pinned on first use, and the password is no longer needed.
	alice.mu.Lock()
	if alice.serverID != serverID.ID || len(alice.loggedIn) != 1 || !alice.loggedIn[0] {
		t.Fatalf("pin/login callbacks: id=%q logins=%v", alice.serverID, alice.loggedIn)
	}
	alice.mu.Unlock()
	if !strings.Contains(alice.dir.Status(), "connected as alice") {
		t.Fatalf("status: %s", alice.dir.Status())
	}

	users, err := alice.dir.List()
	if err != nil || len(users) != 1 || users[0] != "bob" {
		t.Fatalf("list: %v %v", users, err)
	}

	// Lookup returns bob's chat socket (the server saw his login from it)
	// and his key, and makes bob punch toward alice's chat socket.
	resp, err := alice.dir.Lookup("BOB")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Addr != fmt.Sprintf("127.0.0.1:%d", bob.nm.Port) || resp.PeerID != bob.nm.ID() || resp.User != "bob" {
		t.Fatalf("lookup: %+v (bob chat port %d)", resp, bob.nm.Port)
	}
	waitFor(t, "punch at bob", func() bool { bob.mu.Lock(); defer bob.mu.Unlock(); return len(bob.punches) == 1 })
	bob.mu.Lock()
	p := bob.punches[0]
	bob.mu.Unlock()
	if p.From != "alice" || p.PeerID != alice.nm.ID() || p.Addr != fmt.Sprintf("127.0.0.1:%d", alice.nm.Port) {
		t.Fatalf("punch: %+v", p)
	}
	// Same public IP (both on 127.0.0.1): bob is also told alice's LAN
	// address, which is the one alice dials first.
	if fmt.Sprint(p.LocalAddrs) != fmt.Sprint(alice.nm.LocalAddrs()) {
		t.Fatalf("punch LAN addrs %v, want %v", p.LocalAddrs, alice.nm.LocalAddrs())
	}

	// The address really is bob's chat listener: a message gets through,
	// verified against the key the directory reported.
	if _, err := alice.nm.Send(resp.Addr, "alice", "hi via directory", func(id string) error {
		if id != resp.PeerID {
			return fmt.Errorf("key mismatch")
		}
		return nil
	}); err != nil {
		t.Fatalf("send: %v", err)
	}
	select {
	case m := <-bob.nm.MessageChan:
		if m.Body != "hi via directory" || m.PeerID != alice.nm.ID() {
			t.Fatalf("got %+v", m)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("bob got nothing")
	}

	if _, err := alice.dir.Lookup("carol"); err != directory.ErrUserOffline {
		t.Fatalf("offline lookup: %v", err)
	}
}

func TestKeyLoginWithoutPassword(t *testing.T) {
	server, _ := startServer(t)
	id, _ := identity.Generate()
	first := startClient(t, server, "alice", "correct-horse-1", "", id)
	waitFor(t, "first login", first.dir.Connected)
	first.cancel()
	first.nm.Close()

	// Same device key, no password: logs in.
	again := startClient(t, server, "alice", "", "", id)
	waitFor(t, "key login", again.dir.Connected)

	// A different device without the password is refused.
	other := startClient(t, server, "alice", "", "", nil)
	waitFor(t, "refusal", func() bool { return strings.Contains(other.dir.Status(), "not linked") })
}

func TestWrongPasswordAndBadNames(t *testing.T) {
	server, _ := startServer(t)
	owner := startClient(t, server, "alice", "correct-horse-1", "", nil)
	waitFor(t, "owner", owner.dir.Connected)

	thief := startClient(t, server, "alice", "guess123", "", nil)
	waitFor(t, "wrong password", func() bool { return strings.Contains(thief.dir.Status(), "wrong password") })

	injected := startClient(t, server, "zzz\nbob:X:abc\nq", "whatever", "", nil)
	waitFor(t, "invalid name", func() bool { return strings.Contains(injected.dir.Status(), "invalid username") })

	short := startClient(t, server, "carol", "123", "", nil)
	waitFor(t, "weak password", func() bool { return strings.Contains(short.dir.Status(), "at least 10 characters") })

	named := startClient(t, server, "dave", "dave-is-great", "", nil)
	waitFor(t, "password with username", func() bool { return strings.Contains(named.dir.Status(), "must not contain your username") })
}

func TestServerKeyPinMismatch(t *testing.T) {
	server, _ := startServer(t)
	other, _ := identity.Generate()
	c := startClient(t, server, "alice", "correct-horse-1", other.ID, nil)
	waitFor(t, "pin mismatch", func() bool { return strings.Contains(c.dir.Status(), "server key changed") })
	if c.dir.Connected() {
		t.Fatal("must not connect to a server with the wrong key")
	}
}

func TestSecondLoginReplacesFirst(t *testing.T) {
	server, _ := startServer(t)
	id, _ := identity.Generate()
	a := startClient(t, server, "alice", "correct-horse-1", "", id)
	waitFor(t, "first", a.dir.Connected)
	b := startClient(t, server, "alice", "", "", id)
	waitFor(t, "second", b.dir.Connected)
	waitFor(t, "first closed", func() bool { return strings.Contains(a.dir.Status(), "another device") })
}
