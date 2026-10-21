package main

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/necromancer124/tarion/internal/identity"
	"github.com/necromancer124/tarion/internal/storage"
)

func freePort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// startTestNode runs a node with no directory server.
func startTestNode(t *testing.T, cfg *storage.Config) (*node, string) {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Port = freePort(t)
	n, err := startNode(cfg, id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(n.close)
	return n, fmt.Sprintf("127.0.0.1:%d", cfg.Port)
}

func TestChatInputHandlesUnicode(t *testing.T) {
	var m tea.Model = model{state: StateChatView}
	m, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("שלום")})
	m, _ = m.Update(tea.KeyMsg{Type: tea.KeySpace})
	m, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("👋")})
	m, _ = m.Update(tea.KeyMsg{Type: tea.KeyBackspace})
	if got := m.(model).inputBuffer; got != "שלום " {
		t.Fatalf("input buffer = %q", got)
	}
}

func TestControlSocketRequiresToken(t *testing.T) {
	t.Setenv("TARION_HOME", t.TempDir())
	cfg := &storage.Config{ControlPort: freeTCPPort(t)}
	n, _ := startTestNode(t, cfg)

	if backgroundRunning(cfg) {
		t.Fatal("no token file yet, should not count as running")
	}
	token, _ := newControlToken()
	if err := serveBackgroundControl(token, n); err != nil {
		t.Fatal(err)
	}
	if err := saveControlToken("not-the-token"); err != nil {
		t.Fatal(err)
	}
	if err := backgroundRequest(cfg, controlRequest{Cmd: "ping"}); err == nil || !strings.Contains(err.Error(), "bad control token") {
		t.Fatalf("wrong token accepted: %v", err)
	}
	if err := saveControlToken(token); err != nil {
		t.Fatal(err)
	}
	if err := backgroundRequest(cfg, controlRequest{Cmd: "ping"}); err != nil {
		t.Fatalf("right token rejected: %v", err)
	}
	resp, err := backgroundCall(cfg, controlRequest{Cmd: "online"})
	if err != nil || !strings.Contains(resp.Status, "no server configured") {
		t.Fatalf("online without server: %+v %v", resp, err)
	}
}

func TestControlPortDefaultsAndOverride(t *testing.T) {
	if got := controlPort(&storage.Config{Port: 63426}); got != 53426 {
		t.Fatalf("63426 -> %d, want 53426 (63426+10000 is out of range)", got)
	}
	if got := controlPort(&storage.Config{Port: 40000}); got != 50000 {
		t.Fatalf("40000 -> %d", got)
	}
	if got := controlPort(&storage.Config{Port: 40000, ControlPort: 41000}); got != 41000 {
		t.Fatalf("override ignored: %d", got)
	}
}

func TestClientFlagsValidate(t *testing.T) {
	for _, tc := range []struct {
		user, server string
		ok           bool
	}{
		{"alice", "127.0.0.1:63425", true},
		{"שלום", "example.com:63425", true},
		{"a|b", "127.0.0.1:63425", false},
		{"zzz\nbob", "127.0.0.1:63425", false},
		{"alice", "no-port", false},
	} {
		user, server, pass := tc.user, tc.server, ""
		port, ctrl := 0, 0
		f := clientFlags{port: &port, ctrl: &ctrl, server: &server, user: &user, pass: &pass}
		cfg := storage.DefaultConfig()
		err := f.apply(cfg)
		if (err == nil) != tc.ok {
			t.Fatalf("user=%q server=%q: err=%v", tc.user, tc.server, err)
		}
		if tc.ok && cfg.Port != storage.DefaultPort {
			t.Fatalf("default port %d", cfg.Port)
		}
	}
}

func TestDeliverPinsContactAndRefusesImpostor(t *testing.T) {
	t.Setenv("TARION_HOME", t.TempDir())
	alice, _ := startTestNode(t, &storage.Config{Username: "alice"})
	bob, bobAddr := startTestNode(t, &storage.Config{Username: "bob"})
	_, malloryAddr := startTestNode(t, &storage.Config{Username: "mallory"})

	if err := alice.deliver("bob", bobAddr, "hi bob\x1b[2J"); err != nil {
		t.Fatalf("first delivery: %v", err)
	}
	select {
	case msg := <-bob.nm.MessageChan:
		chat, line := recordIncoming(msg)
		if chat != "alice" || line != "alice: hi bob[2J" {
			t.Fatalf("recorded as %q / %q", chat, line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("bob got nothing")
	}

	// Something else now answers for "bob".
	err := alice.deliver("bob", malloryAddr, "secret")
	var mismatch *storage.IdentityMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("expected identity mismatch, got %v", err)
	}
}

func TestDeliverUsesConfigContactAddress(t *testing.T) {
	t.Setenv("TARION_HOME", t.TempDir())
	bob, bobAddr := startTestNode(t, &storage.Config{Username: "bob"})
	alice, _ := startTestNode(t, &storage.Config{Username: "alice", Contacts: []storage.Contact{{Name: "bob", Addr: bobAddr}}})

	if err := alice.deliver("bob", "", "via config"); err != nil {
		t.Fatal(err)
	}
	select {
	case msg := <-bob.nm.MessageChan:
		if msg.Body != "via config" {
			t.Fatalf("got %q", msg.Body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("bob got nothing")
	}
	if err := alice.deliver("carol", "", "nobody"); err == nil || !strings.Contains(err.Error(), "no address") {
		t.Fatalf("unknown contact: %v", err)
	}
}

func TestSubscribeAndHistory(t *testing.T) {
	t.Setenv("TARION_HOME", t.TempDir())
	bobCfg := &storage.Config{Username: "bob", ControlPort: freeTCPPort(t)}
	bob, bobAddr := startTestNode(t, bobCfg)
	alice, _ := startTestNode(t, &storage.Config{Username: "alice"})
	go bob.serveIncoming(nil)

	token, _ := newControlToken()
	if err := serveBackgroundControl(token, bob); err != nil {
		t.Fatal(err)
	}
	if err := saveControlToken(token); err != nil {
		t.Fatal(err)
	}

	events := make(chan controlEvent, 8)
	go func() {
		_ = subscribeControl(bobCfg, func(ev controlEvent) bool {
			events <- ev
			return ev.Type != "message"
		})
	}()
	select {
	case ev := <-events:
		if ev.Type != "status" {
			t.Fatalf("first event should be the status, got %+v", ev)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("subscribe never answered")
	}

	if err := alice.deliver("bob", bobAddr, "hello app"); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-events:
		if ev.Type != "message" || ev.Chat != "alice" || ev.Body != "hello app" || ev.PeerID != alice.nm.ID() {
			t.Fatalf("event: %+v", ev)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no message event")
	}

	resp, err := backgroundCall(bobCfg, controlRequest{Cmd: "history", To: "alice", Limit: 1})
	if err != nil || len(resp.Lines) != 1 || resp.Lines[0] != "alice: hello app" {
		t.Fatalf("history: %+v %v", resp, err)
	}
}

func TestAcceptContactsOnly(t *testing.T) {
	t.Setenv("TARION_HOME", t.TempDir())
	bob, bobAddr := startTestNode(t, &storage.Config{Username: "bob", Accept: "contacts"})
	alice, aliceAddr := startTestNode(t, &storage.Config{Username: "alice"})

	err := alice.deliver("bob", bobAddr, "hi stranger")
	if err == nil || !strings.Contains(err.Error(), "only accepts messages from contacts") {
		t.Fatalf("stranger should be refused, got %v", err)
	}

	// Once bob writes to alice, she is his contact and may answer.
	if err := bob.deliver("alice", aliceAddr, "hi alice"); err != nil {
		t.Fatal(err)
	}
	<-alice.nm.MessageChan
	if err := alice.deliver("bob", bobAddr, "hi back"); err != nil {
		t.Fatalf("contact refused: %v", err)
	}
}
