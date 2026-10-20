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
	"github.com/necromancer124/tarion/internal/network"
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

func startNode(t *testing.T) (*network.NetworkManager, string) {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	nm := network.NewNetworkManager(port, id)
	if err := nm.StartListener(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nm.Close() })
	return nm, fmt.Sprintf("127.0.0.1:%d", port)
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
	nm, _ := startNode(t)
	port := nm.Port

	if backgroundRunning(port) {
		t.Fatal("no token file yet, should not count as running")
	}
	token, _ := newControlToken()
	if err := serveBackgroundControl(port, token, nm, storage.DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	if err := saveControlToken("not-the-token"); err != nil {
		t.Fatal(err)
	}
	if err := backgroundRequest(port, controlRequest{Cmd: "ping"}); err == nil || !strings.Contains(err.Error(), "bad control token") {
		t.Fatalf("wrong token accepted: %v", err)
	}
	if err := saveControlToken(token); err != nil {
		t.Fatal(err)
	}
	if err := backgroundRequest(port, controlRequest{Cmd: "ping"}); err != nil {
		t.Fatalf("right token rejected: %v", err)
	}
}

func TestDeliverPinsContactAndRefusesImpostor(t *testing.T) {
	t.Setenv("TARION_HOME", t.TempDir())
	alice, _ := startNode(t)
	bob, bobAddr := startNode(t)
	_, malloryAddr := startNode(t)
	cfg := &storage.Config{Username: "alice"}

	if err := deliver(alice, cfg, "bob", bobAddr, "hi bob\x1b[2J"); err != nil {
		t.Fatalf("first delivery: %v", err)
	}
	select {
	case msg := <-bob.MessageChan:
		chat, line := recordIncoming(msg)
		if chat != "alice" || line != "alice: hi bob[2J" {
			t.Fatalf("recorded as %q / %q", chat, line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("bob got nothing")
	}

	// The directory (or anyone) now points "bob" at a different key.
	err := deliver(alice, cfg, "bob", malloryAddr, "secret")
	var mismatch *storage.IdentityMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("expected identity mismatch, got %v", err)
	}
}
