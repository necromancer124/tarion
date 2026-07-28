package network

import (
	"fmt"
	"net"
	"testing"
	"time"
)

func freeUDPPort(t *testing.T) int {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

func TestLoopbackSelfMessage(t *testing.T) {
	port := freeUDPPort(t)
	nm := NewNetworkManager(port)
	if err := nm.StartListener(); err != nil {
		t.Fatalf("StartListener: %v", err)
	}

	const body = "hello myself over QUIC"
	if err := nm.SendMessage(fmt.Sprintf("127.0.0.1:%d", port), body); err != nil {
		t.Fatalf("SendMessage loopback: %v", err)
	}

	select {
	case got := <-nm.MessageChan:
		if got.Body != body {
			t.Fatalf("body mismatch: got %q want %q", got.Body, body)
		}
		if got.From == "" {
			t.Fatal("expected non-empty sender address")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for loopback message")
	}
}

func TestLoopbackMessageWithStableSender(t *testing.T) {
	port := freeUDPPort(t)
	nm := NewNetworkManager(port)
	if err := nm.StartListener(); err != nil {
		t.Fatalf("StartListener: %v", err)
	}

	const from = "PC178"
	const body = "hello with identity"
	if err := nm.SendMessageFrom(fmt.Sprintf("127.0.0.1:%d", port), from, body); err != nil {
		t.Fatalf("SendMessageFrom loopback: %v", err)
	}

	select {
	case got := <-nm.MessageChan:
		if got.From != from {
			t.Fatalf("from mismatch: got %q want %q", got.From, from)
		}
		if got.Addr == "" {
			t.Fatal("expected stable advertised sender address")
		}
		if got.Body != body {
			t.Fatalf("body mismatch: got %q want %q", got.Body, body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for identified loopback message")
	}
}
