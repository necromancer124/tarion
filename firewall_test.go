package main

import (
	"strings"
	"testing"

	"github.com/necromancer124/tarion/internal/firewall"
	"github.com/necromancer124/tarion/internal/storage"
)

func TestFirewallBlockExplainsTheFix(t *testing.T) {
	t.Setenv("TARION_HOME", t.TempDir())
	n, _ := startTestNode(t, &storage.Config{Username: "alice"})

	n.firewall = func(int) firewall.Status { return firewall.Status{Known: true} }
	if why := n.firewallBlocked("UDP 1"); why != "" {
		t.Fatalf("an open firewall was blamed: %s", why)
	}

	n.firewall = func(port int) firewall.Status {
		return firewall.Status{Known: true, Blocked: true, Reason: "Windows Firewall blocks incoming connections"}
	}
	why := n.firewallBlocked("UDP 63426 (203.0.113.7:63426 via UPnP)")
	for _, want := range []string{"dropped the server's test packet", "Windows Firewall blocks", "tarion firewall allow", "netsh advfirewall", "tarion portmap"} {
		if !strings.Contains(why, want) {
			t.Errorf("explanation lacks %q:\n%s", want, why)
		}
	}

	var logged []string
	n.setLogger(func(s string) { logged = append(logged, s) })
	n.warnFirewall()
	if len(logged) != 1 || !strings.Contains(logged[0], "people can't connect to you first") {
		t.Fatalf("startup warning: %q", logged)
	}
}
