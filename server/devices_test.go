package main

import (
	"crypto/ed25519"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/necromancer124/tarion/internal/devices"
	"github.com/necromancer124/tarion/internal/directory"
	"github.com/necromancer124/tarion/internal/identity"
)

var codeRe = regexp.MustCompile(`approve ([A-Z0-9]{4}-[A-Z0-9]{4})`)

// approve signs and submits the approval for the device waiting with code.
func approve(t *testing.T, by *testClient, byID *identity.Identity, account, code string) error {
	t.Helper()
	p, err := by.dir.PendingDevice(code)
	if err != nil {
		return err
	}
	c := devices.Cert{Account: account, PeerID: p.PeerID, PubKey: p.PubKey, Name: p.Name, Added: time.Now().Unix()}
	devices.Sign(byID, &c)
	return by.dir.ApproveDevice(code, c)
}

func waitingCode(t *testing.T, c *testClient) string {
	t.Helper()
	var code string
	waitFor(t, "pairing code", func() bool {
		m := codeRe.FindStringSubmatch(c.dir.Status())
		if m != nil {
			code = m[1]
		}
		return m != nil
	})
	return code
}

func TestSecondDeviceNeedsApproval(t *testing.T) {
	old := directory.ApprovalRetry
	directory.ApprovalRetry = 200 * time.Millisecond
	t.Cleanup(func() { directory.ApprovalRetry = old })

	server, _ := startServer(t)
	phoneID, _ := identity.Generate()
	laptopID, _ := identity.Generate()
	phone := startClientCfg(t, directory.ClientConfig{Server: server, User: "alice", Pass: "correct-horse-1", DeviceName: "phone"}, phoneID)
	waitFor(t, "phone", phone.dir.Connected)

	// The right password from a new device isn't enough.
	laptop := startClientCfg(t, directory.ClientConfig{Server: server, User: "alice", Pass: "correct-horse-1", DeviceName: "laptop"}, laptopID)
	code := waitingCode(t, laptop)
	if laptop.dir.Connected() {
		t.Fatal("an unapproved device logged in")
	}

	// Someone else can't approve it, nor can a forged approval get through.
	bobID, _ := identity.Generate()
	bob := startClientCfg(t, directory.ClientConfig{Server: server, User: "bob", Pass: "battery-staple-2"}, bobID)
	waitFor(t, "bob", bob.dir.Connected)
	if err := approve(t, bob, bobID, "bob", code); err == nil {
		t.Fatal("another account approved alice's device")
	}
	p, err := phone.dir.PendingDevice(code)
	if err != nil || p.PeerID != laptopID.ID || p.Name != "laptop" {
		t.Fatalf("pending device: %+v %v", p, err)
	}
	forged := devices.Cert{Account: "alice", PeerID: p.PeerID, PubKey: p.PubKey, Name: p.Name, Added: 1}
	devices.Sign(bobID, &forged)
	forged.By = phoneID.ID
	if err := phone.dir.ApproveDevice(code, forged); err == nil {
		t.Fatal("an approval with a bad signature was accepted")
	}
	if _, err := phone.dir.PendingDevice("ZZZZ-ZZZZ"); err == nil {
		t.Fatal("a wrong code found a device")
	}

	// The phone approves it: both are online at once.
	if err := approve(t, phone, phoneID, "alice", code); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "laptop approved", laptop.dir.Connected)
	if !phone.dir.Connected() {
		t.Fatal("the phone was logged out by the laptop")
	}

	// bob sees both devices, and the chain checks out from the root.
	var resp directory.Response
	waitFor(t, "both devices listed", func() bool {
		resp, err = bob.dir.Lookup("alice")
		return err == nil && len(resp.Devices) == 2
	})
	root, ok := devices.Root(resp.Certs)
	if !ok || root.PeerID != phoneID.ID {
		t.Fatalf("root: %+v", root)
	}
	valid, err := devices.Verify("alice", resp.Certs, root.PeerID)
	sort.Strings(valid)
	want := []string{phoneID.ID, laptopID.ID}
	sort.Strings(want)
	if err != nil || strings.Join(valid, ",") != strings.Join(want, ",") {
		t.Fatalf("chain: %v %v", valid, err)
	}
	if list, _ := bob.dir.List(); len(list) != 1 || list[0] != "alice" {
		t.Fatalf("alice should be listed once: %v", list)
	}

	// Removing the laptop disconnects it; the phone can't remove itself
	// once it's the only device.
	if err := phone.dir.RemoveDevice(laptopID.ID); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "laptop removed", func() bool { return strings.Contains(laptop.dir.Status(), "removed from the account") })
	if err := phone.dir.RemoveDevice(phoneID.ID); err == nil || !strings.Contains(err.Error(), "only device") {
		t.Fatalf("removed the last device: %v", err)
	}
	mine, err := phone.dir.Devices("")
	if err != nil || len(mine.Certs) != 2 || !mine.Certs[1].Removed {
		t.Fatalf("own device list: %+v %v", mine.Certs, err)
	}
	_ = ed25519.PublicKeySize
}
