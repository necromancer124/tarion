package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/necromancer124/tarion/internal/devices"
	"github.com/necromancer124/tarion/internal/directory"
	"github.com/necromancer124/tarion/internal/identity"
	"github.com/necromancer124/tarion/internal/storage"
)

// deviceName names this device in the account's device list.
func deviceName() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "device"
}

// verifiedDevices checks a contact's device chain and returns the devices
// that belong to them. The chain is checked from the key you trust for
// them: the id in config.json, else the key pinned on first contact, else
// (first contact) their account's first device, which then becomes the
// pin. A server that predates devices sends no chain: nil, nil, and the
// single key is checked the old way. A chain that doesn't include the
// trusted key means the account was reset: a key change.
func (n *node) verifiedDevices(name string, certs []devices.Cert) (map[string]bool, error) {
	if len(certs) == 0 {
		return nil, nil
	}
	trusted := configuredID(n.cfg, name)
	if trusted == "" {
		if p, ok := storage.PeerByName(name); ok {
			trusted = p.ID
		}
	}
	root, hasRoot := devices.Root(certs)
	if trusted == "" {
		if !hasRoot {
			return nil, errors.New("the server sent a device list without a first device")
		}
		trusted = root.PeerID
	}
	valid, err := devices.Verify(directory.NameKey(name), certs, trusted)
	if err != nil {
		return nil, &storage.IdentityMismatchError{Name: name, Expected: trusted, Got: root.PeerID}
	}
	if err := storage.PinDevices(name, trusted, valid); err != nil {
		return nil, err
	}
	set := make(map[string]bool, len(valid))
	for _, id := range valid {
		set[id] = true
	}
	return set, nil
}

// learnDevice is asked about a key that wrote to us claiming a contact's
// name. If the contact's device chain includes it, it is pinned as theirs,
// so their new laptop isn't shown as an impostor ("bob~1a2b3c4d").
func (n *node) learnDevice(name, peerID string) {
	if name == "" || n.dir == nil || !n.dir.Connected() || !directory.ValidUsername(name) {
		return
	}
	n.learnMu.Lock()
	if n.learnTried == nil {
		n.learnTried = map[string]time.Time{}
	}
	recent := time.Since(n.learnTried[peerID]) < time.Minute
	if !recent {
		n.learnTried[peerID] = time.Now()
		if len(n.learnTried) > 1000 {
			n.learnTried = map[string]time.Time{peerID: time.Now()}
		}
	}
	n.learnMu.Unlock()
	if recent {
		return
	}
	resp, err := n.dir.Devices(name)
	if err != nil {
		return
	}
	_, _ = n.verifiedDevices(name, resp.Certs) // pins the verified set, if any
}

// deviceLines formats the account's devices for `tarion devices`.
func deviceLines(d *directory.Client, self string) ([]string, error) {
	resp, err := d.Devices("")
	if err != nil {
		return nil, err
	}
	online := map[string]bool{}
	for _, o := range resp.Devices {
		online[o.PeerID] = true
	}
	names := map[string]string{}
	for _, c := range resp.Certs {
		names[c.PeerID] = c.Name
	}
	var lines []string
	for _, c := range resp.Certs {
		if c.Removed {
			continue
		}
		by := "first device"
		if c.By != "" {
			by = "approved by " + names[c.By]
		}
		var notes []string
		if c.PeerID == self {
			notes = append(notes, "this device")
		}
		if online[c.PeerID] {
			notes = append(notes, "online")
		}
		note := ""
		if len(notes) > 0 {
			note = "  (" + strings.Join(notes, ", ") + ")"
		}
		lines = append(lines, fmt.Sprintf("%-16s %s  added %s, %s%s", c.Name, identity.Fingerprint(c.PeerID),
			time.Unix(c.Added, 0).Format("2006-01-02"), by, note))
	}
	return lines, nil
}

// approveDevice signs the waiting device into the account. expect is the
// peer ID the user confirmed, so a different device can't slip in between
// showing it and approving it.
func approveDevice(d *directory.Client, id *identity.Identity, account, code, expect string) error {
	p, err := d.PendingDevice(code)
	if err != nil {
		return err
	}
	if p.PeerID != expect {
		return errors.New("the waiting device changed; run the command again")
	}
	c := devices.Cert{Account: directory.NameKey(account), PeerID: p.PeerID, PubKey: p.PubKey, Name: p.Name, Added: time.Now().Unix()}
	devices.Sign(id, &c)
	return d.ApproveDevice(code, c)
}

// removeDevice removes a device given by name or peer ID.
func removeDevice(d *directory.Client, which string) (string, error) {
	resp, err := d.Devices("")
	if err != nil {
		return "", err
	}
	plain := strings.ReplaceAll(which, " ", "")
	var match []devices.Cert
	for _, c := range resp.Certs {
		if !c.Removed && (strings.EqualFold(c.Name, which) || strings.EqualFold(c.PeerID, plain)) {
			match = append(match, c)
		}
	}
	switch len(match) {
	case 0:
		return "", fmt.Errorf("no device %q on your account (see: tarion devices)", which)
	case 1:
	default:
		return "", fmt.Errorf("several devices are called %q; give its ID instead (see: tarion devices)", which)
	}
	return match[0].Name, d.RemoveDevice(match[0].PeerID)
}

// deviceControl serves `tarion devices` through the background process,
// which owns the server session.
func (n *node) deviceControl(req controlRequest) ([]string, error) {
	if n.dir == nil || !n.dir.Connected() {
		return nil, errors.New("not connected to a server")
	}
	switch req.Body {
	case "list":
		return deviceLines(n.dir, n.nm.Identity().ID)
	case "pending":
		p, err := n.dir.PendingDevice(req.To)
		if err != nil {
			return nil, err
		}
		return []string{p.Name, p.PeerID}, nil
	case "approve":
		return nil, approveDevice(n.dir, n.nm.Identity(), n.cfg.Username, req.To, req.Addr)
	case "remove":
		name, err := removeDevice(n.dir, req.To)
		return []string{name}, err
	}
	return nil, fmt.Errorf("unknown device action %q", req.Body)
}

func setDevicesUsage(fs *flag.FlagSet) {
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage:
  tarion devices                 list the devices on your account
  tarion devices approve CODE    add the device that is waiting with CODE
  tarion devices remove NAME|ID  take a device off your account (it is signed out)

To add a device: log in on it with your password (tarion start -server ...
-user NAME -pass ...). It shows a code; run "tarion devices approve CODE" on a
device that is already signed in. Your contacts accept the new device
automatically: your approval is signed, so the server can't add one itself.
`)
	}
}

func runDevices(args []string) error {
	fs := flag.NewFlagSet("devices", flag.ExitOnError)
	setDevicesUsage(fs)
	apply := portFlags(fs)
	_ = fs.Parse(args)
	cfg, err := storage.LoadOrCreateConfig()
	if err != nil {
		return err
	}
	apply(cfg)
	action, arg := fs.Arg(0), fs.Arg(1)
	switch {
	case action == "":
		action = "list"
	case action == "approve" && arg == "", action == "remove" && arg == "":
		fs.Usage()
		return fmt.Errorf("%s needs an argument", action)
	case action != "approve" && action != "remove":
		fs.Usage()
		return fmt.Errorf("unknown devices action %q", action)
	}

	// Through the background process when it runs (it holds the session),
	// otherwise over a short session of our own.
	call := func(body, to, expect string) ([]string, error) {
		if backgroundRunning(cfg) {
			resp, err := backgroundCall(cfg, controlRequest{Cmd: "devices", Body: body, To: to, Addr: expect})
			if err == nil && !resp.OK {
				err = errors.New(resp.Error)
			}
			return resp.Lines, err
		}
		var lines []string
		err := runAccountOp(cfg, controlRequest{}, func(d *directory.Client) error {
			id, err := loadIdentity()
			if err != nil {
				return err
			}
			switch body {
			case "list":
				lines, err = deviceLines(d, id.ID)
			case "pending":
				var p *directory.Pending
				if p, err = d.PendingDevice(to); err == nil {
					lines = []string{p.Name, p.PeerID}
				}
			case "approve":
				err = approveDevice(d, id, cfg.Username, to, expect)
			case "remove":
				var name string
				name, err = removeDevice(d, to)
				lines = []string{name}
			}
			return err
		})
		return lines, err
	}

	switch action {
	case "list":
		lines, err := call("list", "", "")
		if err != nil {
			return err
		}
		fmt.Printf("Devices on %s's account:\n", cfg.Username)
		for _, l := range lines {
			fmt.Println("  " + l)
		}
		fmt.Println("Add one: log in on it with your password, then run: tarion devices approve CODE")
	case "approve":
		lines, err := call("pending", arg, "")
		if err != nil {
			return err
		}
		if len(lines) != 2 {
			return errors.New("the server sent no device")
		}
		fmt.Printf("Device waiting to join %s:\n  name: %s\n  ID:   %s\n", cfg.Username, lines[0], identity.Fingerprint(lines[1]))
		fmt.Println("Check that the ID matches what the new device shows (tarion id on it).")
		ans, err := readLine("Approve it? [y/N] ")
		if err != nil {
			return err
		}
		if a := strings.ToLower(strings.TrimSpace(ans)); a != "y" && a != "yes" {
			fmt.Println("Not approved.")
			return nil
		}
		if _, err := call("approve", arg, lines[1]); err != nil {
			return err
		}
		fmt.Printf("Approved. %s logs in by itself within a few seconds.\n", lines[0])
	case "remove":
		lines, err := call("remove", arg, "")
		if err != nil {
			return err
		}
		name := arg
		if len(lines) == 1 {
			name = lines[0]
		}
		fmt.Printf("Removed %s from your account; it was signed out.\n", name)
	}
	return nil
}
