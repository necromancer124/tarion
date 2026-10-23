package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/necromancer124/tarion/internal/directory"
	"github.com/necromancer124/tarion/internal/identity"
	"github.com/necromancer124/tarion/internal/mailbox"
	"github.com/necromancer124/tarion/internal/network"
	"github.com/necromancer124/tarion/internal/portmap"
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

func TestRevokedPeerRefusedBothWays(t *testing.T) {
	t.Setenv("TARION_HOME", t.TempDir())
	alice, aliceAddr := startTestNode(t, &storage.Config{Username: "alice"})
	bob, bobAddr := startTestNode(t, &storage.Config{Username: "bob"})

	// alice's server banned bob.
	alice.setRevoked([]string{bob.nm.ID()})
	if err := alice.deliver("bob", bobAddr, "hi"); !errors.Is(err, errRevoked) {
		t.Fatalf("sending to a banned key: %v", err)
	}
	if err := bob.deliver("alice", aliceAddr, "hi"); err == nil || !strings.Contains(err.Error(), "banned") {
		t.Fatalf("banned key's message accepted: %v", err)
	}
	// Survives a restart: the list is saved.
	if !storage.LoadRevoked()[strings.ToLower(bob.nm.ID())] {
		t.Fatal("revocation list not persisted")
	}
	alice.setRevoked(nil)
	if err := alice.deliver("bob", bobAddr, "unbanned"); err != nil {
		t.Fatalf("after unban: %v", err)
	}
}

func TestOfflineMessageIsQueuedAndDeliveredLater(t *testing.T) {
	t.Setenv("TARION_HOME", t.TempDir())
	alice, _ := startTestNode(t, &storage.Config{Username: "alice"})
	alice.sendTimeout = time.Second
	bobPort := freePort(t)
	bobAddr := fmt.Sprintf("127.0.0.1:%d", bobPort)

	how, err := alice.send("bob", bobAddr, "while you were away")
	if how != sendQueued || err == nil {
		t.Fatalf("expected the message to be queued, got %v err=%v", how, err)
	}
	items, _ := storage.Outbox()
	if len(items) != 1 {
		t.Fatalf("outbox: %+v", items)
	}

	// bob comes online at that address (a bare endpoint, so no second
	// outbox loop shares this test's data folder).
	bobID, _ := identity.Generate()
	bob := network.NewNetworkManager(bobPort, bobID)
	if err := bob.StartListener(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bob.Close() })

	items[0].NextTry = time.Now()
	_ = storage.UpdateOutbox(items[0])
	alice.flushOutbox()

	select {
	case m := <-bob.MessageChan:
		if m.Body != "while you were away" || m.ID != items[0].ID {
			t.Fatalf("got %+v, want the queued message with its original ID", m)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("queued message never arrived")
	}
	if left, _ := storage.Outbox(); len(left) != 0 {
		t.Fatalf("outbox not emptied: %+v", left)
	}
	lines, _ := storage.ReadHistory("bob")
	if len(lines) == 0 || !strings.Contains(lines[len(lines)-1], "delivered later") {
		t.Fatalf("history: %v", lines)
	}
}

func TestRetryableErrors(t *testing.T) {
	withServer := &node{dir: &directory.Client{}}
	without := &node{}
	for _, tc := range []struct {
		err       error
		n         *node
		retryable bool
	}{
		{fmt.Errorf("bob is %w", errOffline), without, true},
		{errors.New("dial 1.2.3.4:5: timeout"), without, true},
		{&network.RejectedError{Reason: "receiver busy"}, without, true},
		{&network.RejectedError{Reason: "this user only accepts messages from contacts"}, without, false},
		{&storage.IdentityMismatchError{Name: "bob"}, without, false},
		{fmt.Errorf("bob is %w", errRevoked), without, false},
		{fmt.Errorf("%w for bob", errNoAddress), without, false},
		{fmt.Errorf("%w for bob", errNoAddress), withServer, true},
	} {
		if got := tc.n.retryable(tc.err); got != tc.retryable {
			t.Errorf("%v (server=%v): retryable=%v", tc.err, tc.n.dir != nil, got)
		}
	}
}

func TestLateMessageShowsSendTime(t *testing.T) {
	t.Setenv("TARION_HOME", t.TempDir())
	id, _ := identity.Generate()
	_, line := recordIncoming(network.IncomingMessage{PeerID: id.ID, Name: "bob", Body: "old news", Sent: time.Now().Add(-time.Hour)})
	if !strings.Contains(line, "(sent ") {
		t.Fatalf("late message line: %q", line)
	}
	_, line = recordIncoming(network.IncomingMessage{PeerID: id.ID, Name: "bob", Body: "fresh", Sent: time.Now()})
	if strings.Contains(line, "(sent ") {
		t.Fatalf("fresh message should not show a time: %q", line)
	}
}

func TestBannedContactIsRefusedNotQueued(t *testing.T) {
	t.Setenv("TARION_HOME", t.TempDir())
	alice, _ := startTestNode(t, &storage.Config{Username: "alice"})
	bobID, _ := identity.Generate()
	// alice knows bob from before; then the server bans him and he is offline.
	if err := storage.PinOutgoing("bob", bobID.ID, ""); err != nil {
		t.Fatal(err)
	}
	alice.setRevoked([]string{bobID.ID})
	how, err := alice.send("bob", "", "are you there?")
	if how != sendFailed || !errors.Is(err, errRevoked) {
		t.Fatalf("banned contact: %v err=%v", how, err)
	}
	if items, _ := storage.Outbox(); len(items) != 0 {
		t.Fatalf("message to a banned contact was queued: %+v", items)
	}
}

func TestServerBansCanBeTurnedOff(t *testing.T) {
	t.Setenv("TARION_HOME", t.TempDir())
	alice, _ := startTestNode(t, &storage.Config{Username: "alice", ServerBans: "off"})
	bob, bobAddr := startTestNode(t, &storage.Config{Username: "bob"})
	alice.setRevoked([]string{bob.nm.ID()})
	if err := alice.deliver("bob", bobAddr, "my client ignores the ban list"); err != nil {
		t.Fatalf("with server_bans off the ban list must not apply: %v", err)
	}
}

func TestOptionFlagsValidate(t *testing.T) {
	for _, tc := range []struct {
		bans, relay, public string
		ok                  bool
	}{
		{"", "", "", true},
		{"off", "on", "203.0.113.7:63426", true},
		{"on", "off", "my-home.example.net:63426", true},
		{"maybe", "", "", false},
		{"", "yes", "", false},
		{"", "", "203.0.113.7", false},
		{"", "", "bad host:1", false},
	} {
		empty, port, ctrl := "", 0, 0
		f := clientFlags{port: &port, ctrl: &ctrl, server: &empty, user: &empty, pass: &empty,
			serverBans: &tc.bans, relayMode: &tc.relay, publicAddr: &tc.public}
		cfg := storage.DefaultConfig()
		if err := f.apply(cfg); (err == nil) != tc.ok {
			t.Errorf("bans=%q relay=%q public=%q: %v", tc.bans, tc.relay, tc.public, err)
		}
	}
	if (&storage.Config{}).RelayEnabled() || !(&storage.Config{}).EnforcesServerBans() {
		t.Fatal("defaults: relay must be off and server bans on")
	}
}

func TestDroppedMessagesAreLogged(t *testing.T) {
	t.Setenv("TARION_HOME", t.TempDir())
	_, bobAddr := startTestNode(t, &storage.Config{Username: "bob", Accept: "contacts"})
	alice, _ := startTestNode(t, &storage.Config{Username: "alice"})

	how, err := alice.send("bob", bobAddr, "let me in")
	if how != sendFailed || err == nil {
		t.Fatalf("a contacts-only refusal is final: %v err=%v", how, err)
	}
	entries, _ := storage.ReadDropped(0)
	var in, out bool
	for _, d := range entries {
		switch {
		case d.Dir == "in" && strings.Contains(d.Reason, "only accepts messages from contacts") && d.Body == "":
			in = true // bob's side: who and why, never the text
		case d.Dir == "out" && d.Peer == "bob" && d.Body == "let me in":
			out = true // alice's side keeps what was lost
		}
	}
	if !in || !out {
		t.Fatalf("expected both sides logged, got %+v", entries)
	}
}

func TestOutboxGivesUpAfterSevenDays(t *testing.T) {
	t.Setenv("TARION_HOME", t.TempDir())
	alice, _ := startTestNode(t, &storage.Config{Username: "alice"})
	old := time.Now().Add(-8 * 24 * time.Hour)
	_ = storage.Enqueue(storage.OutboxItem{ID: network.NewMessageID(), To: "bob", Addr: "127.0.0.1:9", Body: "too late", Created: old, NextTry: old, LastError: "bob is offline"})
	alice.flushOutbox()
	if items, _ := storage.Outbox(); len(items) != 0 {
		t.Fatalf("expired message still queued: %+v", items)
	}
	entries, _ := storage.ReadDropped(0)
	if len(entries) != 1 || entries[0].Body != "too late" || !strings.Contains(entries[0].Reason, "7 days") {
		t.Fatalf("dropped log: %+v", entries)
	}
}

// fakeMapper stands in for a router in tests; no real router is contacted.
type fakeMapper struct {
	name    string
	ext     net.IP
	err     error
	removed bool
}

func (f *fakeMapper) Name() string { return f.name }
func (f *fakeMapper) Map(ctx context.Context, localIP net.IP, port int, lease time.Duration) (*portmap.Mapping, error) {
	if f.err != nil {
		return nil, f.err
	}
	return portmap.NewMapping(f.name, f.ext, port, port, lease, nil, func(context.Context) error {
		f.removed = true
		return nil
	}), nil
}

func TestPortMappingOffReasons(t *testing.T) {
	base := storage.Config{ServerAddr: "198.51.100.5:63425", Username: "alice"}
	for _, tc := range []struct {
		mutate func(*storage.Config)
		want   string
	}{
		{func(c *storage.Config) {}, ""},
		{func(c *storage.Config) { c.PortMapping = "off" }, "turned off"},
		{func(c *storage.Config) { c.PublicAddr = "203.0.113.7:63426" }, "public_addr yourself"},
		{func(c *storage.Config) { c.Relay = "on" }, "relay is on"},
		{func(c *storage.Config) { c.Relay, c.PortMapping = "on", "on" }, ""},
		{func(c *storage.Config) { c.ServerAddr = "" }, "no server"},
	} {
		c := base
		tc.mutate(&c)
		got := c.PortMappingOff()
		if (tc.want == "") != (got == "") || !strings.Contains(got, tc.want) {
			t.Errorf("%+v: %q, want %q", c, got, tc.want)
		}
	}
}

func TestMapPortExplainsFailure(t *testing.T) {
	t.Setenv("TARION_HOME", t.TempDir())
	n, _ := startTestNode(t, &storage.Config{Username: "alice"})
	n.mappers = []portmap.Mapper{
		&fakeMapper{name: "UPnP", err: errors.New("no UPnP router answered on your network")},
		&fakeMapper{name: "NAT-PMP", err: errors.New("your router (192.168.1.1) did not answer")},
	}
	ok, report := n.mapPort()
	if ok {
		t.Fatal("expected failure")
	}
	for _, want := range []string{"UPnP: no UPnP router", "NAT-PMP: your router", "tarion portmap", "-relay on"} {
		if !strings.Contains(report, want) {
			t.Errorf("report lacks %q:\n%s", want, report)
		}
	}
	if !strings.Contains(n.portStatus(), "failed") {
		t.Fatalf("status: %q", n.portStatus())
	}
}

func TestMapPortWithoutServerIsUntested(t *testing.T) {
	t.Setenv("TARION_HOME", t.TempDir())
	n, _ := startTestNode(t, &storage.Config{Username: "alice"})
	n.mappers = []portmap.Mapper{&fakeMapper{name: "UPnP", ext: net.ParseIP("203.0.113.7")}}
	ok, report := n.mapPort()
	if !ok || !strings.Contains(report, "203.0.113.7") || !strings.Contains(report, "not announced or tested") {
		t.Fatalf("ok=%v report=%q", ok, report)
	}
}

// The router must not keep forwarding to a port nobody listens on: both a
// normal close (Ctrl+C, quitting the menu, the one-off portmap test) and
// `tarion stop` remove the mapping.
func TestPortForwardIsRemovedOnExit(t *testing.T) {
	t.Setenv("TARION_HOME", t.TempDir())
	for name, exit := range map[string]func(*node){
		"close":       func(n *node) { n.close() },
		"tarion stop": func(n *node) { n.prepareExit() },
	} {
		n, _ := startTestNode(t, &storage.Config{Username: "alice"})
		router := &fakeMapper{name: "UPnP", ext: net.ParseIP("203.0.113.7")}
		n.mappers = []portmap.Mapper{router}
		if ok, report := n.mapPort(); !ok {
			t.Fatalf("%s: mapping failed: %s", name, report)
		}
		if router.removed {
			t.Fatalf("%s: removed too early", name)
		}
		exit(n)
		if !router.removed {
			t.Errorf("%s: the router still forwards the port after exit", name)
		}
	}
}

func TestMailboxLetterArrivesLikeAMessage(t *testing.T) {
	t.Setenv("TARION_HOME", t.TempDir())
	bob, _ := startTestNode(t, &storage.Config{Username: "bob"})
	aliceID, _ := identity.Generate()
	bobBox, _ := mailbox.BoxKeys(bob.nm.Identity())
	sent := time.Now().Add(-3 * time.Hour)
	sealed, err := mailbox.Seal(aliceID, "alice", bob.nm.Identity().ID, bobBox, "m1", sent, "left while you slept")
	if err != nil {
		t.Fatal(err)
	}
	letter := directory.Letter{ID: "a1", From: "alice", Sealed: sealed}

	if err := bob.openLetter(letter); err != nil {
		t.Fatal(err)
	}
	select {
	case msg := <-bob.nm.MessageChan:
		if msg.PeerID != aliceID.ID || msg.Body != "left while you slept" || msg.Sent.Unix() != sent.Unix() || msg.Addr != "" {
			t.Fatalf("message: %+v", msg)
		}
		if chat, line := recordIncoming(msg); chat != "alice" || !strings.Contains(line, "(sent ") {
			t.Fatalf("history: %s %q", chat, line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("letter was not delivered")
	}
	if p, ok := storage.PeerByID(aliceID.ID); !ok || p.Addr != "" {
		t.Fatalf("sender must be pinned without an address: %+v", p)
	}

	// The same letter again (an ack was lost) is not shown twice.
	if err := bob.openLetter(letter); err != nil {
		t.Fatal(err)
	}
	select {
	case msg := <-bob.nm.MessageChan:
		t.Fatalf("duplicate delivered: %+v", msg)
	case <-time.After(200 * time.Millisecond):
	}

	// A letter sealed for someone else can't be opened; it is logged and
	// counts as handled so it doesn't sit on the server.
	carolID, _ := identity.Generate()
	carolBox, _ := mailbox.BoxKeys(carolID)
	other, _ := mailbox.Seal(aliceID, "alice", carolID.ID, carolBox, "m2", sent, "for carol")
	if err := bob.openLetter(directory.Letter{ID: "a2", From: "alice", Sealed: other}); err != nil {
		t.Fatal(err)
	}
	entries, _ := storage.ReadDropped(0)
	if len(entries) == 0 || !strings.Contains(entries[len(entries)-1].Reason, "mailbox letter rejected") {
		t.Fatalf("dropped log: %+v", entries)
	}
}

func TestMailboxLetterFollowsAcceptRules(t *testing.T) {
	t.Setenv("TARION_HOME", t.TempDir())
	bob, _ := startTestNode(t, &storage.Config{Username: "bob", Accept: "contacts"})
	strangerID, _ := identity.Generate()
	box, _ := mailbox.BoxKeys(bob.nm.Identity())
	sealed, _ := mailbox.Seal(strangerID, "stranger", bob.nm.Identity().ID, box, "m1", time.Now(), "hi")
	if err := bob.openLetter(directory.Letter{ID: "a1", From: "stranger", Sealed: sealed}); err != nil {
		t.Fatal(err)
	}
	select {
	case msg := <-bob.nm.MessageChan:
		t.Fatalf("a stranger's letter got past -accept contacts: %+v", msg)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestMailboxFlagValidates(t *testing.T) {
	for v, ok := range map[string]bool{"on": true, "off": true, "yes": false} {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		f := addClientFlags(fs)
		_ = fs.Parse([]string{"-mailbox", v})
		cfg := &storage.Config{}
		if err := f.apply(cfg); (err == nil) != ok {
			t.Errorf("-mailbox %s: %v", v, err)
		}
		if ok && cfg.MailboxEnabled() != (v == "on") {
			t.Errorf("-mailbox %s saved as %q", v, cfg.Mailbox)
		}
	}
}
