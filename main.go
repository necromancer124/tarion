package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/necromancer124/tarion/internal/directory"
	"github.com/necromancer124/tarion/internal/identity"
	"github.com/necromancer124/tarion/internal/network"
	"github.com/necromancer124/tarion/internal/portmap"
	"github.com/necromancer124/tarion/internal/relay"
	"github.com/necromancer124/tarion/internal/storage"
	"golang.org/x/term"
)

var (
	styleOnline   = lipgloss.NewStyle().Foreground(lipgloss.Color("2")).Bold(true)
	styleOffline  = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	styleSelected = lipgloss.NewStyle().Background(lipgloss.Color("60")).Foreground(lipgloss.Color("0"))
	styleBorder   = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("240")).Padding(0, 1)
	styleInput    = lipgloss.NewStyle().Foreground(lipgloss.Color("229"))
	styleNew      = lipgloss.NewStyle().Foreground(lipgloss.Color("13")).Bold(true)
	styleError    = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	styleDim      = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
)

type AppState int

const (
	StateListView AppState = iota
	StateChatView
	StateHelpView
)

type Contact struct {
	Username string
	Online   bool
	Addr     string
	Unread   bool
	IsManual bool // fixed address (config contact or -i); not driven by the server list
}

type model struct {
	state         AppState
	contacts      []Contact
	cursor        int
	activeContact string
	chatHistory   []string
	inputBuffer   string
	statusLine    string // result of the last action
	dirStatus     string // server connection state
	useBackground bool
	selfID        string
	seenMod       map[string]time.Time
	cfg           *storage.Config
	node          *node
}

type msgIncomingChat network.IncomingMessage
type msgSendResult struct {
	to  string
	err error
	how sendOutcome
}
type msgDirectory struct {
	status   string
	contacts []Contact
}
type msgTick time.Time

// node is the network side of a running client: the chat endpoint and, when
// a server is configured, the directory session. Both use the same UDP port,
// so the address the server sees for us is the one peers can dial.
type node struct {
	cfg    *storage.Config
	nm     *network.NetworkManager
	dir    *directory.Client
	cancel context.CancelFunc
	events *hub

	revokedMu sync.RWMutex
	revoked   map[string]bool // keys banned by the server

	relayedMu sync.Mutex
	relayed   map[string]relaySession // contacts last reached via the relay

	logMu sync.Mutex
	logFn func(string) // background process log; nil in the menu

	ctx     context.Context
	mappers []portmap.Mapper // UPnP, NAT-PMP; tests use fakes
	port    portState

	mailMu    sync.Mutex           // one mailbox fetch at a time
	mailWake  chan struct{}        // nudges the mailbox loop
	mailTried map[string]time.Time // outbox ID -> last offline check; under outboxMu

	outboxMu    sync.Mutex    // one outbox pass at a time
	outboxWake  chan struct{} // nudges the outbox loop
	sendTimeout time.Duration // per public-address attempt; tests shorten it
}

// isRevoked reports whether the server banned this key.
func (n *node) isRevoked(peerID string) bool {
	if !n.cfg.EnforcesServerBans() {
		return false
	}
	n.revokedMu.RLock()
	defer n.revokedMu.RUnlock()
	return n.revoked[strings.ToLower(peerID)]
}

func (n *node) setRevoked(keys []string) {
	set := make(map[string]bool, len(keys))
	for _, k := range keys {
		set[strings.ToLower(k)] = true
	}
	n.revokedMu.Lock()
	n.revoked = set
	n.revokedMu.Unlock()
	_ = storage.SaveRevoked(keys)
}

// errRevoked marks a peer the server operator banned.
var errRevoked = errors.New("banned on your server")

// accept filters incoming messages: never from banned keys, and only from
// contacts when cfg.Accept is "contacts".
func (n *node) accept(peerID string) error {
	err := n.acceptRule(peerID)
	if err != nil {
		from := "peer-" + identity.Short(peerID)
		if p, ok := storage.PeerByID(peerID); ok {
			from = p.Name
		}
		n.logDrop(storage.DroppedMessage{Dir: "in", Peer: from, Reason: "refused: " + err.Error()})
	}
	return err
}

func (n *node) acceptRule(peerID string) error {
	if n.isRevoked(peerID) {
		return errors.New("you are banned on this user's server")
	}
	if f := acceptFor(n.cfg); f != nil {
		return f(peerID)
	}
	return nil
}

func (n *node) setLogger(f func(string)) {
	n.logMu.Lock()
	n.logFn = f
	n.logMu.Unlock()
}

// logDrop records a message that will never be delivered, in dropped.log,
// the background log, and as a "dropped" event for local API apps.
func (n *node) logDrop(d storage.DroppedMessage) {
	d.Time = time.Now()
	_ = storage.LogDropped(d)
	n.events.publish(controlEvent{Type: "dropped", Chat: d.Peer, Body: d.Body, Reason: d.Reason, Time: d.Time.Format(time.RFC3339)})
	n.logMu.Lock()
	f := n.logFn
	n.logMu.Unlock()
	if f != nil {
		dir := "to"
		if d.Dir == "in" {
			dir = "from"
		}
		f(fmt.Sprintf("dropped message %s %s: %s", dir, d.Peer, d.Reason))
	}
}

// controlEvent is one line of a `subscribe` stream.
type controlEvent struct {
	Type   string `json:"type"` // "message" or "status"
	Chat   string `json:"chat,omitempty"`
	PeerID string `json:"peer_id,omitempty"`
	Body   string `json:"body,omitempty"`
	Time   string `json:"time,omitempty"` // when it arrived, RFC 3339
	Status string `json:"status,omitempty"`
	Reason string `json:"reason,omitempty"` // for "dropped"
}

// hub fans events out to local API subscribers. A subscriber that falls
// behind loses events rather than slowing down the node.
type hub struct {
	mu   sync.Mutex
	subs map[chan controlEvent]struct{}
}

const maxSubscribers = 16

func (h *hub) subscribe() (chan controlEvent, func(), error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.subs) >= maxSubscribers {
		return nil, nil, errors.New("too many subscribers")
	}
	ch := make(chan controlEvent, 64)
	h.subs[ch] = struct{}{}
	return ch, func() {
		h.mu.Lock()
		delete(h.subs, ch)
		h.mu.Unlock()
	}, nil
}

func (h *hub) publish(ev controlEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

// acceptFor returns the incoming-message filter for cfg.Accept.
func acceptFor(cfg *storage.Config) func(peerID string) error {
	if cfg.Accept != "contacts" {
		return nil
	}
	return func(peerID string) error {
		for _, c := range cfg.Contacts {
			if strings.EqualFold(strings.ReplaceAll(c.ID, " ", ""), peerID) {
				return nil
			}
		}
		if _, ok := storage.PeerByID(peerID); ok {
			return nil
		}
		return errors.New("this user only accepts messages from contacts")
	}
}

func startNode(cfg *storage.Config, id *identity.Identity) (*node, error) {
	nm := network.NewNetworkManager(cfg.Port, id)
	n := &node{
		cfg:         cfg,
		nm:          nm,
		events:      &hub{subs: map[chan controlEvent]struct{}{}},
		revoked:     storage.LoadRevoked(),
		outboxWake:  make(chan struct{}, 1),
		mailWake:    make(chan struct{}, 1),
		sendTimeout: 10 * time.Second,
	}
	nm.Accept = n.accept
	if err := nm.StartListener(); err != nil {
		return nil, err
	}
	if os.Getenv("TARION_SIMULATE_STRICT_NAT") == "1" {
		// Testing aid: behave like a strict NAT (only the server gets in),
		// so messages must take the relay.
		nm.Relay().SimulateStrictNAT(true)
	}
	ctx, cancel := context.WithCancel(context.Background())
	n.ctx, n.cancel = ctx, cancel
	n.mappers = portmap.Default()
	go n.runOutbox(ctx)
	if cfg.ServerAddr != "" && cfg.Username != "" {
		var boxKey, boxSig []byte
		if cfg.MailboxEnabled() {
			boxKey, boxSig = mailboxLogin(id)
		}
		n.dir = directory.NewClient(nm, directory.ClientConfig{
			Server:        cfg.ServerAddr,
			User:          cfg.Username,
			Pass:          cfg.Password,
			Invite:        cfg.Invite,
			ServerID:      cfg.ServerID,
			AcceptRelay:   cfg.RelayEnabled(),
			PublicAddr:    cfg.PublicAddr,
			AcceptMailbox: cfg.MailboxEnabled(),
			BoxKey:        boxKey,
			BoxSig:        boxSig,
			OnMail:        n.wakeMail,
			OnServerID: func(id string) {
				_ = storage.UpdateConfig(func(c *storage.Config) { c.ServerID = id })
			},
			OnRevoked: n.setRevoked,
			OnLoggedIn: func(usedPassword bool) {
				if usedPassword {
					// The account now trusts this device's key; stop keeping the
					// password, and the invite code is spent.
					_ = storage.UpdateConfig(func(c *storage.Config) { c.Password, c.Invite = "", "" })
				}
			},
		})
		go n.dir.Run(ctx)
		if n.mailboxOn() {
			go n.runMailbox(ctx)
		}
	}
	return n, nil
}

const (
	outboxRetryBase = 15 * time.Second
	outboxRetryMax  = 10 * time.Minute
	outboxExpiry    = 7 * 24 * time.Hour
)

// sendOutcome is what happened to a message when it was sent.
type sendOutcome int

const (
	sendFailed    sendOutcome = iota // not delivered and given up on
	sendDelivered                    // the contact has it
	sendMailed                       // sealed and left in their server mailbox
	sendQueued                       // waiting in the outbox for a retry
)

// send delivers now or, if the contact can't be reached, leaves the message
// in their server mailbox (when both use it) or queues it in the outbox and
// keeps retrying. err says why it was not delivered right away.
func (n *node) send(to, addr, body string) (sendOutcome, error) {
	if body == "" || len(body) > network.MaxBodyBytes {
		return sendFailed, fmt.Errorf("message must be 1-%d bytes", network.MaxBodyBytes)
	}
	id, now := network.NewMessageID(), time.Now()
	err := n.deliverMsg(id, now, to, addr, body)
	if err == nil {
		return sendDelivered, nil
	}
	if !n.retryable(err) {
		n.logDrop(storage.DroppedMessage{Dir: "out", Peer: to, Reason: err.Error(), Body: body})
		return sendFailed, err
	}
	if n.useMailbox(err) {
		merr := n.depositMail(id, now, to, body)
		if merr == nil {
			return sendMailed, err
		}
		err = fmt.Errorf("%w; mailbox: %v", err, merr)
	}
	item := storage.OutboxItem{ID: id, To: to, Addr: addr, Body: body, Created: now, Attempts: 1,
		NextTry: now.Add(outboxRetryBase), LastError: err.Error()}
	if qerr := storage.Enqueue(item); qerr != nil {
		err = fmt.Errorf("%v (could not queue it: %v)", err, qerr)
		n.logDrop(storage.DroppedMessage{Dir: "out", Peer: to, Reason: err.Error(), Body: body})
		return sendFailed, err
	}
	select {
	case n.outboxWake <- struct{}{}:
	default:
	}
	return sendQueued, err
}

// retryable is false for failures waiting won't fix: a wrong or banned key,
// a refusal, or nowhere to look for the contact.
func (n *node) retryable(err error) bool {
	var mismatch *storage.IdentityMismatchError
	var rejected *network.RejectedError
	switch {
	case errors.Is(err, errRevoked), errors.As(err, &mismatch):
		return false
	case errors.As(err, &rejected):
		return rejected.Reason == "receiver busy"
	case errors.Is(err, errNoAddress):
		return n.dir != nil // they may still log in to the server
	}
	return true
}

func (n *node) runOutbox(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-n.outboxWake:
		}
		n.flushOutbox()
	}
}

// flushOutbox retries queued messages that are due, or whose recipient the
// server now lists as online. Messages to one contact stay in order: after
// a failure, that contact's later messages wait for the next pass.
func (n *node) flushOutbox() {
	n.outboxMu.Lock()
	defer n.outboxMu.Unlock()
	items, err := storage.Outbox()
	if err != nil || len(items) == 0 {
		return
	}
	online := map[string]bool{}
	if n.dir != nil && n.dir.Connected() {
		users, _ := n.dir.List()
		for _, u := range users {
			online[strings.ToLower(u)] = true
		}
	}
	now := time.Now()
	blocked := map[string]bool{}
	for _, it := range items {
		key := strings.ToLower(it.To)
		if blocked[key] {
			continue
		}
		if now.Sub(it.Created) > outboxExpiry {
			_ = storage.RemoveOutbox(it.ID)
			_ = storage.AppendHistory(it.To, "  ! gave up after 7 days, not delivered: "+snippet(it.Body))
			n.logDrop(storage.DroppedMessage{Dir: "out", Peer: it.To, Reason: "gave up after 7 days: " + it.LastError, Body: it.Body})
			continue
		}
		if now.Before(it.NextTry) && !online[key] {
			// Not due yet, but if they have gone offline their mailbox can
			// take it now instead of after the retry wait.
			if n.mailboxOn() && n.mailWhenOffline(it, now) {
				continue
			}
			blocked[key] = true
			continue
		}
		err := n.deliverMsg(it.ID, it.Created, it.To, it.Addr, it.Body)
		switch {
		case err == nil:
			_ = storage.RemoveOutbox(it.ID)
			_ = storage.AppendHistory(it.To, "  ✓ delivered later: "+snippet(it.Body))
			n.events.publish(controlEvent{Type: "delivered", Chat: it.To, Body: it.Body, Time: time.Now().Format(time.RFC3339)})
		case !n.retryable(err):
			_ = storage.RemoveOutbox(it.ID)
			_ = storage.AppendHistory(it.To, "  ! not delivered: "+storage.CleanText(err.Error()))
			n.logDrop(storage.DroppedMessage{Dir: "out", Peer: it.To, Reason: err.Error(), Body: it.Body})
		default:
			if n.useMailbox(err) {
				merr := n.mailItem(it, err)
				if merr == nil {
					continue
				}
				err = fmt.Errorf("%w; mailbox: %v", err, merr)
			}
			it.Attempts++
			wait := outboxRetryBase << min(it.Attempts, 6)
			if wait > outboxRetryMax {
				wait = outboxRetryMax
			}
			it.NextTry, it.LastError = now.Add(wait), err.Error()
			_ = storage.UpdateOutbox(it)
			blocked[key] = true
		}
	}
}

// mailItem leaves a queued message in the contact's server mailbox.
func (n *node) mailItem(it storage.OutboxItem, deliverErr error) error {
	if err := n.depositMail(it.ID, it.Created, it.To, it.Body); err != nil {
		return err
	}
	_ = storage.RemoveOutbox(it.ID)
	_ = storage.AppendHistory(it.To, "  ✉ left in their server mailbox: "+snippet(it.Body))
	n.events.publish(controlEvent{Type: "mailed", Chat: it.To, Body: it.Body, Reason: deliverErr.Error(), Time: time.Now().Format(time.RFC3339)})
	return nil
}

func snippet(s string) string {
	s = storage.CleanText(s)
	if r := []rune(s); len(r) > 40 {
		return string(r[:40]) + "…"
	}
	return s
}

// serveIncoming records each incoming message and tells subscribers. The
// TUI reads MessageChan itself; the background process uses this.
func (n *node) serveIncoming(log func(chat string, msg network.IncomingMessage)) {
	for msg := range n.nm.MessageChan {
		chat, _ := recordIncoming(msg)
		n.events.publish(controlEvent{Type: "message", Chat: chat, PeerID: msg.PeerID, Body: msg.Body, Time: time.Now().Format(time.RFC3339)})
		if log != nil {
			log(chat, msg)
		}
	}
}

// watchStatus publishes server status changes.
func (n *node) watchStatus(log func(string)) {
	if n.dir == nil {
		return
	}
	last := ""
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for ; ; <-ticker.C {
		if s := n.dir.Status(); s != last {
			last = s
			n.events.publish(controlEvent{Type: "status", Status: s})
			if log != nil {
				log(s)
			}
		}
	}
}

func (n *node) close() {
	n.cancel()
	n.removeMapping(false)
	_ = n.nm.Close()
}

// directoryStatus returns the server state and who is online.
func (n *node) directoryStatus() (string, []string) {
	if n.dir == nil {
		return "no server configured (use -server and -user)", nil
	}
	if !n.dir.Connected() {
		return n.dir.Status(), nil
	}
	users, err := n.dir.List()
	if err != nil {
		return "server: " + err.Error(), nil
	}
	status := n.dir.Status()
	if p := n.portStatus(); p != "" {
		status += "; " + p
	}
	return status, users
}

// portState is the automatic port forwarding (see package portmap).
type portState struct {
	busy    sync.Mutex // one attempt at a time
	mu      sync.Mutex
	mapping *portmap.Mapping
	status  string // one line for menus
	report  string // the full story of the last attempt
}

func (n *node) portStatus() string {
	n.port.mu.Lock()
	defer n.port.mu.Unlock()
	return n.port.status
}

func (n *node) setPort(m *portmap.Mapping, status, report string) {
	n.port.mu.Lock()
	n.port.mapping, n.port.status, n.port.report = m, status, report
	n.port.mu.Unlock()
	n.events.publish(controlEvent{Type: "portmap", Status: status, Reason: report, Time: time.Now().Format(time.RFC3339)})
	n.logMu.Lock()
	f := n.logFn
	n.logMu.Unlock()
	if f != nil && report != "" {
		f(report)
	}
}

// startPortMapping opens a port mapping in the background when the
// settings call for it (by default: whenever the relay is off), and keeps
// it renewed.
func (n *node) startPortMapping() {
	if n.cfg.PortMappingOff() != "" || n.dir == nil {
		return
	}
	go func() {
		// The server's view of our address is needed to check the mapping.
		for deadline := time.Now().Add(30 * time.Second); !n.dir.Connected() && time.Now().Before(deadline); {
			select {
			case <-n.ctx.Done():
				return
			case <-time.After(200 * time.Millisecond):
			}
		}
		n.mapPort()
		for {
			select {
			case <-n.ctx.Done():
				return
			case <-time.After(portRenewEvery):
			}
			n.port.mu.Lock()
			m := n.port.mapping
			n.port.mu.Unlock()
			if m == nil {
				continue // failed earlier; `tarion portmap` retries on demand
			}
			ctx, cancel := context.WithTimeout(n.ctx, 10*time.Second)
			err := m.Renew(ctx)
			cancel()
			if err != nil {
				n.mapPort() // the router forgot it (reboot?): start over
			}
		}
	}()
}

const (
	portLease      = time.Hour
	portRenewEvery = 25 * time.Minute
)

// mapPort asks the router to forward the chat port, checks that the result
// is really reachable from the internet, and announces it to the server.
// It reports whether it worked and, either way, explains what happened.
func (n *node) mapPort() (bool, string) {
	n.port.busy.Lock()
	defer n.port.busy.Unlock()
	n.removeMapping(true)
	n.setPort(nil, "port forwarding: asking the router...", "")

	ctx, cancel := context.WithTimeout(n.ctx, 45*time.Second)
	defer cancel()
	fail := func(report string) (bool, string) {
		n.setPort(nil, "port forwarding failed (run 'tarion portmap' to see why)", report)
		return false, report
	}

	m, err := portmap.Open(ctx, n.mappers, lanIP(n.nm), n.cfg.Port, portLease)
	if err != nil {
		return fail(err.Error())
	}
	drop := func() { _ = m.Remove(context.Background()) }

	if m.ExternalIP == nil {
		// The router forwarded the port but wouldn't say its internet
		// address: use the one the server sees; the test packet below checks it.
		seen := net.IP(nil)
		if n.dir != nil {
			seen = hostIP(n.dir.SeenAddr())
		}
		if seen == nil || seen.IsLoopback() || portmap.NotPublic(seen) != "" {
			drop()
			return fail("automatic port forwarding did not work:\n  - " + m.Method + ": the router forwarded the port but wouldn't say its internet address, and there is no server that sees a public one to use instead\n" + portmap.Advice(n.cfg.Port))
		}
		m.ExternalIP = seen
	}

	if n.dir != nil {
		if seen := hostIP(n.dir.SeenAddr()); seen != nil && !seen.IsLoopback() && !seen.Equal(m.ExternalIP) {
			drop()
			return fail("automatic port forwarding did not work:\n  - " + portmap.DoubleNAT(m.ExternalIP.String(), seen.String()) + "\n" + portmap.Advice(n.cfg.Port))
		}
		if err := n.dir.SetPublicAddr(m.Addr()); err != nil {
			drop()
			return fail("the router forwards " + m.Addr() + ", but telling the server failed: " + err.Error())
		}
		reachable, err := n.probeReachable()
		switch {
		case err != nil:
			// An older server, or one that can't test; keep it untested.
			ok := fmt.Sprintf("port forwarding: on via %s, %s (not verified: %v)", m.Method, m.Addr(), err)
			n.setPort(m, ok, ok)
			return true, ok
		case !reachable:
			_ = n.dir.SetPublicAddr("")
			drop()
			return fail("automatic port forwarding did not work:\n  - " + m.Method + ": " + portmap.Unreachable(m.Addr(), n.cfg.Port) + "\n" + portmap.Advice(n.cfg.Port))
		}
	}
	ok := fmt.Sprintf("port forwarding: on via %s, %s (reachable from the internet)", m.Method, m.Addr())
	if n.dir == nil {
		ok = fmt.Sprintf("port forwarding: on via %s, %s (not announced or tested: no server)", m.Method, m.Addr())
	}
	n.setPort(m, ok, ok)
	return true, ok
}

// probeReachable has the server send a test packet to our advertised
// address from a different port, as a stranger would.
func (n *node) probeReachable() (bool, error) {
	nonce := relay.NewID()
	got, stop := n.nm.Relay().ExpectProbe(nonce)
	defer stop()
	if err := n.dir.Probe(nonce.String()); err != nil {
		return false, err
	}
	select {
	case <-got:
		return true, nil
	case <-time.After(4 * time.Second):
		return false, nil
	}
}

// prepareExit undoes what must not outlive the process: the router's port
// forward (nothing would be listening behind it) and the control token.
// `tarion stop` ends the process with os.Exit, which skips deferred
// cleanup, so it calls this first.
func (n *node) prepareExit() {
	n.removeMapping(false)
	_ = os.Remove(storage.GetControlTokenPath())
}

// removeMapping deletes the current mapping from the router and, when
// announce is set, withdraws it from the server.
func (n *node) removeMapping(announce bool) {
	n.port.mu.Lock()
	m := n.port.mapping
	n.port.mapping = nil
	n.port.mu.Unlock()
	if m == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = m.Remove(ctx)
	if announce && n.dir != nil && n.dir.Connected() {
		_ = n.dir.SetPublicAddr("")
	}
}

func lanIP(nm *network.NetworkManager) net.IP {
	if addrs := nm.LocalAddrs(); len(addrs) > 0 {
		return hostIP(addrs[0])
	}
	return nil
}

func hostIP(addr string) net.IP {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

func configuredID(cfg *storage.Config, name string) string {
	for _, c := range cfg.Contacts {
		if strings.EqualFold(c.Name, name) {
			// Accept the spaced form "tarion id" prints.
			return strings.ReplaceAll(strings.TrimSpace(c.ID), " ", "")
		}
	}
	return ""
}

// deliver sends body to the contact named to. If the server knows them it
// supplies their current address (LAN addresses first when you share a
// router) and their key, and asks them to punch toward us. Whatever key
// answers must match the key fixed in config, the server's record, and the
// key pinned on first contact; otherwise nothing is sent.
func (n *node) deliver(to, addr, body string) error {
	return n.deliverMsg(network.NewMessageID(), time.Now(), to, addr, body)
}

var (
	errOffline   = errors.New("offline")
	errNoAddress = errors.New("no address")
)

func (n *node) deliverMsg(id string, sent time.Time, to, addr, body string) error {
	// Refuse a banned contact up front: once the ban disconnects them they
	// look merely offline, and the message would sit in the outbox.
	if p, ok := storage.PeerByName(to); ok && n.isRevoked(p.ID) {
		return fmt.Errorf("%s is %w", to, errRevoked)
	}
	if id := configuredID(n.cfg, to); id != "" && n.isRevoked(id) {
		return fmt.Errorf("%s is %w", to, errRevoked)
	}
	var candidates []string
	dirID := ""
	offline := false
	if n.dir != nil && n.dir.Connected() && directory.ValidUsername(to) {
		resp, err := n.dir.Lookup(to)
		switch {
		case err == nil:
			dirID = resp.PeerID
			// LAN first, then an address they made reachable themselves
			// (a forwarded port), then the one the server observed.
			candidates = append(candidates, resp.LocalAddrs...)
			if resp.PublicAddr != "" && resp.PublicAddr != resp.Addr {
				candidates = append(candidates, resp.PublicAddr)
			}
			candidates = append(candidates, resp.Addr)
		case errors.Is(err, directory.ErrUserOffline):
			offline = true
		}
	}
	if len(candidates) == 0 {
		if addr == "" {
			addr = knownAddr(n.cfg, to)
		}
		if addr == "" {
			if offline {
				return fmt.Errorf("%s is %w", to, errOffline)
			}
			return fmt.Errorf("%w for %s", errNoAddress, to)
		}
		candidates = []string{addr}
	}

	configured := configuredID(n.cfg, to)
	attempt := func(cand string, timeout time.Duration, wantID string) error {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		_, err := n.nm.SendMessage(ctx, id, sent, cand, senderName(n.cfg), body, func(peerID string) error {
			if n.isRevoked(peerID) {
				return fmt.Errorf("%s is %w", to, errRevoked)
			}
			if configured != "" && !strings.EqualFold(configured, peerID) {
				return &storage.IdentityMismatchError{Name: to, Expected: configured, Got: peerID}
			}
			if wantID != "" && !strings.EqualFold(wantID, peerID) {
				return &storage.IdentityMismatchError{Name: to, Expected: wantID, Got: peerID}
			}
			return storage.PinOutgoing(to, peerID, cand)
		})
		return err
	}
	// final errors end the attempt: a wrong or banned key, or the peer was
	// reached and refused. Trying their other addresses (or the relay)
	// would only repeat the same answer.
	isIdentityErr := func(err error) bool {
		var mismatch *storage.IdentityMismatchError
		var rejected *network.RejectedError
		return errors.As(err, &mismatch) || errors.Is(err, errRevoked) || errors.As(err, &rejected)
	}

	// When the server knows the contact, it can relay if the direct path
	// fails (strict NATs). The packets stay end-to-end encrypted.
	canRelay := dirID != "" && n.cfg.RelayEnabled()
	viaRelay := func() error {
		// Reuse the contact's relay session while it is alive; the server
		// caps how many each user may hold open.
		if s, ok := n.relaySession(to); ok {
			err := attempt(s.addr, 3*time.Second, s.peerID)
			if err == nil {
				n.setRelaySession(to, s)
				return nil
			}
			if isIdentityErr(err) {
				return err
			}
		}
		raddr, relayID, err := n.dir.Relay(to)
		if err != nil {
			return err
		}
		if err := attempt(raddr, n.sendTimeout, relayID); err != nil {
			return err
		}
		n.setRelaySession(to, relaySession{addr: raddr, peerID: relayID})
		return nil
	}
	triedRelay := false
	if canRelay && n.relayedRecently(to) {
		triedRelay = true
		if err := viaRelay(); err == nil || isIdentityErr(err) {
			return err
		}
	}

	var lastErr error
	for i, cand := range candidates {
		timeout := n.sendTimeout
		if canRelay {
			timeout /= 2 // the relay is the fallback, don't wait the full time
		}
		if i < len(candidates)-1 {
			timeout = 3 * time.Second // a LAN address either answers fast or is wrong
		}
		err := attempt(cand, timeout, dirID)
		if err == nil {
			n.clearRelay(to)
			return nil
		}
		if isIdentityErr(err) {
			return err
		}
		lastErr = err
	}
	if canRelay && !triedRelay {
		err := viaRelay()
		if err == nil || isIdentityErr(err) {
			return err
		}
		return fmt.Errorf("%w (relay: %v)", lastErr, err)
	}
	if offline {
		// The server says they're offline; we only tried an old address.
		return fmt.Errorf("%s is %w (nothing at their last known address: %w)", to, errOffline, lastErr)
	}
	return lastErr
}

const (
	relayMemory     = 10 * time.Minute // go straight to the relay for this long
	relaySessionTTL = 90 * time.Second // reuse a session (the server keeps it 2 min)
)

type relaySession struct {
	addr, peerID string
	used         time.Time
}

// relayedRecently reports whether to was reached only through the relay in
// the last few minutes, so the next message can skip the direct attempts.
func (n *node) relayedRecently(to string) bool {
	n.relayedMu.Lock()
	defer n.relayedMu.Unlock()
	s, ok := n.relayed[strings.ToLower(to)]
	return ok && time.Since(s.used) < relayMemory
}

// relaySession returns a still-usable relay session to to.
func (n *node) relaySession(to string) (relaySession, bool) {
	n.relayedMu.Lock()
	defer n.relayedMu.Unlock()
	s, ok := n.relayed[strings.ToLower(to)]
	return s, ok && s.addr != "" && time.Since(s.used) < relaySessionTTL
}

func (n *node) setRelaySession(to string, s relaySession) {
	n.relayedMu.Lock()
	defer n.relayedMu.Unlock()
	if n.relayed == nil {
		n.relayed = map[string]relaySession{}
	}
	s.used = time.Now()
	n.relayed[strings.ToLower(to)] = s
}

func (n *node) clearRelay(to string) {
	n.relayedMu.Lock()
	delete(n.relayed, strings.ToLower(to))
	n.relayedMu.Unlock()
}

// The local API: one JSON object per line over TCP on 127.0.0.1, each
// request carrying the token from control.token. See docs/local-api.md.
type controlRequest struct {
	Token string `json:"token"`
	Cmd   string `json:"cmd"`
	To    string `json:"to,omitempty"`
	Addr  string `json:"addr,omitempty"`
	Body  string `json:"body,omitempty"`
	Limit int    `json:"limit,omitempty"`
	// Pass and NewPass are only used by change_password / delete_account.
	Pass    string `json:"pass,omitempty"`
	NewPass string `json:"new_pass,omitempty"`
}

type controlResponse struct {
	OK     bool     `json:"ok"`
	Error  string   `json:"error,omitempty"`
	Status string   `json:"status,omitempty"`
	Users  []string `json:"users,omitempty"`
	Lines  []string `json:"lines,omitempty"`
	// Queued (on send) means the contact couldn't be reached and the message
	// waits in the outbox; Error says why.
	Queued bool `json:"queued,omitempty"`
	// Mailed (on send) means the contact couldn't be reached and the message
	// was sealed and left in their server mailbox; Error says why.
	Mailed bool `json:"mailed,omitempty"`
}

const maxControlRequest = 64 * 1024

func controlPort(cfg *storage.Config) int {
	if cfg.ControlPort != 0 {
		return cfg.ControlPort
	}
	port := cfg.Port
	if port == 0 {
		port = storage.DefaultPort
	}
	if port+10000 > 65535 {
		return port - 10000
	}
	return port + 10000
}

func controlAddr(cfg *storage.Config) string {
	return fmt.Sprintf("127.0.0.1:%d", controlPort(cfg))
}

// Any local process can reach the control port, but only one that can read
// the token file (private to this OS user) is allowed to use it.
func newControlToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func saveControlToken(token string) error {
	if err := os.MkdirAll(storage.GetBaseConfigDir(), 0700); err != nil {
		return err
	}
	return os.WriteFile(storage.GetControlTokenPath(), []byte(token), 0600)
}

func readControlToken() string {
	data, err := os.ReadFile(storage.GetControlTokenPath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func backgroundCall(cfg *storage.Config, req controlRequest) (controlResponse, error) {
	var resp controlResponse
	req.Token = readControlToken()
	if req.Token == "" {
		return resp, errors.New("background not running (no control token)")
	}
	conn, err := net.DialTimeout("tcp", controlAddr(cfg), 500*time.Millisecond)
	if err != nil {
		return resp, err
	}
	defer conn.Close()
	// A send may try a LAN address and then the public one, each waiting
	// for the peer's ack.
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return resp, err
	}
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return resp, err
	}
	if !resp.OK {
		if resp.Error == "" {
			resp.Error = "background rejected request"
		}
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}

func backgroundRequest(cfg *storage.Config, req controlRequest) error {
	_, err := backgroundCall(cfg, req)
	return err
}

// subscribeControl streams events from the background process until
// onEvent returns false or the connection ends.
func subscribeControl(cfg *storage.Config, onEvent func(controlEvent) bool) error {
	token := readControlToken()
	if token == "" {
		return errors.New("background not running (no control token)")
	}
	conn, err := net.DialTimeout("tcp", controlAddr(cfg), time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(controlRequest{Token: token, Cmd: "subscribe"}); err != nil {
		return err
	}
	dec := json.NewDecoder(conn)
	var first controlResponse
	if err := dec.Decode(&first); err != nil {
		return err
	}
	if !first.OK {
		return errors.New(first.Error)
	}
	if first.Status != "" && !onEvent(controlEvent{Type: "status", Status: first.Status}) {
		return nil
	}
	for {
		var ev controlEvent
		if err := dec.Decode(&ev); err != nil {
			return err
		}
		if !onEvent(ev) {
			return nil
		}
	}
}

func backgroundRunning(cfg *storage.Config) bool {
	return backgroundRequest(cfg, controlRequest{Cmd: "ping"}) == nil
}

func serveBackgroundControl(token string, n *node) error {
	ln, err := net.Listen("tcp", controlAddr(n.cfg))
	if err != nil {
		return err
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleControlConn(conn, token, n)
		}
	}()
	return nil
}

func handleControlConn(conn net.Conn, token string, n *node) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
	send := func(resp controlResponse) { _ = json.NewEncoder(conn).Encode(resp) }
	reply := func(err error) {
		resp := controlResponse{OK: err == nil}
		if err != nil {
			resp.Error = err.Error()
		}
		send(resp)
	}

	var req controlRequest
	if err := json.NewDecoder(io.LimitReader(conn, maxControlRequest)).Decode(&req); err != nil {
		reply(err)
		return
	}
	if subtle.ConstantTimeCompare([]byte(req.Token), []byte(token)) != 1 {
		reply(errors.New("bad control token"))
		return
	}
	switch req.Cmd {
	case "ping":
		reply(nil)
	case "stop":
		reply(nil)
		go func() {
			time.Sleep(100 * time.Millisecond)
			n.prepareExit()
			os.Exit(0)
		}()
	case "send":
		switch how, err := n.send(req.To, req.Addr, req.Body); how {
		case sendQueued:
			send(controlResponse{OK: true, Queued: true, Error: err.Error()})
		case sendMailed:
			send(controlResponse{OK: true, Mailed: true, Error: err.Error()})
		default:
			reply(err)
		}
	case "online":
		status, users := n.directoryStatus()
		send(controlResponse{OK: true, Status: status, Users: users})
	case "portmap":
		if why := n.cfg.PortMappingOff(); why != "" {
			reply(errors.New("port forwarding is off: " + why))
			return
		}
		if n.dir == nil {
			reply(errors.New("port forwarding is off: no server configured"))
			return
		}
		if ok, report := n.mapPort(); ok {
			send(controlResponse{OK: true, Status: report})
		} else {
			reply(errors.New(report))
		}
	case "change_password", "delete_account":
		if n.dir == nil || !n.dir.Connected() {
			reply(errors.New("not connected to a server"))
			return
		}
		if req.Cmd == "change_password" {
			reply(n.dir.ChangePassword(req.Pass, req.NewPass))
		} else {
			reply(n.dir.DeleteAccount(req.Pass))
		}
	case "history":
		if req.To == "" {
			reply(errors.New(`history needs "to"`))
			return
		}
		lines, err := storage.ReadHistory(req.To)
		if err != nil {
			reply(err)
			return
		}
		if req.Limit > 0 && len(lines) > req.Limit {
			lines = lines[len(lines)-req.Limit:]
		}
		send(controlResponse{OK: true, Lines: lines})
	case "subscribe":
		events, unsubscribe, err := n.events.subscribe()
		if err != nil {
			reply(err)
			return
		}
		defer unsubscribe()
		_ = conn.SetDeadline(time.Time{}) // the stream stays open
		status, _ := n.directoryStatus()
		send(controlResponse{OK: true, Status: status})
		enc := json.NewEncoder(conn)
		for ev := range events {
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if enc.Encode(ev) != nil {
				return // subscriber went away
			}
		}
	default:
		reply(errors.New("unknown command"))
	}
}

// recordIncoming files an authenticated message under its sender's chat.
func recordIncoming(msg network.IncomingMessage) (chat, line string) {
	chat, err := storage.ResolveIncoming(msg.PeerID, msg.Name, msg.Addr)
	if err != nil || chat == "" {
		chat = "peer-" + identity.Short(msg.PeerID)
	}
	line = fmt.Sprintf("%s: %s", chat, storage.CleanText(msg.Body))
	if late := time.Since(msg.Sent); late > 2*time.Minute && msg.Sent.Year() > 2000 {
		line += "  (sent " + msg.Sent.Local().Format("Jan 2 15:04") + ")"
	}
	_ = storage.AppendHistory(chat, line)
	return chat, line
}

func loadIdentity() (*identity.Identity, error) {
	return identity.LoadOrCreate(storage.GetIdentityPath())
}

// knownAddr is a contact's fixed address from config, else the address it
// was last reached at.
func knownAddr(cfg *storage.Config, name string) string {
	for _, c := range cfg.Contacts {
		if strings.EqualFold(c.Name, name) && c.Addr != "" {
			return c.Addr
		}
	}
	return pinnedAddr(name)
}

func pinnedAddr(name string) string {
	if p, ok := storage.PeerByName(name); ok {
		return p.Addr
	}
	return ""
}

func initialModel(cfg *storage.Config, forceChatUser, forceChatAddr string) model {
	contacts := collectContacts(cfg)
	seenMod := make(map[string]time.Time, len(contacts))
	for _, c := range contacts {
		seenMod[c.Username] = storage.GetLastModified(c.Username)
	}
	m := model{state: StateListView, contacts: contacts, cfg: cfg, seenMod: seenMod}
	id, idErr := loadIdentity()
	if idErr == nil {
		m.selfID = id.ID
	}
	if backgroundRunning(cfg) {
		m.useBackground = true
		m.statusLine = "using background process at " + controlAddr(cfg)
	} else if idErr != nil {
		m.statusLine = "menu-only: identity: " + idErr.Error()
	} else if n, err := startNode(cfg, id); err != nil {
		m.statusLine = "menu-only: " + err.Error()
	} else {
		m.node = n
		n.startPortMapping()
		m.statusLine = fmt.Sprintf("listening UDP/%d as %s", cfg.Port, identity.Short(id.ID))
	}
	if forceChatUser != "" && forceChatAddr != "" {
		m.upsertContact(Contact{Username: forceChatUser, Addr: forceChatAddr, Online: true, IsManual: true})
		m.openChat(forceChatUser)
	}
	return m
}

func collectContacts(cfg *storage.Config) []Contact {
	contacts := make([]Contact, 0, len(cfg.Contacts)+8)
	seen := map[string]bool{}
	for _, c := range cfg.Contacts {
		if c.Name == "" {
			continue
		}
		addr := c.Addr
		if addr == "" {
			addr = pinnedAddr(c.Name)
		}
		contacts = append(contacts, Contact{Username: c.Name, Addr: addr, Online: c.Addr != "", IsManual: c.Addr != ""})
		seen[c.Name] = true
	}
	return mergeHistoryContacts(contacts, seen)
}

func mergeHistoryContacts(contacts []Contact, seen map[string]bool) []Contact {
	if seen == nil {
		seen = map[string]bool{}
		for _, c := range contacts {
			seen[c.Username] = true
		}
	}
	if histories, err := storage.ListHistoryContacts(); err == nil {
		for _, h := range histories {
			if h.Name != "" && !seen[h.Name] {
				contacts = append(contacts, Contact{Username: h.Name, Addr: pinnedAddr(h.Name), Online: false})
				seen[h.Name] = true
			}
		}
	}
	return contacts
}

func (m model) Init() tea.Cmd {
	cmds := []tea.Cmd{m.refreshDirectory(), tick()}
	if m.node != nil {
		cmds = append(cmds, m.listenForMessages())
	}
	return tea.Batch(cmds...)
}

func tick() tea.Cmd {
	return tea.Tick(5*time.Second, func(t time.Time) tea.Msg { return msgTick(t) })
}

func (m model) listenForMessages() tea.Cmd {
	return func() tea.Msg { return msgIncomingChat(<-m.node.nm.MessageChan) }
}

// refreshDirectory asks the server (directly, or through the background
// process) who is online. It no longer looks up every contact: addresses
// are fetched only when you send, which is also when punching happens.
func (m model) refreshDirectory() tea.Cmd {
	cfg, n, useBackground := m.cfg, m.node, m.useBackground
	contacts := mergeHistoryContacts(append([]Contact(nil), m.contacts...), nil)
	return func() tea.Msg {
		var status string
		var online []string
		switch {
		case useBackground:
			resp, err := backgroundCall(cfg, controlRequest{Cmd: "online"})
			if err != nil {
				status = "background: " + err.Error()
			} else {
				status, online = resp.Status, resp.Users
			}
		case n != nil:
			status, online = n.directoryStatus()
		default:
			status = "no listener; cannot reach the server"
		}
		isOnline := map[string]bool{}
		for _, u := range online {
			isOnline[strings.ToLower(u)] = true
		}
		known := map[string]bool{}
		for i := range contacts {
			known[strings.ToLower(contacts[i].Username)] = true
			if !contacts[i].IsManual {
				contacts[i].Online = isOnline[strings.ToLower(contacts[i].Username)]
			}
		}
		for _, u := range online {
			if !known[strings.ToLower(u)] {
				contacts = append(contacts, Contact{Username: u, Online: true})
			}
		}
		return msgDirectory{status: status, contacts: contacts}
	}
}

func (m *model) upsertContact(c Contact) {
	for i := range m.contacts {
		if m.contacts[i].Username == c.Username {
			if c.Addr != "" {
				m.contacts[i].Addr = c.Addr
			}
			m.contacts[i].Online = c.Online
			m.contacts[i].Unread = m.contacts[i].Unread || c.Unread
			m.contacts[i].IsManual = m.contacts[i].IsManual || c.IsManual
			return
		}
	}
	m.contacts = append(m.contacts, c)
}

func (m *model) openChat(name string) {
	m.activeContact = name
	m.state = StateChatView
	m.chatHistory, _ = storage.ReadHistory(name)
	if m.seenMod == nil {
		m.seenMod = map[string]time.Time{}
	}
	m.seenMod[name] = storage.GetLastModified(name)
	for i := range m.contacts {
		if m.contacts[i].Username == name {
			m.contacts[i].Unread = false
			break
		}
	}
}

func (m model) selfAddr() string {
	port := m.cfg.Port
	if port == 0 {
		port = storage.DefaultPort
	}
	return fmt.Sprintf("127.0.0.1:%d", port)
}

func senderName(cfg *storage.Config) string {
	if cfg != nil && strings.TrimSpace(cfg.Username) != "" {
		return strings.TrimSpace(cfg.Username)
	}
	if host, err := os.Hostname(); err == nil && strings.TrimSpace(host) != "" {
		return strings.TrimSpace(host)
	}
	return "tarion-peer"
}

func (m model) isSelfChat(name string) bool {
	name = strings.TrimSpace(strings.ToLower(name))
	if name == "self" || name == "myself" || name == "me" {
		return true
	}
	return m.cfg != nil && m.cfg.Username != "" && name == strings.ToLower(m.cfg.Username)
}

func (m model) targetAddrFor(name string) string {
	for _, c := range m.contacts {
		if c.Username == name {
			if c.Addr != "" {
				return c.Addr
			}
			break
		}
	}
	if m.isSelfChat(name) {
		return m.selfAddr()
	}
	return pinnedAddr(name)
}

func (m model) sendCmd(to, addr, body string) tea.Cmd {
	cfg, n, useBackground := m.cfg, m.node, m.useBackground
	return func() tea.Msg {
		var err error
		how := sendFailed
		switch {
		case useBackground:
			var resp controlResponse
			resp, err = backgroundCall(cfg, controlRequest{Cmd: "send", To: to, Addr: addr, Body: body})
			switch {
			case resp.Queued:
				how, err = sendQueued, errors.New(resp.Error)
			case resp.Mailed:
				how, err = sendMailed, errors.New(resp.Error)
			case err == nil:
				how = sendDelivered
			}
		case n != nil:
			how, err = n.send(to, addr, body)
		default:
			err = errors.New("not connected: no listener and no background process")
		}
		return msgSendResult{to: to, err: err, how: how}
	}
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch m.state {
		case StateListView:
			switch msg.String() {
			case "ctrl+c", "q":
				return m, tea.Quit
			case "h", "?":
				m.state = StateHelpView
			case "r":
				return m, m.refreshDirectory()
			case "up", "k":
				if m.cursor > 0 {
					m.cursor--
				}
			case "down", "j":
				if m.cursor < len(m.contacts)-1 {
					m.cursor++
				}
			case "enter":
				if len(m.contacts) > 0 {
					m.openChat(m.contacts[m.cursor].Username)
				}
			}
		case StateChatView:
			switch msg.String() {
			case "ctrl+c":
				return m, tea.Quit
			case "esc":
				m.state = StateListView
			case "enter":
				if strings.TrimSpace(m.inputBuffer) != "" {
					text := m.inputBuffer
					line := "Me: " + storage.CleanText(text)
					m.chatHistory = append(m.chatHistory, line)
					_ = storage.AppendHistory(m.activeContact, line)
					m.inputBuffer = ""
					m.statusLine = "sending to " + m.activeContact + "..."
					return m, m.sendCmd(m.activeContact, m.targetAddrFor(m.activeContact), text)
				}
			case "backspace":
				if r := []rune(m.inputBuffer); len(r) > 0 {
					m.inputBuffer = string(r[:len(r)-1])
				}
			default:
				// KeyRunes covers every script (Hebrew, emoji, ...) and pastes.
				if len(m.inputBuffer) < network.MaxBodyBytes {
					switch msg.Type {
					case tea.KeyRunes:
						m.inputBuffer += string(msg.Runes)
					case tea.KeySpace:
						m.inputBuffer += " "
					}
				}
			}
		case StateHelpView:
			switch msg.String() {
			case "esc", "q", "h", "?":
				m.state = StateListView
			}
		}
	case msgIncomingChat:
		incoming := network.IncomingMessage(msg)
		name, line := recordIncoming(incoming)
		viewing := m.state == StateChatView && m.activeContact == name
		addr := incoming.Addr
		if relay.IsAddr(addr) {
			addr = "" // only valid during that relay session
		}
		m.upsertContact(Contact{Username: name, Addr: addr, Online: true, Unread: !viewing})
		if viewing {
			m.chatHistory = append(m.chatHistory, line)
		}
		return m, m.listenForMessages()
	case msgSendResult:
		if msg.how == sendMailed {
			m.statusLine = msg.to + " is not reachable; left a sealed copy in their server mailbox"
			line := "  ✉ left in their server mailbox (" + storage.CleanText(msg.err.Error()) + ")"
			_ = storage.AppendHistory(msg.to, line)
			if m.state == StateChatView && m.activeContact == msg.to {
				m.chatHistory = append(m.chatHistory, line)
			}
		} else if msg.how == sendQueued {
			m.statusLine = "queued for " + msg.to + " (" + msg.err.Error() + "); it will be delivered automatically"
			line := "  … queued: " + storage.CleanText(msg.err.Error()) + "; will retry"
			_ = storage.AppendHistory(msg.to, line)
			if m.state == StateChatView && m.activeContact == msg.to {
				m.chatHistory = append(m.chatHistory, line)
			}
		} else if msg.err != nil {
			m.statusLine = styleError.Render("not delivered to " + msg.to + ": " + msg.err.Error())
			line := "  ! not delivered: " + storage.CleanText(msg.err.Error())
			_ = storage.AppendHistory(msg.to, line)
			if m.state == StateChatView && m.activeContact == msg.to {
				m.chatHistory = append(m.chatHistory, line)
			}
		} else {
			m.statusLine = "delivered to " + msg.to
		}
		return m, nil
	case msgDirectory:
		m.dirStatus = msg.status
		if m.seenMod == nil {
			m.seenMod = map[string]time.Time{}
		}
		for _, c := range msg.contacts {
			mod := storage.GetLastModified(c.Username)
			if seen, ok := m.seenMod[c.Username]; !ok {
				m.seenMod[c.Username] = mod
			} else if !mod.IsZero() && mod.After(seen) && !(m.state == StateChatView && m.activeContact == c.Username) {
				c.Unread = true
			}
			m.upsertContact(c)
		}
		return m, tick()
	case msgTick:
		if m.state == StateChatView && m.activeContact != "" {
			if history, err := storage.ReadHistory(m.activeContact); err == nil {
				m.chatHistory = history
			}
			if m.seenMod == nil {
				m.seenMod = map[string]time.Time{}
			}
			m.seenMod[m.activeContact] = storage.GetLastModified(m.activeContact)
		}
		return m, m.refreshDirectory()
	}
	return m, nil
}

func (m model) View() string {
	switch m.state {
	case StateListView:
		var s strings.Builder
		s.WriteString("\nTARION\n\n")
		if len(m.contacts) == 0 {
			s.WriteString("No contacts yet. Press h for setup/help.\n")
		} else {
			for i, c := range m.contacts {
				status := styleOffline.Render("[offline]")
				if c.Online {
					status = styleOnline.Render("[ONLINE]")
				}
				newIndicator := ""
				if c.Unread {
					newIndicator = styleNew.Render(" [NEW]")
				}
				line := fmt.Sprintf("%-18s %s%s", c.Username, status, newIndicator)
				if i == m.cursor {
					line = styleSelected.Render(line) + " <--"
				}
				s.WriteString(line + "\n")
			}
		}
		s.WriteString("\n(↑/↓ Enter, h help, r refresh, q quit)\n")
		if m.dirStatus != "" {
			s.WriteString(styleDim.Render(m.dirStatus) + "\n")
		}
		if m.statusLine != "" {
			s.WriteString(m.statusLine + "\n")
		}
		return styleBorder.Render(s.String())
	case StateChatView:
		var s strings.Builder
		s.WriteString(fmt.Sprintf("Chatting with %s  (Esc: menu)\n", m.activeContact))
		s.WriteString("--------------------------------\n")
		for _, line := range m.chatHistory {
			s.WriteString(line + "\n")
		}
		s.WriteString("--------------------------------\n")
		s.WriteString(styleInput.Render("> " + m.inputBuffer + "_"))
		if m.statusLine != "" {
			s.WriteString("\n" + m.statusLine)
		}
		return styleBorder.Render(s.String())
	case StateHelpView:
		return styleBorder.Render(helpText(m))
	}
	return ""
}

func helpText(m model) string {
	return strings.Join([]string{
		"\nTARION HELP",
		"",
		"Open menu:",
		"  tarion.exe menu",
		"",
		"Run network process detached:",
		"  tarion.exe background --detach -server SERVER:63425 -user alice -pass secret",
		"  Then use tarion.exe menu to read/send through that background process.",
		"  Stop it with: tarion.exe stop",
		"",
		"Start connected client:",
		"  tarion.exe start -server SERVER:63425 -user alice -pass secret",
		"  (-pass is only needed the first time on each device)",
		"",
		"Ports (all configurable):",
		fmt.Sprintf("  chat + server traffic: UDP/%d  (-p)", m.cfg.Port),
		fmt.Sprintf("  background control:    TCP/%d  (-cp)", controlPort(m.cfg)),
		"  server:                set in -server host:port (tariond default 63425)",
		"",
		"Direct/self test chat:",
		fmt.Sprintf("  tarion.exe start -u Myself -i 127.0.0.1:%d", m.cfg.Port),
		"",
		"Config file:",
		"  " + storage.GetConfigPath(),
		"",
		"History folder:",
		"  " + storage.GetHistoryDir(),
		"",
		"Your peer ID (share it so contacts can verify you):",
		"  " + identity.Fingerprint(m.selfID),
		"",
		"Server:",
		"  " + m.dirStatus,
		"Status:",
		"  " + m.statusLine,
		"",
		"Controls: Enter open/send, Esc back, r refresh, h help, q quit.",
	}, "\n")
}

func backgroundLogPath() string {
	return storage.GetBaseConfigDir() + string(os.PathSeparator) + "background.log"
}

func setBackgroundUsage(fs *flag.FlagSet) {
	fs.Usage = func() {
		out := fs.Output()
		fmt.Fprintln(out, "Usage: tarion background [options]")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Starts Tarion's always-on network listener and server session.")
		fmt.Fprintln(out, "Use --detach to keep it running after the terminal closes on Windows/Linux.")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Examples:")
		fmt.Fprintln(out, "  tarion background --detach")
		fmt.Fprintln(out, "  tarion background --detach -server SERVER:63425 -user alice -pass secret")
		fmt.Fprintln(out, "  tarion menu")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Stop background process:")
		fmt.Fprintln(out, "  tarion stop")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Logs:")
		fmt.Fprintf(out, "  %s\n", backgroundLogPath())
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Options:")
		fs.PrintDefaults()
	}
}

func setStopUsage(fs *flag.FlagSet) {
	fs.Usage = func() {
		out := fs.Output()
		fmt.Fprintln(out, "Usage: tarion stop [options]")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Stops the Tarion background process started with:")
		fmt.Fprintln(out, "  tarion background --detach")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Ports come from config.json; pass -p/-cp only to override them.")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Options:")
		fs.PrintDefaults()
	}
}

// clientFlags are the settings shared by start, menu and background.
type clientFlags struct {
	port, ctrl                                     *int
	server, user, pass, invite, accept             *string
	serverBans, relayMode, publicAddr, portMapping *string
	mailbox                                        *string
}

func addClientFlags(fs *flag.FlagSet) clientFlags {
	return clientFlags{
		port:        fs.Int("p", 0, fmt.Sprintf("local UDP port for chat and server traffic (default %d)", storage.DefaultPort)),
		ctrl:        fs.Int("cp", 0, "local TCP port of the background control socket (default: -p plus 10000)"),
		server:      fs.String("server", "", fmt.Sprintf("directory server host:port (tariond default port %d)", directory.DefaultServerPort)),
		user:        fs.String("user", "", "directory username"),
		pass:        fs.String("pass", "", "directory password (only needed the first time on this device)"),
		invite:      fs.String("invite", "", "one-time invite code, if the server is invite-only"),
		accept:      fs.String("accept", "", "who may message you: anyone or contacts (saved)"),
		serverBans:  fs.String("server-bans", "", "on (default) or off: refuse keys the server banned (saved)"),
		relayMode:   fs.String("relay", "", "off (default) or on: allow messages through the server when no direct path exists (saved)"),
		publicAddr:  fs.String("public-addr", "", `address peers can reach you at directly, e.g. a forwarded port "203.0.113.7:63426"; "none" clears it (saved)`),
		portMapping: fs.String("port-mapping", "", "auto (default: ask the router to forward the port when the relay is off), on, or off (saved)"),
		mailbox:     fs.String("mailbox", "", "off (default) or on: let the server hold sealed messages while you or a contact are offline (saved)"),
	}
}

// apply merges flags into the saved config and validates it.
func (f clientFlags) apply(cfg *storage.Config) error {
	if *f.server != "" {
		cfg.ServerAddr = *f.server
	}
	if *f.user != "" {
		cfg.Username = *f.user
	}
	if *f.pass != "" {
		cfg.Password = *f.pass
	}
	if f.invite != nil && *f.invite != "" {
		cfg.Invite = *f.invite
	}
	if f.accept != nil && *f.accept != "" {
		cfg.Accept = *f.accept
	}
	switch cfg.Accept {
	case "", "anyone", "contacts":
	default:
		return errors.New(`-accept must be "anyone" or "contacts"`)
	}
	if f.serverBans != nil && *f.serverBans != "" {
		cfg.ServerBans = *f.serverBans
	}
	if f.relayMode != nil && *f.relayMode != "" {
		cfg.Relay = *f.relayMode
	}
	if f.mailbox != nil && *f.mailbox != "" {
		cfg.Mailbox = *f.mailbox
	}
	for name, v := range map[string]string{"-server-bans": cfg.ServerBans, "-relay": cfg.Relay, "-mailbox": cfg.Mailbox} {
		if v != "" && v != "on" && v != "off" {
			return fmt.Errorf(`%s must be "on" or "off"`, name)
		}
	}
	if f.portMapping != nil && *f.portMapping != "" {
		cfg.PortMapping = *f.portMapping
	}
	switch cfg.PortMapping {
	case "", "auto", "on", "off":
	default:
		return errors.New(`-port-mapping must be "auto", "on" or "off"`)
	}
	if f.publicAddr != nil && *f.publicAddr != "" {
		cfg.PublicAddr = *f.publicAddr
		if cfg.PublicAddr == "none" {
			cfg.PublicAddr = ""
		}
	}
	if cfg.PublicAddr != "" && !directory.ValidPublicAddr(cfg.PublicAddr) {
		return errors.New(`-public-addr must be "host:port" (an IP or DNS name)`)
	}
	if *f.port != 0 {
		cfg.Port = *f.port
	}
	if *f.ctrl != 0 {
		cfg.ControlPort = *f.ctrl
	}
	if cfg.Port == 0 {
		cfg.Port = storage.DefaultPort
	}
	for _, p := range []int{cfg.Port, cfg.ControlPort} {
		if p < 0 || p > 65535 {
			return fmt.Errorf("port %d out of range", p)
		}
	}
	if cfg.ServerAddr != "" {
		if _, _, err := net.SplitHostPort(cfg.ServerAddr); err != nil {
			return fmt.Errorf("server must be host:port: %w", err)
		}
	}
	if cfg.Username != "" && !directory.ValidUsername(cfg.Username) {
		return errors.New("username must be 1-32 letters or digits and may contain . _ -")
	}
	return nil
}

func runStop(args []string) error {
	fs := flag.NewFlagSet("stop", flag.ExitOnError)
	setStopUsage(fs)
	portFlag := fs.Int("p", 0, "local UDP port the background uses")
	ctrlFlag := fs.Int("cp", 0, "background control TCP port")
	_ = fs.Parse(args)

	cfg, _ := storage.LoadOrCreateConfig()
	if *portFlag != 0 {
		cfg.Port = *portFlag
	}
	if *ctrlFlag != 0 {
		cfg.ControlPort = *ctrlFlag
	}
	return backgroundRequest(cfg, controlRequest{Cmd: "stop"})
}

func runBackground(args []string) error {
	fs := flag.NewFlagSet("background", flag.ExitOnError)
	setBackgroundUsage(fs)
	flags := addClientFlags(fs)
	detachFlag := fs.Bool("detach", false, "start detached so it survives terminal close")
	_ = fs.Parse(args)

	cfg, err := storage.LoadOrCreateConfig()
	if err != nil {
		return err
	}
	if err := flags.apply(cfg); err != nil {
		return err
	}
	if err := storage.SaveConfig(cfg); err != nil {
		return err
	}

	if *detachFlag && os.Getenv("TARION_BACKGROUND_CHILD") != "1" {
		// Settings were saved above; the child reads them from config so the
		// password never appears in its command line.
		detachedArgs := append([]string{"background"}, fs.Args()...)
		if err := startDetached(detachedArgs, backgroundLogPath()); err != nil {
			return err
		}
		fmt.Printf("tarion background detached; log %s\n", backgroundLogPath())
		return nil
	}

	id, err := loadIdentity()
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}
	n, err := startNode(cfg, id)
	if err != nil {
		return err
	}
	defer n.close()
	token, err := newControlToken()
	if err != nil {
		return err
	}
	if err := serveBackgroundControl(token, n); err != nil {
		return fmt.Errorf("start background control at %s: %w", controlAddr(cfg), err)
	}
	if err := saveControlToken(token); err != nil {
		return fmt.Errorf("save control token: %w", err)
	}
	fmt.Printf("tarion background listening on UDP/%d as %s; control %s\n", cfg.Port, identity.Short(id.ID), controlAddr(cfg))

	go n.serveIncoming(func(chat string, msg network.IncomingMessage) {
		via := msg.Addr
		if via == "" {
			via = "via the server mailbox"
		}
		fmt.Printf("new message from %s (%s, id %s)\n", chat, via, identity.Short(msg.PeerID))
	})
	go n.watchStatus(func(s string) { fmt.Println(s) })
	n.setLogger(func(s string) { fmt.Println(s) })
	n.startPortMapping()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	_ = os.Remove(storage.GetControlTokenPath())
	return nil
}

func runStart(args []string) error {
	fs := flag.NewFlagSet("start", flag.ExitOnError)
	userFlag := fs.String("u", "", "display name for a direct-IP chat")
	ipFlag := fs.String("i", "", "peer IP:port for a direct-IP chat")
	flags := addClientFlags(fs)
	wipeFlag := fs.Bool("wipe-history", false, "delete all local Tarion chat history and exit")
	_ = fs.Parse(args)

	if *wipeFlag {
		if err := storage.DeleteAllHistory(); err != nil {
			return err
		}
		fmt.Println("Tarion history wiped:", storage.GetHistoryDir())
		return nil
	}

	cfg, err := storage.LoadOrCreateConfig()
	if err != nil {
		return err
	}
	if err := flags.apply(cfg); err != nil {
		return err
	}
	if err := storage.SaveConfig(cfg); err != nil {
		return err
	}

	m := initialModel(cfg, *userFlag, *ipFlag)
	if m.node != nil {
		defer m.node.close()
	}
	_, err = tea.NewProgram(m).Run()
	return err
}

// runSend sends one message through the running background process, for
// scripts and quick tests: tarion send bob "hello".
func runSend(args []string) error {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	portFlag := fs.Int("p", 0, "local UDP port the background uses")
	ctrlFlag := fs.Int("cp", 0, "background control TCP port")
	_ = fs.Parse(args)
	rest := fs.Args()
	if len(rest) < 2 {
		return errors.New("usage: tarion send <name> <message>")
	}
	cfg, err := storage.LoadOrCreateConfig()
	if err != nil {
		return err
	}
	if *portFlag != 0 {
		cfg.Port = *portFlag
	}
	if *ctrlFlag != 0 {
		cfg.ControlPort = *ctrlFlag
	}
	to, body := rest[0], strings.Join(rest[1:], " ")
	if !backgroundRunning(cfg) {
		return errors.New("no background process running; start one with: tarion background --detach")
	}
	resp, err := backgroundCall(cfg, controlRequest{Cmd: "send", To: to, Body: body})
	if err != nil {
		return fmt.Errorf("not delivered to %s: %w", to, err)
	}
	_ = storage.AppendHistory(to, "Me: "+storage.CleanText(body))
	if resp.Queued {
		_ = storage.AppendHistory(to, "  … queued: "+storage.CleanText(resp.Error)+"; will retry")
		fmt.Printf("queued for %s (%s); the background process delivers it when they can be reached\n", to, resp.Error)
		return nil
	}
	if resp.Mailed {
		_ = storage.AppendHistory(to, "  ✉ left in their server mailbox ("+storage.CleanText(resp.Error)+")")
		fmt.Printf("%s is not reachable (%s); left a sealed copy in their server mailbox\n", to, resp.Error)
		return nil
	}
	fmt.Println("delivered to", to)
	return nil
}

// portFlags adds -p/-cp for commands that only talk to the background.
func portFlags(fs *flag.FlagSet) func(*storage.Config) {
	port := fs.Int("p", 0, "local UDP port the background uses")
	ctrl := fs.Int("cp", 0, "background control TCP port")
	return func(cfg *storage.Config) {
		if *port != 0 {
			cfg.Port = *port
		}
		if *ctrl != 0 {
			cfg.ControlPort = *ctrl
		}
	}
}

// runListen prints every incoming message (and server status change) from
// the background process as one JSON object per line, for scripts and bots.
func runListen(args []string) error {
	fs := flag.NewFlagSet("listen", flag.ExitOnError)
	apply := portFlags(fs)
	_ = fs.Parse(args)
	cfg, err := storage.LoadOrCreateConfig()
	if err != nil {
		return err
	}
	apply(cfg)
	out := json.NewEncoder(os.Stdout)
	return subscribeControl(cfg, func(ev controlEvent) bool {
		return out.Encode(ev) == nil
	})
}

// runHistory prints a chat's saved history.
func runHistory(args []string) error {
	fs := flag.NewFlagSet("history", flag.ExitOnError)
	n := fs.Int("n", 20, "how many recent lines (0 = all)")
	rest := parseInterspersed(fs, args)
	if len(rest) != 1 {
		return errors.New("usage: tarion history [-n 20] <name>")
	}
	lines, err := storage.ReadHistory(rest[0])
	if err != nil {
		return err
	}
	if *n > 0 && len(lines) > *n {
		lines = lines[len(lines)-*n:]
	}
	for _, l := range lines {
		fmt.Println(l)
	}
	return nil
}

// parseInterspersed parses flags that may come before or after positional
// arguments ("tariond ban bob -data /srv" as well as "-data /srv bob"); the
// standard flag package stops at the first positional one.
func parseInterspersed(fs *flag.FlagSet, args []string) []string {
	var positional []string
	for {
		_ = fs.Parse(args)
		if fs.NArg() == 0 {
			return positional
		}
		positional = append(positional, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

var stdinLines = bufio.NewReader(os.Stdin)

// readSecret prompts on stderr and reads without echo from a terminal, or a
// plain line when input is piped (for scripts).
func readSecret(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	if fd := int(os.Stdin.Fd()); term.IsTerminal(fd) {
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		return string(b), err
	}
	return readLine("")
}

func readLine(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	line, err := stdinLines.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// runAccountOp performs an account operation through the background
// process if one is running (it owns the server session), or else logs in
// briefly with this device's key.
func runAccountOp(cfg *storage.Config, ctl controlRequest, op func(*directory.Client) error) error {
	if backgroundRunning(cfg) {
		return backgroundRequest(cfg, ctl)
	}
	if cfg.ServerAddr == "" || cfg.Username == "" {
		return errors.New("no server account configured (log in once with -server and -user)")
	}
	id, err := loadIdentity()
	if err != nil {
		return err
	}
	n, err := startNode(cfg, id)
	if err != nil {
		return err
	}
	defer n.close()
	for deadline := time.Now().Add(15 * time.Second); !n.dir.Connected(); time.Sleep(100 * time.Millisecond) {
		if time.Now().After(deadline) {
			return fmt.Errorf("could not log in: %s", n.dir.Status())
		}
	}
	return op(n.dir)
}

func runPasswd(args []string) error {
	fs := flag.NewFlagSet("passwd", flag.ExitOnError)
	apply := portFlags(fs)
	_ = fs.Parse(args)
	cfg, err := storage.LoadOrCreateConfig()
	if err != nil {
		return err
	}
	apply(cfg)
	oldPass, err := readSecret("Current password: ")
	if err != nil {
		return err
	}
	newPass, err := readSecret("New password: ")
	if err != nil {
		return err
	}
	again, err := readSecret("Repeat new password: ")
	if err != nil {
		return err
	}
	if newPass != again {
		return errors.New("the new passwords don't match")
	}
	err = runAccountOp(cfg, controlRequest{Cmd: "change_password", Pass: oldPass, NewPass: newPass},
		func(d *directory.Client) error { return d.ChangePassword(oldPass, newPass) })
	if err != nil {
		return err
	}
	fmt.Println("Password changed.")
	return nil
}

func runDeleteAccount(args []string) error {
	fs := flag.NewFlagSet("delete-account", flag.ExitOnError)
	apply := portFlags(fs)
	_ = fs.Parse(args)
	cfg, err := storage.LoadOrCreateConfig()
	if err != nil {
		return err
	}
	apply(cfg)
	if cfg.Username == "" {
		return errors.New("no account configured")
	}
	confirm, err := readLine(fmt.Sprintf("This deletes the account %q on %s. Type the username to confirm: ", cfg.Username, cfg.ServerAddr))
	if err != nil {
		return err
	}
	if confirm != cfg.Username {
		return errors.New("username did not match; nothing deleted")
	}
	pass, err := readSecret("Password: ")
	if err != nil {
		return err
	}
	err = runAccountOp(cfg, controlRequest{Cmd: "delete_account", Pass: pass},
		func(d *directory.Client) error { return d.DeleteAccount(pass) })
	if err != nil {
		return err
	}
	_ = storage.UpdateConfig(func(c *storage.Config) { c.Username, c.Password, c.Invite = "", "", "" })
	fmt.Println("Account deleted. Your history and identity key on this device were kept.")
	if backgroundRunning(cfg) {
		fmt.Println("The background process is still running without an account; stop it with: tarion stop")
	}
	return nil
}

// runPortmap retries automatic port forwarding now, with the saved
// settings, and explains the result.
func runPortmap(args []string) error {
	fs := flag.NewFlagSet("portmap", flag.ExitOnError)
	apply := portFlags(fs)
	_ = fs.Parse(args)
	cfg, err := storage.LoadOrCreateConfig()
	if err != nil {
		return err
	}
	apply(cfg)
	if why := cfg.PortMappingOff(); why != "" {
		fmt.Println("Port forwarding is off: " + why + ".")
		return nil
	}
	fmt.Printf("Asking your router to forward UDP port %d (UPnP, then NAT-PMP); this takes a few seconds...\n", cfg.Port)
	if backgroundRunning(cfg) {
		resp, err := backgroundCall(cfg, controlRequest{Cmd: "portmap"})
		if err != nil {
			return err
		}
		fmt.Println(resp.Status)
		return nil
	}
	// No background process: check once here, then undo it, since
	// nothing will be listening on the port afterwards.
	id, err := loadIdentity()
	if err != nil {
		return err
	}
	n, err := startNode(cfg, id)
	if err != nil {
		return fmt.Errorf("%w (is another Tarion using UDP %d?)", err, cfg.Port)
	}
	defer n.close()
	for deadline := time.Now().Add(15 * time.Second); !n.dir.Connected(); time.Sleep(100 * time.Millisecond) {
		if time.Now().After(deadline) {
			return fmt.Errorf("could not log in to the server to test it: %s", n.dir.Status())
		}
	}
	ok, report := n.mapPort()
	if !ok {
		return errors.New(report)
	}
	fmt.Println(report)
	fmt.Println("This was a test without the background process, so the forwarding is removed again; the background process sets it up by itself.")
	return nil
}

// runOutbox lists messages waiting to be delivered.
func runOutbox(args []string) error {
	fs := flag.NewFlagSet("outbox", flag.ExitOnError)
	_ = fs.Parse(args)
	items, err := storage.Outbox()
	if err != nil {
		return err
	}
	if len(items) == 0 {
		fmt.Println("Nothing is waiting to be delivered.")
		return nil
	}
	now := time.Now()
	for _, it := range items {
		fmt.Printf("to %-16s queued %s ago, %d tries, next %s\n    %s\n    last error: %s\n",
			it.To, now.Sub(it.Created).Round(time.Second), it.Attempts, nextTry(it.NextTry, now),
			snippet(it.Body), storage.CleanText(it.LastError))
	}
	fmt.Printf("%d waiting. The background process (or open menu) retries them for up to 7 days.\n", len(items))
	return nil
}

func nextTry(t, now time.Time) string {
	if !t.After(now) {
		return "now"
	}
	return "in " + t.Sub(now).Round(time.Second).String()
}

// runDropped lists messages that were given up on or refused.
func runDropped(args []string) error {
	fs := flag.NewFlagSet("dropped", flag.ExitOnError)
	n := fs.Int("n", 20, "how many recent entries (0 = all)")
	_ = fs.Parse(args)
	entries, err := storage.ReadDropped(*n)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		fmt.Println("No dropped messages.")
		return nil
	}
	for _, d := range entries {
		dir := "to  "
		if d.Dir == "in" {
			dir = "from"
		}
		fmt.Printf("%s  %s %-16s %s\n", d.Time.Local().Format("2006-01-02 15:04"), dir, d.Peer, storage.CleanText(d.Reason))
		if d.Body != "" {
			fmt.Printf("    %s\n", snippet(d.Body))
		}
	}
	return nil
}

func runID() error {
	id, err := loadIdentity()
	if err != nil {
		return err
	}
	fmt.Println("Your Tarion peer ID:")
	fmt.Println("  " + identity.Fingerprint(id.ID))
	fmt.Println()
	fmt.Println("Read it to your contacts over a channel you trust. They can pin it in")
	fmt.Println(storage.GetConfigPath() + " as the contact's \"id\".")
	return nil
}

func runPeers() error {
	peers, err := storage.ListPeers()
	if err != nil {
		return err
	}
	if len(peers) == 0 {
		fmt.Println("No pinned peers yet.")
		return nil
	}
	for _, p := range peers {
		fmt.Printf("%-20s %s  last %s  %s\n", p.Name, identity.Fingerprint(p.ID), p.LastSeen.Format("2006-01-02 15:04"), p.Addr)
	}
	return nil
}

func runForget(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: tarion forget <name>")
	}
	ok, err := storage.ForgetPeer(args[0])
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("no pinned peer named %s", args[0])
	}
	fmt.Printf("Forgot %s. The next key that answers for this name will be pinned.\n", args[0])
	return nil
}

func printGeneralHelp() {
	fmt.Println(strings.Join([]string{
		"Tarion - secure QUIC P2P terminal chat",
		"",
		"Usage:",
		"  tarion [command] [options]",
		"",
		"Commands:",
		"  start       Open the interactive menu/TUI and listen if no background is running",
		"  menu        Open the interactive menu/TUI",
		"  background  Run the always-on listener; use --detach to survive terminal close",
		"  stop        Stop the detached/background listener",
		"  send        Send one message through the background process",
		"  listen      Print incoming messages as JSON lines (for scripts and apps)",
		"  history     Print a chat's recent history",
		"  portmap     Ask the router to forward your port again, and explain the result",
		"  outbox      List messages waiting to be delivered",
		"  dropped     List messages that were given up on or refused",
		"  passwd      Change your account password",
		"  delete-account  Delete your account on the server",
		"  id          Show your peer ID so contacts can verify you",
		"  peers       List pinned contacts and their peer IDs",
		"  forget      Remove a contact's pinned key (after they reinstall)",
		"  help        Show this help",
		"",
		"Command help:",
		"  tarion start -h",
		"  tarion background -h",
		"  tarion stop -h",
		"",
		"Common examples:",
		"  tarion start -server SERVER:63425 -user alice -pass secret",
		"  tarion background --detach",
		"  tarion menu",
		"  tarion send bob \"hello\"",
		"  tarion stop",
		fmt.Sprintf("  tarion start -u Myself -i 127.0.0.1:%d", storage.DefaultPort),
		"",
		fmt.Sprintf("Ports: the client uses one UDP port (default %d, -p) for chat and for", storage.DefaultPort),
		fmt.Sprintf("talking to the server; tariond listens on %d by default.", directory.DefaultServerPort),
	}, "\n"))
}

func main() {
	args := os.Args[1:]
	if len(args) > 0 {
		switch args[0] {
		case "-h", "--help", "help":
			printGeneralHelp()
			return
		}
	}
	cmd := "start"
	if len(args) > 0 {
		switch args[0] {
		case "start", "menu", "background", "stop", "send", "listen", "history", "portmap", "outbox", "dropped", "passwd", "delete-account", "id", "peers", "forget":
			cmd, args = args[0], args[1:]
		}
	}

	var err error
	switch cmd {
	case "background":
		err = runBackground(args)
	case "stop":
		err = runStop(args)
	case "send":
		err = runSend(args)
	case "listen":
		err = runListen(args)
	case "history":
		err = runHistory(args)
	case "portmap":
		err = runPortmap(args)
	case "outbox":
		err = runOutbox(args)
	case "dropped":
		err = runDropped(args)
	case "passwd":
		err = runPasswd(args)
	case "delete-account":
		err = runDeleteAccount(args)
	case "id":
		err = runID()
	case "peers":
		err = runPeers()
	case "forget":
		err = runForget(args)
	case "menu", "start":
		err = runStart(args)
	}
	if err != nil {
		msg := "tarion: " + err.Error()
		if strings.Contains(msg, "\n") {
			// Multi-line explanations: plain text, so the terminal styling
			// doesn't pad every line to the widest one.
			fmt.Fprintln(os.Stderr, strings.TrimRight(msg, "\n"))
		} else {
			fmt.Fprintln(os.Stderr, styleError.Render(msg))
		}
		os.Exit(1)
	}
}
