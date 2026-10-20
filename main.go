package main

import (
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
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/necromancer124/tarion/internal/identity"
	"github.com/necromancer124/tarion/internal/network"
	"github.com/necromancer124/tarion/internal/storage"
)

var (
	styleOnline   = lipgloss.NewStyle().Foreground(lipgloss.Color("2")).Bold(true)
	styleOffline  = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	styleSelected = lipgloss.NewStyle().Background(lipgloss.Color("60")).Foreground(lipgloss.Color("0"))
	styleBorder   = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("240")).Padding(0, 1)
	styleInput    = lipgloss.NewStyle().Foreground(lipgloss.Color("229"))
	styleNew      = lipgloss.NewStyle().Foreground(lipgloss.Color("13")).Bold(true)
	styleError    = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
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
	IsManual bool
}

type model struct {
	state         AppState
	contacts      []Contact
	cursor        int
	activeContact string
	chatHistory   []string
	inputBuffer   string
	statusLine    string
	useBackground bool
	selfID        string
	seenMod       map[string]time.Time
	cfg           *storage.Config
	netMgr        *network.NetworkManager
}

type msgIncomingChat network.IncomingMessage
type msgSendResult struct {
	to  string
	err error
}
type msgDirectory struct {
	status   string
	contacts []Contact
}
type msgTick time.Time

type directoryClient struct {
	server   string
	username string
	password string
}

func newDirectoryClient(cfg *storage.Config) directoryClient {
	return directoryClient{server: cfg.ServerAddr, username: cfg.Username, password: cfg.Password}
}

func (d directoryClient) request(payload string) (string, error) {
	if d.server == "" {
		return "", fmt.Errorf("server not configured")
	}
	addr, err := net.ResolveUDPAddr("udp", d.server)
	if err != nil {
		return "", err
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte(payload)); err != nil {
		return "", err
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

func (d directoryClient) register() error {
	_, err := d.request(fmt.Sprintf("REG|%s|%s", d.username, d.password))
	return err
}

func (d directoryClient) heartbeat() error {
	_, err := d.request(fmt.Sprintf("HBT|%s|%s", d.username, d.password))
	return err
}

func (d directoryClient) query(target string) (string, bool) {
	resp, err := d.request(fmt.Sprintf("QRY|%s|%s|%s", d.username, d.password, target))
	if err != nil || !strings.HasPrefix(resp, "OK|ADDR|") {
		return "", false
	}
	return strings.TrimPrefix(resp, "OK|ADDR|"), true
}

func (d directoryClient) listOnline() []Contact {
	resp, err := d.request(fmt.Sprintf("LST|%s|%s", d.username, d.password))
	if err != nil || !strings.HasPrefix(resp, "OK|USERS|") {
		return nil
	}
	payload := strings.TrimPrefix(resp, "OK|USERS|")
	if payload == "" {
		return nil
	}
	var contacts []Contact
	for _, item := range strings.Split(payload, ",") {
		name, addr, ok := strings.Cut(item, "=")
		if !ok || name == "" || addr == "" || name == d.username {
			continue
		}
		contacts = append(contacts, Contact{Username: name, Addr: addr, Online: true})
	}
	return contacts
}

type controlRequest struct {
	Token string `json:"token"`
	Cmd   string `json:"cmd"`
	To    string `json:"to,omitempty"`
	Addr  string `json:"addr,omitempty"`
	Body  string `json:"body,omitempty"`
}

type controlResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

const maxControlRequest = 64 * 1024

func controlAddr(port int) string {
	if port == 0 {
		port = 63425
	}
	ctrl := port + 10000
	if ctrl > 65535 {
		ctrl = port - 10000
	}
	return fmt.Sprintf("127.0.0.1:%d", ctrl)
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

// validateDirectoryField rejects characters that would break the directory
// server's "CMD|user|pass" text protocol.
func validateDirectoryField(field, value string) error {
	if strings.ContainsAny(value, "|,=\r\n") {
		return fmt.Errorf("%s must not contain | , = or newlines", field)
	}
	return nil
}

func validateDirectoryConfig(cfg *storage.Config) error {
	if err := validateDirectoryField("username", cfg.Username); err != nil {
		return err
	}
	return validateDirectoryField("password", cfg.Password)
}

func readControlToken() string {
	data, err := os.ReadFile(storage.GetControlTokenPath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func backgroundRequest(port int, req controlRequest) error {
	req.Token = readControlToken()
	if req.Token == "" {
		return errors.New("background not running (no control token)")
	}
	conn, err := net.DialTimeout("tcp", controlAddr(port), 500*time.Millisecond)
	if err != nil {
		return err
	}
	defer conn.Close()
	// A send waits for the peer's ack, which can take a full dial + retry.
	_ = conn.SetDeadline(time.Now().Add(25 * time.Second))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return err
	}
	var resp controlResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return err
	}
	if !resp.OK {
		if resp.Error == "" {
			resp.Error = "background rejected request"
		}
		return errors.New(resp.Error)
	}
	return nil
}

func backgroundRunning(port int) bool {
	return backgroundRequest(port, controlRequest{Cmd: "ping"}) == nil
}

func serveBackgroundControl(port int, token string, nm *network.NetworkManager, cfg *storage.Config) error {
	ln, err := net.Listen("tcp", controlAddr(port))
	if err != nil {
		return err
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleControlConn(conn, token, nm, cfg)
		}
	}()
	return nil
}

func handleControlConn(conn net.Conn, token string, nm *network.NetworkManager, cfg *storage.Config) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(25 * time.Second))
	reply := func(err error) {
		resp := controlResponse{OK: err == nil}
		if err != nil {
			resp.Error = err.Error()
		}
		_ = json.NewEncoder(conn).Encode(resp)
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
			_ = os.Remove(storage.GetControlTokenPath())
			os.Exit(0)
		}()
	case "send":
		reply(deliver(nm, cfg, req.To, req.Addr, req.Body))
	default:
		reply(errors.New("unknown command"))
	}
}

// deliver sends body to the contact named to and enforces its identity: a
// key fixed in config or pinned on first contact must match, otherwise
// nothing is written to the connection.
func deliver(nm *network.NetworkManager, cfg *storage.Config, to, addr, body string) error {
	if addr == "" {
		addr = pinnedAddr(to)
	}
	if addr == "" {
		return fmt.Errorf("no address for %s", to)
	}
	configured := ""
	for _, c := range cfg.Contacts {
		if strings.EqualFold(c.Name, to) {
			// Accept the spaced form "tarion id" prints.
			configured = strings.ReplaceAll(strings.TrimSpace(c.ID), " ", "")
		}
	}
	_, err := nm.Send(addr, senderName(cfg), body, func(peerID string) error {
		if configured != "" && !strings.EqualFold(configured, peerID) {
			return &storage.IdentityMismatchError{Name: to, Expected: configured, Got: peerID}
		}
		return storage.PinOutgoing(to, peerID, addr)
	})
	return err
}

// recordIncoming files an authenticated message under its sender's chat.
func recordIncoming(msg network.IncomingMessage) (chat, line string) {
	chat, err := storage.ResolveIncoming(msg.PeerID, msg.Name, msg.Addr)
	if err != nil || chat == "" {
		chat = "peer-" + identity.Short(msg.PeerID)
	}
	line = fmt.Sprintf("%s: %s", chat, storage.CleanText(msg.Body))
	_ = storage.AppendHistory(chat, line)
	return chat, line
}

func loadIdentity() (*identity.Identity, error) {
	return identity.LoadOrCreate(storage.GetIdentityPath())
}

func pinnedAddr(name string) string {
	if p, ok := storage.PeerByName(name); ok {
		return p.Addr
	}
	return ""
}

func initialModel(cfg *storage.Config, forceChatUser, forceChatAddr string, port int) model {
	if port == 0 {
		port = 63425
	}

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
	if backgroundRunning(port) {
		m.useBackground = true
		m.statusLine = "using background listener at " + controlAddr(port)
	} else if idErr != nil {
		m.statusLine = "menu-only: identity: " + idErr.Error()
	} else {
		nm := network.NewNetworkManager(port, id)
		m.netMgr = nm
		m.statusLine = fmt.Sprintf("listening UDP/%d as %s", port, identity.Short(id.ID))
		if err := nm.StartListener(); err != nil {
			m.statusLine = "menu-only: " + err.Error()
			m.netMgr = nil
		}
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
		contacts = append(contacts, Contact{Username: c.Name, Addr: addr, Online: addr != ""})
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
	if !m.useBackground && m.netMgr != nil {
		cmds = append(cmds, m.listenForMessages())
	}
	return tea.Batch(cmds...)
}

func tick() tea.Cmd {
	return tea.Tick(5*time.Second, func(t time.Time) tea.Msg { return msgTick(t) })
}

func (m model) listenForMessages() tea.Cmd {
	return func() tea.Msg { return msgIncomingChat(<-m.netMgr.MessageChan) }
}

func (m model) refreshDirectory() tea.Cmd {
	cfg := *m.cfg
	contacts := mergeHistoryContacts(append([]Contact(nil), m.contacts...), nil)
	return func() tea.Msg {
		if cfg.ServerAddr == "" || cfg.Username == "" || cfg.Password == "" {
			return msgDirectory{status: "offline: configure server_addr, username, password in " + storage.GetConfigPath(), contacts: contacts}
		}
		d := newDirectoryClient(&cfg)
		status := "server connected"
		if err := d.heartbeat(); err != nil {
			if err := d.register(); err != nil {
				status = "server error: " + err.Error()
			}
		}
		for _, listed := range d.listOnline() {
			contacts = append(contacts, listed)
		}
		for i := range contacts {
			if contacts[i].IsManual {
				continue
			}
			addr, ok := d.query(contacts[i].Username)
			contacts[i].Online = ok
			if ok {
				contacts[i].Addr = addr
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
		port = 63425
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
	cfg, nm, useBackground := m.cfg, m.netMgr, m.useBackground
	return func() tea.Msg {
		var err error
		switch {
		case useBackground:
			err = backgroundRequest(cfg.Port, controlRequest{Cmd: "send", To: to, Addr: addr, Body: body})
		case nm != nil:
			err = deliver(nm, cfg, to, addr, body)
		default:
			err = errors.New("not connected: no listener and no background process")
		}
		return msgSendResult{to: to, err: err}
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
					targetAddr := m.targetAddrFor(m.activeContact)
					if targetAddr == "" {
						m.statusLine = "cannot send: no peer address for " + m.activeContact
						break
					}
					line := "Me: " + storage.CleanText(text)
					m.chatHistory = append(m.chatHistory, line)
					_ = storage.AppendHistory(m.activeContact, line)
					m.inputBuffer = ""
					m.statusLine = "sending to " + m.activeContact + "..."
					return m, m.sendCmd(m.activeContact, targetAddr, text)
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
		m.upsertContact(Contact{Username: name, Addr: incoming.Addr, Online: true, Unread: !viewing, IsManual: true})
		if m.state == StateChatView && m.activeContact == name {
			m.chatHistory = append(m.chatHistory, line)
		} else {
			for i := range m.contacts {
				if m.contacts[i].Username == name {
					m.contacts[i].Unread = true
					m.contacts[i].Online = true
				}
			}
		}
		return m, m.listenForMessages()
	case msgSendResult:
		if msg.err != nil {
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
		m.statusLine = msg.status
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
		"  tarion.exe background --detach -server 127.0.0.1:63425 -user alice -pass secret",
		"  Then use tarion.exe menu to read/send through that background process.",
		"  Stop it with: tarion.exe stop",
		"",
		"Start connected client:",
		"  tarion.exe start -server 127.0.0.1:63425 -user alice -pass secret",
		"",
		"Direct/self test chat:",
		"  tarion.exe start -p 63426 -u Myself -i 127.0.0.1:63426",
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
		fmt.Fprintln(out, "Starts Tarion's always-on network listener.")
		fmt.Fprintln(out, "Use --detach to keep it running after the terminal closes on Windows/Linux.")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Examples:")
		fmt.Fprintln(out, "  tarion background --detach")
		fmt.Fprintln(out, "  tarion background --detach -server 127.0.0.1:63425 -user alice -pass secret")
		fmt.Fprintln(out, "  tarion menu")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Stop background process:")
		fmt.Fprintln(out, "  tarion stop")
		fmt.Fprintln(out, "  tarion stop -p 63425")
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
		fmt.Fprintln(out, "If background was started with a custom port, pass the same port:")
		fmt.Fprintln(out, "  tarion stop -p 63425")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Options:")
		fs.PrintDefaults()
	}
}

func runStop(args []string) error {
	fs := flag.NewFlagSet("stop", flag.ExitOnError)
	setStopUsage(fs)
	portFlag := fs.Int("p", 0, "local UDP port/background control port base")
	_ = fs.Parse(args)

	cfg, _ := storage.LoadOrCreateConfig()
	port := cfg.Port
	if *portFlag != 0 {
		port = *portFlag
	}
	if port == 0 {
		port = 63425
	}
	return backgroundRequest(port, controlRequest{Cmd: "stop"})
}

func runBackground(args []string) error {
	fs := flag.NewFlagSet("background", flag.ExitOnError)
	setBackgroundUsage(fs)
	portFlag := fs.Int("p", 0, "local UDP port to listen on")
	serverFlag := fs.String("server", "", "directory server IP:port")
	nameFlag := fs.String("user", "", "directory username")
	passFlag := fs.String("pass", "", "directory password")
	detachFlag := fs.Bool("detach", false, "start detached so it survives terminal close")
	_ = fs.Parse(args)

	cfg, err := storage.LoadOrCreateConfig()
	if err != nil {
		return err
	}
	if *serverFlag != "" {
		cfg.ServerAddr = *serverFlag
	}
	if *nameFlag != "" {
		cfg.Username = *nameFlag
	}
	if *passFlag != "" {
		cfg.Password = *passFlag
	}
	if *portFlag != 0 {
		cfg.Port = *portFlag
	}
	if cfg.Port == 0 {
		cfg.Port = 63425
	}
	if err := validateDirectoryConfig(cfg); err != nil {
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
	nm := network.NewNetworkManager(cfg.Port, id)
	if err := nm.StartListener(); err != nil {
		return err
	}
	token, err := newControlToken()
	if err != nil {
		return err
	}
	if err := serveBackgroundControl(cfg.Port, token, nm, cfg); err != nil {
		return fmt.Errorf("start background control at %s: %w", controlAddr(cfg.Port), err)
	}
	if err := saveControlToken(token); err != nil {
		return fmt.Errorf("save control token: %w", err)
	}
	fmt.Printf("tarion background listening on UDP/%d as %s; control %s\n", cfg.Port, identity.Short(id.ID), controlAddr(cfg.Port))

	go func() {
		for msg := range nm.MessageChan {
			chat, _ := recordIncoming(msg)
			fmt.Printf("new message from %s (%s, id %s)\n", chat, msg.Addr, identity.Short(msg.PeerID))
		}
	}()

	if cfg.ServerAddr != "" && cfg.Username != "" && cfg.Password != "" {
		d := newDirectoryClient(cfg)
		go func() {
			for {
				if err := d.heartbeat(); err != nil {
					_ = d.register()
				}
				time.Sleep(20 * time.Second)
			}
		}()
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	return nil
}

func runStart(args []string) error {
	fs := flag.NewFlagSet("start", flag.ExitOnError)
	userFlag := fs.String("u", "", "display name for a direct-IP chat")
	ipFlag := fs.String("i", "", "peer IP:port for a direct-IP chat")
	portFlag := fs.Int("p", 0, "local UDP port to listen on")
	serverFlag := fs.String("server", "", "directory server IP:port")
	nameFlag := fs.String("user", "", "directory username")
	passFlag := fs.String("pass", "", "directory password")
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
	if *serverFlag != "" {
		cfg.ServerAddr = *serverFlag
	}
	if *nameFlag != "" {
		cfg.Username = *nameFlag
	}
	if *passFlag != "" {
		cfg.Password = *passFlag
	}
	if *portFlag != 0 {
		cfg.Port = *portFlag
	}
	if err := validateDirectoryConfig(cfg); err != nil {
		return err
	}
	if err := storage.SaveConfig(cfg); err != nil {
		return err
	}

	p := tea.NewProgram(initialModel(cfg, *userFlag, *ipFlag, cfg.Port))
	_, err = p.Run()
	return err
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
		"  id          Show your peer ID so contacts can verify you",
		"  peers       List pinned contacts and their peer IDs",
		"  forget      Remove a contact's pinned key (after they reinstall)",
		"  help        Show this help",
		"",
		"Command help:",
		"  tarion start -h",
		"  tarion menu -h",
		"  tarion background -h",
		"  tarion stop -h",
		"",
		"Common examples:",
		"  tarion start",
		"  tarion background --detach",
		"  tarion menu",
		"  tarion stop",
		"  tarion start -server 127.0.0.1:63425 -user alice -pass secret",
		"  tarion menu -p 63425 -u Myself -i 127.0.0.1:63425",
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
		case "start", "menu", "background", "stop", "id", "peers", "forget":
			cmd, args = args[0], args[1:]
		}
	}

	var err error
	switch cmd {
	case "background":
		err = runBackground(args)
	case "stop":
		err = runStop(args)
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
		fmt.Fprintln(os.Stderr, styleError.Render("tarion: "+err.Error()))
		os.Exit(1)
	}
}
