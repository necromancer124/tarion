package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
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
	cfg           *storage.Config
	netMgr        *network.NetworkManager
}

type msgIncomingChat network.IncomingMessage
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

func initialModel(cfg *storage.Config, forceChatUser, forceChatAddr string, port int) model {
	if port == 0 {
		port = 63425
	}
	nm := network.NewNetworkManager(port)
	status := fmt.Sprintf("listening UDP/%d", port)
	if err := nm.StartListener(); err != nil {
		status = "network error: " + err.Error()
	}

	contacts := make([]Contact, 0, len(cfg.Contacts)+1)
	for _, c := range cfg.Contacts {
		contacts = append(contacts, Contact{Username: c.Name, Addr: c.Addr, Online: c.Addr != ""})
	}

	m := model{state: StateListView, contacts: contacts, netMgr: nm, cfg: cfg, statusLine: status}
	if forceChatUser != "" && forceChatAddr != "" {
		m.upsertContact(Contact{Username: forceChatUser, Addr: forceChatAddr, Online: true, IsManual: true})
		m.openChat(forceChatUser)
	}
	return m
}

func (m model) Init() tea.Cmd {
	return tea.Batch(m.listenForMessages(), m.refreshDirectory(), tick())
}

func tick() tea.Cmd {
	return tea.Tick(5*time.Second, func(t time.Time) tea.Msg { return msgTick(t) })
}

func (m model) listenForMessages() tea.Cmd {
	return func() tea.Msg { return msgIncomingChat(<-m.netMgr.MessageChan) }
}

func (m model) refreshDirectory() tea.Cmd {
	cfg := *m.cfg
	contacts := append([]Contact(nil), m.contacts...)
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
		if m.contacts[i].Username == c.Username || (c.Addr != "" && m.contacts[i].Addr == c.Addr) {
			if c.Username != "" {
				m.contacts[i].Username = c.Username
			}
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
	for i := range m.contacts {
		if m.contacts[i].Username == name {
			m.contacts[i].Unread = false
			break
		}
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
					line := "Me: " + text
					m.chatHistory = append(m.chatHistory, line)
					_ = storage.AppendHistory(m.activeContact, line)
					targetAddr := ""
					for _, c := range m.contacts {
						if c.Username == m.activeContact {
							targetAddr = c.Addr
							break
						}
					}
					go func() { _ = m.netMgr.SendMessage(targetAddr, text) }()
					m.inputBuffer = ""
				}
			case "backspace":
				if len(m.inputBuffer) > 0 {
					m.inputBuffer = m.inputBuffer[:len(m.inputBuffer)-1]
				}
			default:
				if len(msg.String()) == 1 {
					m.inputBuffer += msg.String()
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
		name := ""
		if m.state == StateChatView && m.activeContact != "" {
			name = m.activeContact
		} else {
			for _, c := range m.contacts {
				if c.Addr == incoming.From {
					name = c.Username
					break
				}
			}
		}
		if name == "" {
			name = incoming.From
			m.upsertContact(Contact{Username: name, Addr: incoming.From, Online: true, Unread: true, IsManual: true})
		}
		line := fmt.Sprintf("%s: %s", name, incoming.Body)
		_ = storage.AppendHistory(name, line)
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
	case msgDirectory:
		m.statusLine = msg.status
		for _, c := range msg.contacts {
			m.upsertContact(c)
		}
		return m, tick()
	case msgTick:
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
				if lastMod := storage.GetLastModified(c.Username); c.Unread || (!lastMod.IsZero() && time.Since(lastMod) < 5*time.Minute) {
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
		"Status:",
		"  " + m.statusLine,
		"",
		"Controls: Enter open/send, Esc back, r refresh, h help, q quit.",
	}, "\n")
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
	if err := storage.SaveConfig(cfg); err != nil {
		return err
	}

	p := tea.NewProgram(initialModel(cfg, *userFlag, *ipFlag, cfg.Port))
	_, err = p.Run()
	return err
}

func main() {
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "start" {
		args = args[1:]
	}
	if err := runStart(args); err != nil {
		fmt.Fprintln(os.Stderr, styleError.Render("tarion: "+err.Error()))
		os.Exit(1)
	}
}
