package main

import (
	"flag"
	"fmt"
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
	styleHelp     = lipgloss.NewStyle().Foreground(lipgloss.Color("12"))
	styleError    = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
)

type AppState int

const (
	StateListView AppState = iota
	StateChatView
)

type Contact struct {
	Username string
	Online   bool
	Addr     string
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
	netMgr        *network.NetworkManager
}

type msgIncomingChat network.IncomingMessage

func initialModel(forceChatUser, forceChatAddr string, port int) model {
	nm := network.NewNetworkManager(port)
	status := fmt.Sprintf("listening on UDP/%d", port)
	if err := nm.StartListener(); err != nil {
		status = "network error: " + err.Error()
	}

	contacts := []Contact{}
	m := model{state: StateListView, contacts: contacts, netMgr: nm, statusLine: status}

	if forceChatUser != "" && forceChatAddr != "" {
		m.contacts = append(m.contacts, Contact{Username: forceChatUser, Online: true, Addr: forceChatAddr, IsManual: true})
		m.activeContact = forceChatUser
		m.state = StateChatView
		m.chatHistory, _ = storage.ReadHistory(forceChatUser)
		if len(m.chatHistory) == 0 {
			m.chatHistory = []string{"--- Manual direct chat started with " + forceChatAddr + " ---"}
		}
	}
	return m
}

func (m model) Init() tea.Cmd { return m.listenForMessages() }

func (m model) listenForMessages() tea.Cmd {
	return func() tea.Msg {
		msg := <-m.netMgr.MessageChan
		return msgIncomingChat(msg)
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
			case "up", "k":
				if m.cursor > 0 {
					m.cursor--
				}
			case "down", "j":
				if m.cursor < len(m.contacts)-1 {
					m.cursor++
				}
			case "enter":
				if len(m.contacts) == 0 {
					return m, nil
				}
				m.activeContact = m.contacts[m.cursor].Username
				m.state = StateChatView
				m.chatHistory, _ = storage.ReadHistory(m.activeContact)
			}
		case StateChatView:
			switch msg.String() {
			case "ctrl+c":
				return m, tea.Quit
			case "esc":
				m.state = StateListView
			case "enter":
				if strings.TrimSpace(m.inputBuffer) != "" {
					msgText := fmt.Sprintf("Me: %s", m.inputBuffer)
					m.chatHistory = append(m.chatHistory, msgText)
					_ = storage.AppendHistory(m.activeContact, msgText)

					targetAddr := ""
					for _, c := range m.contacts {
						if c.Username == m.activeContact {
							targetAddr = c.Addr
							break
						}
					}
					text := m.inputBuffer
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
		}
	case msgIncomingChat:
		incoming := network.IncomingMessage(msg)
		name := m.activeContact
		if name == "" {
			name = incoming.From
		}
		line := fmt.Sprintf("%s: %s", incoming.From, incoming.Body)
		_ = storage.AppendHistory(name, line)
		if m.state == StateChatView {
			m.chatHistory = append(m.chatHistory, line)
		}
		return m, m.listenForMessages()
	}
	return m, nil
}

func (m model) View() string {
	switch m.state {
	case StateListView:
		var s strings.Builder
		s.WriteString("\nTARION P2P CHAT\n")
		s.WriteString(styleHelp.Render("Help: run `tarion.exe -u Name -i IP:Port` for direct chat. Press q to quit.") + "\n")
		s.WriteString(styleHelp.Render("History: "+storage.GetHistoryDir()) + "\n")
		s.WriteString(styleHelp.Render("Network: "+m.statusLine) + "\n\n")
		if len(m.contacts) == 0 {
			s.WriteString("No contacts loaded yet. Start a direct chat with flags.\n")
		} else {
			for i, c := range m.contacts {
				status := styleOffline.Render("[offline]")
				if c.Online {
					status = styleOnline.Render("[ONLINE]")
				}
				newIndicator := ""
				if lastMod := storage.GetLastModified(c.Username); !lastMod.IsZero() && time.Since(lastMod) < 5*time.Minute {
					newIndicator = styleNew.Render(" [NEW]")
				}
				line := fmt.Sprintf("%-15s %s %s%s", c.Username, status, c.Addr, newIndicator)
				if i == m.cursor {
					line = styleSelected.Render(line) + " <--"
				}
				s.WriteString(line + "\n")
			}
		}
		s.WriteString("\n(↑/↓ navigate, Enter open, q quit)\n")
		return styleBorder.Render(s.String())
	case StateChatView:
		var s strings.Builder
		s.WriteString(fmt.Sprintf("Chatting with %s  (Esc: list, Ctrl+C: quit)\n", m.activeContact))
		s.WriteString("--------------------------------\n")
		for _, line := range m.chatHistory {
			s.WriteString(line + "\n")
		}
		s.WriteString("--------------------------------\n")
		s.WriteString(styleInput.Render("> " + m.inputBuffer + "_"))
		return styleBorder.Render(s.String())
	}
	return ""
}

func main() {
	userFlag := flag.String("u", "", "display name for a direct-IP chat")
	ipFlag := flag.String("i", "", "peer IP:port for a direct-IP chat")
	portFlag := flag.Int("p", 63425, "local UDP port to listen on")
	wipeFlag := flag.Bool("wipe-history", false, "delete all local Tarion chat history and exit")
	flag.Parse()

	if *wipeFlag {
		if err := storage.DeleteAllHistory(); err != nil {
			fmt.Fprintf(os.Stderr, "failed to wipe history: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Tarion history wiped:", storage.GetHistoryDir())
		return
	}

	p := tea.NewProgram(initialModel(*userFlag, *ipFlag, *portFlag))
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error running TUI: %v", err)
		os.Exit(1)
	}
}
