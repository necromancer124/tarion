package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/necro/tarion/internal/network"
	storagepkg "github.com/necro/tarion/internal/storage"
)

// --- Styles ---
var (
	styleOnline   = lipgloss.NewStyle().Foreground(lipgloss.Color("2")).Bold(true)
	styleOffline  = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	styleSelected = lipgloss.NewStyle().Background(lipgloss.Color("60")).Foreground(lipgloss.Color("0"))
	styleBorder    = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("240"))
	styleInput     = lipgloss.NewStyle().Foreground(lipgloss.Color("229"))
	styleNew       = lipgloss.NewStyle().Foreground(lipgloss.Color("13")).Bold(true)
	styleHelp      = lipgloss.NewStyle().Padding(1).Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("10"))
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
	IsManual bool
}

type model struct {
	state         AppState
	contacts      []Contact
	cursor        int
	activeContact string
	chatHistory   []string
	inputBuffer   string
	netMgr        *network.NetworkManager
}

type msgIncomingChat string

func initialModel(forceChatUser string, forceChatAddr string) model {
	nm := network.NewNetworkManager(63425)
	nm.StartListener()

	contacts := []Contact{}

	if forceChatUser != "" && forceChatAddr != "" {
		contacts = append(contacts, Contact{Username: forceChatUser, Online: true, Addr: forceChatAddr, IsManual: true})
		return model{
			state:         StateChatView,
			contacts:      contacts,
			activeContact: forceChatUser,
			chatHistory:   []string{"--- Manual P2P Connection Started ---"},
			netMgr:        nm,
		}
	}

	return model{
		state:    StateListView,
		contacts: contacts,
		cursor:   0,
		netMgr:   nm,
	}
}

func (m model) Init() tea.Cmd {
	return m.listenForMessages()
}

func (m model) listenForMessages() tea.Cmd {
	return tea.Exec(func(msg tea.Msg) tea.Msg {
		msgStr := <-m.netMgr.MessageChan
		return msgIncomingChat(msgStr)
	})
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch m.state {
		case StateListView:
			switch msg.String() {
			case "ctrl+c", "q":
				return model{}, tea.Quit
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
				hist, _ := storage.ReadHistory(m.activeContact)
				m.chatHistory = hist
			case "?":
				m.state = StateHelpView
			}

		case StateChatView:
			switch msg.String() {
			case "esc":
				m.state = StateListView
			case "enter":
				if m.inputBuffer != "" {
					msgText := fmt.Sprintf("Me: %s", m.inputBuffer)
					m.chatHistory = append(m.chatHistory, msgText)
					storage.AppendHistory(m.activeContact, msgText)
					
					var targetAddr string
					for _, c := range m.contacts {
						if c.Username == m.activeContact {
							targetAddr = c.Addr
						}
					}
					go m.netMgr.SendMessage(targetAddr, msgText)
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
			if msg.String() == "esc" || msg.String() == "q" {
				m.state = StateListView
			}
		}

	case msgIncomingChat:
		m.chatHistory = append(m.chatHistory, string(msg))
		storage.AppendHistory(m.activeContact, string(msg))
		return m, m.listenForMessages()
	}

	return m, nil
}

func (m model) View() string {
	switch m.state {
	case StateListView:
		var s strings.Builder
		s.WriteString("\n  TARION P2P CHAT\n\n")
		if len(m.contacts) == 0 {
			s.WriteString("  No contacts found.\n")
			s.WriteString("  Use '?' for help on how to add users.\n")
		} else {
			for i, c := range m.contacts {
				status := styleOffline.Render("[offline]")
				if c.Online {
					status = styleOnline.Render("[ONLINE]")
				}

				lastMod := storage.GetLastModified(c.Username)
				newIndicator := ""
				if !lastMod.IsZero() && time.Since(lastMod) < 5*time.Minute {
					newIndicator = styleNew.Render(" [NEW]")
				}

				line := fmt.Sprintf("%-15s %s%s", c.Username, status, newIndicator)
				if i == m.cursor {
					line = styleSelected.Render(line) + " <--"
				}
				s.WriteString(line + "\n")
			}
		}
		s.WriteString("\n\n(↑/↓ Navigate, Enter Select, ? Help, q Quit)")
		return styleBorder.Render(s.String())

	case StateChatView:
		var s strings.Builder
		s.WriteString(fmt.Sprintf(" Chatting with %s\n", m.activeContact))
		s.WriteString("--------------------------------\n")
		for _, line := range m.chatHistory {
			s.WriteString(line + "\n")
		}
		s.WriteString("\n--------------------------------\n")
		s.WriteString(styleInput.Render("> " + m.inputBuffer + "_"))
		return styleBorder.Render(s.String())

	case StateHelpView:
		helpText := " TARION SETUP & HELP\n\n" +
			"1. Start the server (tariond).\n" +
			"2. Launch client: ./tarion.exe\n" +
			" 3. Direct IP Chat: ./tarion.exe -u Name -i IP:Port\n\n" +
			"CONTROLS:\n" +
			"- Arrow Keys: Navigate List\n" +
			"- Enter: Open Chat\n" +
			"- Esc: Back to List\n" +
			"- q: Quit"
		return styleHelp.Render(helpText)
	}
	return ""
}

func main() {
	userFlag := flag.String("u", "", "Username to open chat with")
	ipFlag := flag.String("i", "", "IP address for the user")
	flag.Parse()

	p := tea.NewProgram(initialModel(*userFlag, *ipFlag))
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error running TUI: %v", err)
		os.Exit(1)
	}
}
