package main

import (
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/necro/tarion/internal/network"
)

// --- Styles ---
var (
	styleOnline   = lipgloss.NewStyle().Foreground(lipgloss.Color("2")).Bold(true)
	styleOffline  = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	styleSelected = lipgloss.NewStyle().Background(lipgloss.Color("60")).Foreground(lipgloss.Color("0"))
	styleBorder    = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("240"))
	styleInput     = lipgloss.NewStyle().Foreground(lipgloss.Color("229"))
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

func initialModel() model {
	nm := network.NewNetworkManager(63425)
	err := nm.StartListener()
	if err != nil {
		fmt.Printf("Network Error: %v\n", err)
	}

	return model{
		state:    StateListView,
		contacts: []Contact{
			{"Alice", true, "127.0.0.1:63425"},
			{"Bob", false, "127.0.0.1:63426"},
		},
		cursor: 0,
		netMgr: nm,
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
				m.activeContact = m.contacts[m.cursor].Username
				m.state = StateChatView
				m.chatHistory = []string{"--- P2P Stream Established ---"}
			}

		case StateChatView:
			switch msg.String() {
			case "esc":
				m.state = StateListView
			case "enter":
				if m.inputBuffer != "" {
					msgText := fmt.Sprintf("Me: %s", m.inputBuffer)
					m.chatHistory = append(m.chatHistory, msgText)
					
					// Network Send
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
		}

	case msgIncomingChat:
		m.chatHistory = append(m.chatHistory, string(msg))
		return m, m.listenForMessages()
	}

	return m, nil
}

func (m model) View() string {
	switch m.state {
	case StateListView:
		var s strings.Builder
		s.WriteString("\n  TARION P2P CHAT\n\n")
		for i, c := range m.contacts {
			status := styleOffline.Render("[offline]")
			if c.Online {
				status = styleOnline.Render("[ONLINE]")
			}
			line := fmt.Sprintf("%-15s %s", c.Username, status)
			if i == m.cursor {
				line = styleSelected.Render(line) + " <--"
			}
			s.WriteString(line + "\n")
		}
		s.WriteString("\n\n(↑/↓ Navigate, Enter Select, q Quit)")
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
	}
	return ""
}

func main() {
	p := tea.NewProgram(initialModel())
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error running TUI: %v", err)
		os.Exit(1)
	}
}
