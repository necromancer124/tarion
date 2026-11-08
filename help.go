package main

import (
	"embed"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/necromancer124/tarion/internal/directory"
	"github.com/necromancer124/tarion/internal/storage"
)

// The help topics are the same files GitHub shows in docs/topics, built
// into the binary, so `tarion help` and the docs can't disagree.
//
//go:embed docs/topics/*.md
var topicFiles embed.FS

// command is one tarion command, for help and the man page.
type command struct {
	name, args, summary string
	topic               string // help topic that explains it
}

var commands = []command{
	{"start", "[options]", "open the menu and chat; listens itself if no background process runs", "start"},
	{"menu", "", "open the menu (same as start)", "start"},
	{"background", "[--detach] [options]", "run the always-on listener; --detach survives closing the terminal", "background"},
	{"stop", "", "stop the background process", "background"},
	{"send", "<name> <message>", "send one message through the background process", "background"},
	{"listen", "", "print incoming messages and events as JSON lines (for scripts and apps)", "api"},
	{"history", "[-n N] <name>", "print a chat's recent history", "background"},
	{"devices", "[approve CODE | remove NAME]", "list your devices, add one with its code, or take one off", "devices"},
	{"protect", "[passphrase | windows | off]", "show or change how your local data is encrypted", "protect"},
	{"portmap", "", "ask the router to forward your port again, and explain the result", "portmap"},
	{"firewall", "[allow | remove]", "check Windows Firewall; allow lets people reach you", "firewall"},
	{"outbox", "", "list messages waiting to be delivered", "outbox"},
	{"dropped", "[-n N]", "list messages that were given up on or refused", "outbox"},
	{"id", "", "show your peer ID so contacts can verify you", "keys"},
	{"peers", "", "list pinned contacts and their peer IDs", "keys"},
	{"forget", "<name>", "forget a contact's pinned key (after they reinstall)", "keys"},
	{"passwd", "", "change your account password", "account"},
	{"delete-account", "", "delete your account on the server", "account"},
	{"help", "[command | topic]", "show help: tarion help devices, tarion help relay, ...", ""},
}

// topic is one help topic: its name and one-line summary come from the
// file's first line, "# name: summary".
type topic struct{ name, summary, body string }

func loadTopics() []topic {
	entries, _ := topicFiles.ReadDir("docs/topics")
	var out []topic
	for _, e := range entries {
		data, err := topicFiles.ReadFile("docs/topics/" + e.Name())
		if err != nil {
			continue
		}
		first, rest, _ := strings.Cut(string(data), "\n")
		name, summary, _ := strings.Cut(strings.TrimPrefix(first, "# "), ": ")
		out = append(out, topic{name: name, summary: summary, body: strings.TrimLeft(rest, "\n")})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

func findTopic(name string) (topic, bool) {
	for _, t := range loadTopics() {
		if t.name == name {
			return t, true
		}
	}
	return topic{}, false
}

var (
	reLink   = regexp.MustCompile(`\[([^\]]+)\]\(([^)]+)\)`)
	reBold   = regexp.MustCompile(`\*\*([^*]+)\*\*`)
	reCode   = regexp.MustCompile("`([^`]+)`")
	reTabSep = regexp.MustCompile(`^\|[-| ]+\|$`)
)

// plainText turns a topic's Markdown into terminal text: headings in
// capitals, no fences, bold or backticks, tables as aligned columns.
func plainText(md string) string {
	var out []string
	var table [][]string
	flush := func() {
		if len(table) == 0 {
			return
		}
		widths := make([]int, len(table[0]))
		for _, row := range table {
			for i, c := range row {
				if i < len(widths) && len([]rune(c)) > widths[i] {
					widths[i] = len([]rune(c))
				}
			}
		}
		for _, row := range table {
			var b strings.Builder
			b.WriteString("  ")
			for i, c := range row {
				if i == len(row)-1 || i >= len(widths) {
					b.WriteString(c)
					break
				}
				b.WriteString(c + strings.Repeat(" ", widths[i]-len([]rune(c))+2))
			}
			out = append(out, strings.TrimRight(b.String(), " "))
		}
		table = nil
	}
	inCode := false
	for _, line := range strings.Split(md, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "```") {
			inCode = !inCode
			continue
		}
		if inCode {
			out = append(out, "    "+line)
			continue
		}
		if strings.HasPrefix(line, "|") {
			if reTabSep.MatchString(line) {
				continue
			}
			var cells []string
			for _, c := range strings.Split(strings.Trim(line, "|"), "|") {
				cells = append(cells, inline(strings.TrimSpace(c)))
			}
			table = append(table, cells)
			continue
		}
		flush()
		if h, ok := strings.CutPrefix(line, "## "); ok {
			out = append(out, strings.ToUpper(inline(h)))
			continue
		}
		out = append(out, inline(line))
	}
	flush()
	return strings.TrimRight(strings.Join(out, "\n"), "\n") + "\n"
}

func inline(s string) string {
	s = reLink.ReplaceAllStringFunc(s, func(m string) string {
		p := reLink.FindStringSubmatch(m)
		if strings.HasPrefix(p[2], "http") {
			return p[1] + " (" + p[2] + ")"
		}
		return p[1]
	})
	s = reBold.ReplaceAllString(s, "$1")
	return reCode.ReplaceAllString(s, "$1")
}

func printGeneralHelp() {
	w := os.Stdout
	fmt.Fprintln(w, "Tarion: peer-to-peer, end-to-end encrypted terminal chat")
	fmt.Fprintln(w, "\nUsage:\n  tarion [command] [options]\n\nCommands:")
	for _, c := range commands {
		fmt.Fprintf(w, "  %-15s %s\n", c.name, c.summary)
	}
	fmt.Fprintln(w, "\nTopics (tarion help <topic>):")
	for _, t := range loadTopics() {
		fmt.Fprintf(w, "  %-15s %s\n", t.name, t.summary)
	}
	fmt.Fprintf(w, `
Common examples:
  tarion start -server SERVER:%d -user alice -pass "a long passphrase"
  tarion background --detach
  tarion send bob "hello"
  tarion devices approve 7WMW-26Z2

Every command also takes -h for its options. New here? Read: tarion help start
`, directory.DefaultServerPort)
}

// runHelp shows the topic for a command or concept.
func runHelp(args []string) error {
	if len(args) == 0 {
		printGeneralHelp()
		return nil
	}
	name := strings.ToLower(args[0])
	for _, c := range commands {
		if c.name == name && c.topic != "" {
			fmt.Printf("tarion %s %s\n  %s\n\n", c.name, c.args, c.summary)
			name = c.topic
			break
		}
	}
	t, ok := findTopic(name)
	if !ok {
		return fmt.Errorf("no help for %q; run tarion help to see the commands and topics", args[0])
	}
	fmt.Print(strings.ToUpper(t.name) + ": " + t.summary + "\n\n" + plainText(t.body))
	return nil
}

// manEscape makes text safe for roff.
func manEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\e`)
	s = strings.ReplaceAll(s, "-", `\-`)
	if strings.HasPrefix(s, ".") || strings.HasPrefix(s, "'") {
		s = `\&` + s
	}
	return s
}

// writeManPage writes tarion(1) from the command table, the real flag
// definitions and the help topics, so it can't drift from the program.
// docs/man/tarion.1 is its output; a test checks it is up to date.
func writeManPage(w io.Writer) {
	p := func(format string, a ...any) { fmt.Fprintf(w, format+"\n", a...) }
	p(`.TH TARION 1 "" "tarion" "User Commands"`)
	p(`.SH NAME`)
	p(`tarion \- peer\-to\-peer, end\-to\-end encrypted terminal chat`)
	p(`.SH SYNOPSIS`)
	p(`.B tarion`)
	p(`[\fIcommand\fR] [\fIoptions\fR]`)
	p(`.SH DESCRIPTION`)
	p(`Tarion sends chat messages directly between devices over QUIC with mutually authenticated TLS 1.3.`)
	p(`A directory server (\fBtariond\fR(8)) tells peers where to find each other and helps them through home routers.`)
	p(`Each device has its own Ed25519 identity key; contacts pin it on first contact.`)
	p(`Without a command, \fBtarion\fR runs \fBstart\fR.`)
	p(`.SH COMMANDS`)
	for _, c := range commands {
		p(`.TP`)
		if c.args != "" {
			p(`\fB%s\fR %s`, manEscape(c.name), manEscape(c.args))
		} else {
			p(`\fB%s\fR`, manEscape(c.name))
		}
		p(`%s`, manEscape(c.summary))
	}
	p(`.SH OPTIONS`)
	p(`These options are shared by \fBstart\fR, \fBmenu\fR and \fBbackground\fR. Options marked "saved" are written to config.json.`)
	fs := flag.NewFlagSet("tarion", flag.ContinueOnError)
	addClientFlags(fs)
	fs.VisitAll(func(f *flag.Flag) {
		p(`.TP`)
		p(`\fB\-%s\fR`, manEscape(f.Name))
		p(`%s`, manEscape(f.Usage))
	})
	p(`.TP`)
	p(`\fB\-\-detach\fR`)
	p(`(background) start detached, so it survives closing the terminal.`)
	p(`.TP`)
	p(`\fB\-u\fR \fIname\fR \fB\-i\fR \fIip:port\fR`)
	p(`(start) chat directly with an address, without a server.`)
	p(`.TP`)
	p(`\fB\-n\fR \fIN\fR`)
	p(`(history, dropped) how many recent lines to show; 0 shows all.`)
	p(`.SH TOPICS`)
	p(`\fBtarion help\fR \fItopic\fR explains:`)
	for _, t := range loadTopics() {
		p(`.TP`)
		p(`\fB%s\fR`, manEscape(t.name))
		p(`%s`, manEscape(t.summary))
	}
	p(`.SH FILES`)
	p(`Files live in %s on Windows, ~/.config/tarion on Linux and ~/Library/Application Support/tarion on macOS, or in \fB$TARION_HOME\fR.`, manEscape(`%APPDATA%\tarion`))
	for _, f := range [][2]string{
		{"config.json", "settings and contacts"},
		{"identity.key", "this device's private key (encrypted)"},
		{"vault.json", "the data key, protected by the Windows login or a passphrase"},
		{"peers.json", "pinned contacts and their verified devices"},
		{"history/", "one chat per file"},
		{"outbox.json", "messages waiting to be delivered"},
		{"dropped.log", "messages given up on or refused"},
		{"revoked.json", "keys the server banned"},
		{"background.log", "the background process's log"},
		{"control.token", "the local API secret, while the background process runs"},
	} {
		p(`.TP`)
		p(`\fI%s\fR`, manEscape(f[0]))
		p(`%s`, manEscape(f[1]))
	}
	p(`.SH ENVIRONMENT`)
	for _, e := range [][2]string{
		{"TARION_HOME", "use another folder, e.g. a second identity on one machine"},
		{"TARION_NO_AUTO_PROTECT", "set to 1 to not encrypt a new Windows install automatically"},
		{"TARION_SIMULATE_STRICT_NAT", "set to 1 to drop direct packets from peers (testing)"},
	} {
		p(`.TP`)
		p(`\fB%s\fR`, e[0])
		p(`%s`, manEscape(e[1]))
	}
	p(`.SH PORTS`)
	p(`One UDP port for chat and the server (default %d, \fB\-p\fR); the background control socket listens on 127.0.0.1, by default that port plus 10000 (\fB\-cp\fR). tariond listens on UDP %d.`, storage.DefaultPort, directory.DefaultServerPort)
	p(`.SH EXIT STATUS`)
	p(`0 on success; 1 on an error, which is printed to standard error with what to do about it.`)
	p(`.SH SEE ALSO`)
	p(`\fBtariond\fR(8), \fBtarion help\fR, https://github.com/necromancer124/tarion`)
}

// runMan prints the man page (hidden command used to regenerate docs/man).
func runMan() error {
	writeManPage(os.Stdout)
	return nil
}
