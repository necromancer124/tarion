package main

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/necromancer124/tarion/internal/directory"
)

func manEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\e`)
	s = strings.ReplaceAll(s, "-", `\-`)
	if strings.HasPrefix(s, ".") || strings.HasPrefix(s, "'") {
		s = `\&` + s
	}
	return s
}

// writeManPage writes tariond(8) from the real flag definitions, so it
// can't drift from the program. docs/man/tariond.8 is its output; a test
// checks it is up to date.
func writeManPage(w io.Writer) {
	p := func(format string, a ...any) { fmt.Fprintf(w, format+"\n", a...) }
	p(`.TH TARIOND 8 "" "tariond" "System Administration"`)
	p(`.SH NAME`)
	p(`tariond \- Tarion directory server`)
	p(`.SH SYNOPSIS`)
	p(`.B tariond`)
	p(`[\fBserve\fR] [\fIoptions\fR]`)
	p(`.br`)
	p(`.B tariond`)
	p(`\fIcommand\fR [\fIargs\fR] [\fB\-data\fR \fIdir\fR]`)
	p(`.SH DESCRIPTION`)
	p(`tariond tells Tarion clients where to find each other and signals NAT hole punching. Chat messages go directly between clients and are end\-to\-end encrypted.`)
	p(`Two opt\-in features let messages pass through the server without it being able to read them: the relay (\fB\-relay\fR) and the mailbox (\fB\-mailbox\fR).`)
	p(`Accounts use argon2id password hashes; each device logs in with its own Ed25519 key, and a new device must be approved by one already on the account.`)
	p(`.SH COMMANDS`)
	for _, c := range [][3]string{
		{"serve", "[options]", "run the server (the default)"},
		{"invite", "[-n N]", "create one-time invite codes (safe while the server runs)"},
		{"accounts", "", "list accounts, their first device, device count and bans"},
		{"ban", "<name|peer-id>", "ban a username or a device key (applied within seconds)"},
		{"unban", "<name|peer-id>", "lift a ban"},
		{"delete", "<name>", "delete an account and free the name"},
		{"devices", "<name>", "list an account's devices"},
		{"devices reset", "<name>", "forget all of an account's devices (the user lost them all); their next password login becomes the first"},
		{"id", "", "print the server ID; clients pin it, give it to users as server_id"},
	} {
		p(`.TP`)
		p(`\fB%s\fR %s`, manEscape(c[0]), manEscape(c[1]))
		p(`%s`, manEscape(c[2]))
	}
	p(`Operator commands take the same \fB\-data\fR (or \fBTARIOND_DATA\fR) as the server and write request files a running server picks up.`)
	p(`.SH OPTIONS`)
	fs := flag.NewFlagSet("tariond", flag.ContinueOnError)
	addServeFlags(fs)
	addPathFlags(fs)
	fs.VisitAll(func(f *flag.Flag) {
		p(`.TP`)
		if f.DefValue != "" && f.DefValue != "false" {
			p(`\fB\-%s\fR (default %s)`, manEscape(f.Name), manEscape(f.DefValue))
		} else {
			p(`\fB\-%s\fR`, manEscape(f.Name))
		}
		p(`%s`, manEscape(f.Usage))
	})
	p(`.SH FILES`)
	p(`Everything lives in the data folder (\fB\-data\fR, \fBTARIOND_DATA\fR, default the current directory).`)
	for _, f := range [][2]string{
		{"tariond.key", "the server identity; back it up: losing it makes every client refuse the server"},
		{"users.json", "accounts, password hashes and device chains; back it up"},
		{"invites/", "one file per unused invite code"},
		{"bans.txt", "banned usernames and peer IDs, one per line, re-read when changed"},
		{"deletions/, device-resets/", "operator requests waiting for the server"},
		{"mailbox/", "with -mailbox: sealed letters and each device's mailbox key"},
	} {
		p(`.TP`)
		p(`\fI%s\fR`, manEscape(f[0]))
		p(`%s`, manEscape(f[1]))
	}
	p(`.SH ENVIRONMENT`)
	p(`.TP`)
	p(`\fBTARIOND_DATA\fR`)
	p(`the data folder, if \fB\-data\fR isn't given`)
	p(`.SH NETWORK`)
	p(`Open UDP %d (\fB\-port\fR) inbound. Probes for clients' forwarded ports go out from a second, random UDP port.`, directory.DefaultServerPort)
	p(`quic\-go may warn that it can't raise the UDP buffer size; on Linux raise the limits with sysctl net.core.rmem_max=7500000 net.core.wmem_max=7500000.`)
	p(`.SH EXIT STATUS`)
	p(`0 on success; 1 on an error, printed to standard error.`)
	p(`.SH SEE ALSO`)
	p(`\fBtarion\fR(1), docs/operator.md, https://github.com/necromancer124/tarion`)
}
