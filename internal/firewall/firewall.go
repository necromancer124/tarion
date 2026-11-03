// Package firewall checks whether the computer's own firewall lets peers
// reach Tarion's chat port, and explains how to fix it when it doesn't.
//
// Only Windows Firewall is checked: it blocks unsolicited inbound UDP by
// default, and its "Allow access" prompt never appears for a detached
// background process, so the block is silent. Hole punching still works
// through it (our own outgoing packets open the way), but a forwarded port
// and peers who connect first don't.
package firewall

import (
	"fmt"
	"strconv"
	"strings"
)

// Status is the result of a check.
type Status struct {
	Known   bool   // false: not Windows, or the check itself failed
	Blocked bool   // incoming connections to the chat port are dropped
	Reason  string // why, when Blocked
	Err     error  // why the check failed, when !Known
}

// Rule is an enabled inbound firewall rule for UDP (or any protocol) that
// applies to the current network profile and either names no program or
// names this program.
type Rule struct {
	App    string `json:"app"`    // program path, "" for any program
	Ports  string `json:"ports"`  // local ports: "*", "63426", "1000-2000,63426", ...
	Remote string `json:"remote"` // remote addresses: "*", or a limited set such as "LocalSubnet"
	Action int    `json:"action"` // 0 block, 1 allow
}

// anyRemote reports whether a rule applies to every remote address. One
// limited to, say, the local network doesn't decide whether strangers on
// the internet get through.
func (r Rule) anyRemote() bool { return r.Remote == "" || r.Remote == "*" }

// Report is what the platform check reads from the firewall.
type Report struct {
	Enabled      bool   `json:"enabled"`       // on for a current network profile
	DefaultBlock bool   `json:"default_block"` // inbound default is block there
	Rules        []Rule `json:"rules"`
}

// Decide works out whether exe can receive unsolicited UDP on port.
// Windows applies block rules before allow rules.
func Decide(r Report, exe string, port int) Status {
	if !r.Enabled || !r.DefaultBlock {
		return Status{Known: true}
	}
	allowed := false
	for _, rule := range r.Rules {
		forUs := (rule.App == "" || strings.EqualFold(rule.App, exe)) && rule.anyRemote()
		switch {
		case rule.Action == 0 && forUs && portMatches(rule.Ports, port):
			if rule.App == "" {
				return Status{Known: true, Blocked: true, Reason: fmt.Sprintf("a Windows Firewall rule blocks incoming UDP on port %d for every program", port)}
			}
			return Status{Known: true, Blocked: true, Reason: "Windows Firewall has a rule that blocks tarion.exe from receiving connections (Windows creates one when \"Cancel\" is clicked on its \"Allow access\" prompt)"}
		case rule.Action == 1 && forUs && portMatches(rule.Ports, port):
			allowed = true
		}
	}
	if allowed {
		return Status{Known: true}
	}
	return Status{Known: true, Blocked: true, Reason: fmt.Sprintf("Windows Firewall blocks incoming connections and has no rule that allows tarion.exe on UDP port %d", port)}
}

// portMatches reports whether a rule's local port list includes port.
func portMatches(list string, port int) bool {
	for _, p := range strings.Split(list, ",") {
		p = strings.TrimSpace(p)
		if p == "*" || strings.EqualFold(p, "any") {
			return true
		}
		lo, hi, isRange := strings.Cut(p, "-")
		a, err := strconv.Atoi(strings.TrimSpace(lo))
		if err != nil {
			continue // named sets like "RPC" don't cover a chat port
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(strings.TrimSpace(hi)); err != nil {
				continue
			}
		}
		if a <= port && port <= b {
			return true
		}
	}
	return false
}

// RuleName is the name `tarion firewall allow` gives its rule.
func RuleName(port int) string { return fmt.Sprintf("Tarion chat (UDP %d)", port) }

// ApplyCommands are the netsh argument lists behind `tarion firewall allow`
// (remove false) and `remove`. Every inbound rule for this program goes
// first, including a block rule from a "Cancel" click; then allow adds one
// rule for UDP on the chat port only.
func ApplyCommands(exe string, port int, remove bool) [][]string {
	cmds := [][]string{{"advfirewall", "firewall", "delete", "rule", "name=all", "dir=in", "program=" + exe}}
	if !remove {
		cmds = append(cmds, []string{"advfirewall", "firewall", "add", "rule", "name=" + RuleName(port),
			"dir=in", "action=allow", "protocol=UDP", fmt.Sprintf("localport=%d", port), "program=" + exe,
			"profile=any", "description=Lets peers reach Tarion's chat port. Added by: tarion firewall allow"})
	}
	return cmds
}

// Fix explains how to let peers in, for messages and logs.
func Fix(exe string, port int) string {
	return fmt.Sprintf(`To let people reach you directly, allow Tarion in Windows Firewall:
  - run: tarion firewall allow   (asks for administrator permission once)
  - or, in an administrator terminal:
      netsh advfirewall firewall add rule name="%s" dir=in action=allow protocol=UDP localport=%d program="%s"
Then run: tarion portmap`, RuleName(port), port, exe)
}
