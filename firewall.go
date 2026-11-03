package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/necromancer124/tarion/internal/firewall"
	"github.com/necromancer124/tarion/internal/storage"
)

// selfPath is this program's real path, as firewall rules name it.
func selfPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "tarion.exe"
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	return exe
}

// firewallStatus checks whether the computer's firewall lets peers reach
// the chat port. Tests replace n.firewall.
func (n *node) firewallStatus() firewall.Status {
	if n.firewall != nil {
		return n.firewall(n.cfg.Port)
	}
	return firewall.Check(selfPath(), n.cfg.Port)
}

// firewallBlocked explains a dropped test packet when this computer's
// firewall is the cause, or returns "".
func (n *node) firewallBlocked(forwarded string) string {
	fw := n.firewallStatus()
	if !fw.Blocked {
		return ""
	}
	return fmt.Sprintf("automatic port forwarding did not work:\n  - the router forwards %s, but this computer dropped the server's test packet: %s.\n%s\n",
		forwarded, fw.Reason, firewall.Fix(selfPath(), n.cfg.Port))
}

// warnFirewall logs, once at start, when this computer's firewall keeps
// peers from connecting first. Hole punching still works without a rule.
func (n *node) warnFirewall() {
	fw := n.firewallStatus()
	if !fw.Blocked {
		return
	}
	n.logMu.Lock()
	f := n.logFn
	n.logMu.Unlock()
	if f != nil {
		f(fmt.Sprintf("firewall: %s. You can still reach people and they can answer, but a forwarded port won't work and people can't connect to you first.\n%s",
			fw.Reason, firewall.Fix(selfPath(), n.cfg.Port)))
	}
}

func setFirewallUsage(fs *flag.FlagSet) {
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage:
  tarion firewall            check whether Windows Firewall lets people reach you
  tarion firewall allow      add a rule for tarion.exe on its chat port (asks for administrator permission)
  tarion firewall remove     delete Tarion's rules again

The rule only covers incoming UDP to this program on its chat port (-p).
Options:
`)
		fs.PrintDefaults()
	}
}

// runFirewall checks, adds or removes the Windows Firewall rule.
func runFirewall(args []string) error {
	fs := flag.NewFlagSet("firewall", flag.ExitOnError)
	setFirewallUsage(fs)
	portFlag := fs.Int("p", 0, "chat UDP port (default: the saved one)")
	action := ""
	if len(args) > 0 && (args[0] == "allow" || args[0] == "remove" || args[0] == "apply") {
		action, args = args[0], args[1:]
	}
	removeFlag := fs.Bool("remove", false, "with apply: remove instead of add")
	_ = fs.Parse(args)
	cfg, err := storage.LoadOrCreateConfig()
	if err != nil {
		return err
	}
	port := cfg.Port
	if *portFlag != 0 {
		port = *portFlag
	}
	if port == 0 {
		port = storage.DefaultPort
	}
	exe := selfPath()

	switch action {
	case "apply":
		// The elevated half of allow/remove; runs as administrator.
		return firewall.Apply(exe, port, *removeFlag)
	case "allow", "remove":
		if !firewall.Supported {
			return errors.New("only Windows Firewall can be changed by Tarion; on Linux allow it yourself, e.g. sudo ufw allow " + fmt.Sprint(port) + "/udp")
		}
		elevated := []string{"firewall", "apply", "-p", fmt.Sprint(port)}
		if action == "remove" {
			elevated = append(elevated, "-remove")
			fmt.Println("Removing Tarion's Windows Firewall rules; Windows will ask for administrator permission...")
		} else {
			fmt.Printf("Adding a Windows Firewall rule for %s on UDP %d; Windows will ask for administrator permission...\n", exe, port)
		}
		if err := firewall.Elevate(exe, elevated...); err != nil {
			return fmt.Errorf("the firewall was not changed: %w", err)
		}
	}

	fw := firewall.Check(exe, port)
	switch {
	case !fw.Known && fw.Err != nil:
		return fw.Err
	case !fw.Known:
		fmt.Println("Tarion only checks Windows Firewall. On Linux or macOS, make sure incoming UDP to port", port, "is allowed.")
	case fw.Blocked:
		if action == "remove" {
			fmt.Printf("Done. Windows Firewall now blocks incoming connections to Tarion on UDP %d again.\n", port)
			return nil
		}
		return fmt.Errorf("%s.\n%s", fw.Reason, firewall.Fix(exe, port))
	default:
		if action == "remove" {
			fmt.Printf("Tarion's rules are removed, but Windows Firewall still lets UDP %d in (another rule allows it, or inbound isn't blocked).\n", port)
			return nil
		}
		fmt.Printf("Windows Firewall lets people reach Tarion on UDP %d.\n", port)
		if action == "allow" {
			fmt.Println("If port forwarding failed before, run: tarion portmap")
		}
	}
	return nil
}
