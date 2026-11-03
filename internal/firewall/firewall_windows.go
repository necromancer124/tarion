//go:build windows

package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// checkScript reads Windows Firewall through its COM interface
// (HNetCfg.FwPolicy2), which answers the same on every Windows language.
// It prints a Report as JSON, keeping only rules that could matter: enabled,
// inbound, UDP or any protocol, active in a current profile, not limited to
// a service, and either for this program or for listed ports.
const checkScript = `$ErrorActionPreference = 'Stop'
$exe = $env:TARION_FW_EXE
$fw = New-Object -ComObject HNetCfg.FwPolicy2
$cur = $fw.CurrentProfileTypes
$enabled = $false; $block = $false
foreach ($p in 1, 2, 4) {
  if (($cur -band $p) -and $fw.FirewallEnabled($p)) {
    $enabled = $true
    if ($fw.DefaultInboundAction($p) -eq 0) { $block = $true }
  }
}
$rules = @()
foreach ($r in $fw.Rules) {
  if (-not $r.Enabled -or $r.Direction -ne 1) { continue }
  if (($r.Profiles -band $cur) -eq 0) { continue }
  if ($r.Protocol -ne 17 -and $r.Protocol -ne 256) { continue }
  if ($r.serviceName) { continue }
  $app = ''
  if ($r.ApplicationName) { $app = [Environment]::ExpandEnvironmentVariables($r.ApplicationName) }
  if ($app -and ($app -ine $exe)) { continue }
  $ports = '*'
  if ($r.LocalPorts) { $ports = [string]$r.LocalPorts }
  # Rules for every program and every port are almost always scoped to a
  # Store app package, which this interface doesn't show: skip them.
  if (-not $app -and $ports -eq '*') { continue }
  $remote = '*'
  if ($r.RemoteAddresses) { $remote = [string]$r.RemoteAddresses }
  $rules += @{ app = $app; ports = $ports; remote = $remote; action = [int]$r.Action }
}
@{ enabled = $enabled; default_block = $block; rules = $rules } | ConvertTo-Json -Compress -Depth 3`

// Check reads Windows Firewall and decides whether exe can be reached on
// UDP port. It takes a second or two.
func Check(exe string, port int) Status {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", checkScript)
	cmd.Env = append(cmd.Environ(), "TARION_FW_EXE="+exe)
	out, err := cmd.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && len(exit.Stderr) > 0 {
			err = fmt.Errorf("%v: %s", err, strings.TrimSpace(string(exit.Stderr)))
		}
		return Status{Err: fmt.Errorf("could not read Windows Firewall settings: %w", err)}
	}
	var r Report
	if err := json.Unmarshal(out, &r); err != nil {
		return Status{Err: fmt.Errorf("could not read Windows Firewall settings: %w", err)}
	}
	return Decide(r, exe, port)
}

// Supported reports whether this platform's firewall can be checked and
// changed by Tarion.
const Supported = true

// Elevate runs exe with args as administrator (the UAC prompt) and waits.
func Elevate(exe string, args ...string) error {
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = "'" + strings.ReplaceAll(a, "'", "''") + "'"
	}
	script := fmt.Sprintf("$p = Start-Process -FilePath '%s' -ArgumentList %s -Verb RunAs -Wait -PassThru -WindowStyle Hidden; exit $p.ExitCode",
		strings.ReplaceAll(exe, "'", "''"), strings.Join(quoted, ","))
	out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "canceled by the user") {
			return errors.New("administrator permission was not given")
		}
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Apply adds the inbound rule for exe on port, or removes Tarion's rules
// for exe when remove is set. It must run as administrator. Old rules for
// this program, including a block rule from a "Cancel" click, go first.
func Apply(exe string, port int, remove bool) error {
	cmds := ApplyCommands(exe, port, remove)
	for i, args := range cmds {
		out, err := exec.Command("netsh", args...).CombinedOutput()
		// The first command deletes old rules; netsh fails when there are
		// none, which is fine.
		if err != nil && i > 0 {
			return fmt.Errorf("netsh: %v: %s", err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}
