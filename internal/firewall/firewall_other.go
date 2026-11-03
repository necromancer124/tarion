//go:build !windows

package firewall

import "errors"

// Check is only implemented for Windows Firewall. Linux and macOS firewalls
// are usually set up by hand; the port-forwarding report mentions them.
func Check(exe string, port int) Status { return Status{} }

// Supported reports whether this platform's firewall can be checked and
// changed by Tarion.
const Supported = false

var errUnsupported = errors.New("only Windows Firewall can be changed by Tarion; on Linux allow the port yourself, e.g. sudo ufw allow 63426/udp")

func Elevate(exe string, args ...string) error      { return errUnsupported }
func Apply(exe string, port int, remove bool) error { return errUnsupported }
