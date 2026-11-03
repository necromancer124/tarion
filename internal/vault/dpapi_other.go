//go:build !windows

package vault

import "errors"

// WindowsAvailable reports whether the Windows protector can be used here.
const WindowsAvailable = false

var errNoDPAPI = errors.New("only available on Windows; use a passphrase instead")

func dpapiProtect([]byte) ([]byte, error)   { return nil, errNoDPAPI }
func dpapiUnprotect([]byte) ([]byte, error) { return nil, errNoDPAPI }
