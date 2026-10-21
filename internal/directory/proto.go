// Package directory is the protocol between Tarion clients and tariond, the
// directory server. Clients connect over QUIC from their chat socket, so the
// address the server observes is the one peers must dial. One request or
// response is one framed JSON object on its own stream (see package wire).
package directory

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	ALPN = "tarion-dir/1"

	// DefaultServerPort is tariond's UDP port. Clients default to a different
	// chat port (storage.DefaultPort) so both can run on one machine.
	DefaultServerPort = 63425

	MaxUsernameRunes = 32
	MinPasswordLen   = 6
	MaxPasswordLen   = 256
	MaxListedUsers   = 500
	MaxLocalAddrs    = 4
)

// Request operations.
const (
	OpRegister = "register" // create an account and bind this device's key
	OpLogin    = "login"    // with a password, or with the bound key alone
	OpList     = "list"     // names of online users
	OpLookup   = "lookup"   // a user's address and key; also signals a punch
)

// Error codes in Response.Error.
const (
	ErrBadRequest       = "bad_request"
	ErrInvalidName      = "invalid_name"
	ErrWeakPassword     = "weak_password"
	ErrNameTaken        = "name_taken"
	ErrNoSuchUser       = "no_such_user"
	ErrAuthFailed       = "auth_failed"
	ErrPasswordRequired = "password_required"
	ErrNotLoggedIn      = "not_logged_in"
	ErrOffline          = "offline"
	ErrRateLimited      = "rate_limited"
	ErrServer           = "server_error"
)

type Request struct {
	Op         string   `json:"op"`
	User       string   `json:"user,omitempty"`
	Pass       string   `json:"pass,omitempty"`
	Target     string   `json:"target,omitempty"`
	LocalAddrs []string `json:"local_addrs,omitempty"`
}

type Response struct {
	OK         bool     `json:"ok"`
	Error      string   `json:"error,omitempty"`
	User       string   `json:"user,omitempty"`      // canonical account name
	YourAddr   string   `json:"your_addr,omitempty"` // public address the server sees
	Users      []string `json:"users,omitempty"`
	Truncated  bool     `json:"truncated,omitempty"`
	Addr       string   `json:"addr,omitempty"`
	LocalAddrs []string `json:"local_addrs,omitempty"` // only when both share a public IP
	PeerID     string   `json:"peer_id,omitempty"`
}

// Push is sent by the server on a stream it opens to a logged-in client.
type Push struct {
	Type   string `json:"type"` // "punch"
	From   string `json:"from,omitempty"`
	PeerID string `json:"peer_id,omitempty"`
	Addr   string `json:"addr,omitempty"`
	// LocalAddrs is the requester's LAN address, sent only when both are
	// behind the same public IP: the requester dials that first, so the
	// target must open its firewall toward it too.
	LocalAddrs []string `json:"local_addrs,omitempty"`
}

const PushPunch = "punch"

// ValidUsername allows 1-32 letters or digits (any script) plus . _ -,
// starting with a letter or digit. Nothing here can break a file format,
// a terminal, or a log line.
func ValidUsername(name string) bool {
	if name == "" || utf8.RuneCountInString(name) > MaxUsernameRunes || !utf8.ValidString(name) {
		return false
	}
	for i, r := range name {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
		case i > 0 && (r == '.' || r == '_' || r == '-'):
		default:
			return false
		}
	}
	return true
}

// NameKey is the case-insensitive key accounts are unique by, so "Bob"
// cannot register next to "bob".
func NameKey(name string) string { return strings.ToLower(name) }
