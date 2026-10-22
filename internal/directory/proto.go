// Package directory is the protocol between Tarion clients and tariond, the
// directory server. Clients connect over QUIC from their chat socket, so the
// address the server observes is the one peers must dial. One request or
// response is one framed JSON object on its own stream (see package wire).
package directory

import (
	"net"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/quic-go/quic-go"
)

const (
	ALPN = "tarion-dir/1"

	// DefaultServerPort is tariond's UDP port. Clients default to a different
	// chat port (storage.DefaultPort) so both can run on one machine.
	DefaultServerPort = 63425

	MaxUsernameRunes = 32
	// DefaultMinPassword is tariond's default; operators can change it.
	DefaultMinPassword = 10
	MaxPasswordLen     = 256
	MaxListedUsers     = 500
	MaxLocalAddrs      = 4
	MaxRevoked         = 1000 // banned keys sent to clients
)

// Request operations.
const (
	OpRegister = "register" // create an account and bind this device's key
	OpLogin    = "login"    // with a password, or with the bound key alone
	OpList     = "list"     // names of online users
	OpLookup   = "lookup"   // a user's address and key; also signals a punch

	OpRelay          = "relay"           // open a relay session to Target (direct path failed)
	OpChangePassword = "change_password" // Pass = current, NewPass = new
	OpDeleteAccount  = "delete_account"  // Pass = current; the session then closes
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
	ErrBanned           = "banned"
	ErrInviteRequired   = "invite_required"
	ErrBadInvite        = "bad_invite"
	ErrRegistrationOff  = "registration_closed"
	ErrRelayOff         = "relay_disabled"
	ErrRelayRefused     = "relay_refused" // the target turned the relay off
)

// QUIC application error codes tariond closes a session with.
const (
	CodeReplaced quic.ApplicationErrorCode = 3 // a newer login took over
	CodeBanned   quic.ApplicationErrorCode = 4 // the operator banned the account or key
	CodeDeleted  quic.ApplicationErrorCode = 5 // the account was deleted
)

type Request struct {
	Op         string   `json:"op"`
	User       string   `json:"user,omitempty"`
	Pass       string   `json:"pass,omitempty"`
	NewPass    string   `json:"new_pass,omitempty"`
	Target     string   `json:"target,omitempty"`
	Invite     string   `json:"invite,omitempty"` // one-time code, for servers in invite mode
	LocalAddrs []string `json:"local_addrs,omitempty"`
	// AcceptRelay (login) says whether this client lets others reach it
	// through the server's relay. PublicAddr (login) is an address the user
	// made reachable themselves, such as a forwarded port.
	AcceptRelay bool   `json:"accept_relay,omitempty"`
	PublicAddr  string `json:"public_addr,omitempty"`
}

type Response struct {
	OK         bool     `json:"ok"`
	Error      string   `json:"error,omitempty"`
	Detail     string   `json:"detail,omitempty"`    // human-readable reason, e.g. the password rules
	User       string   `json:"user,omitempty"`      // canonical account name
	YourAddr   string   `json:"your_addr,omitempty"` // public address the server sees
	Users      []string `json:"users,omitempty"`
	Truncated  bool     `json:"truncated,omitempty"`
	Addr       string   `json:"addr,omitempty"`
	LocalAddrs []string `json:"local_addrs,omitempty"` // only when both share a public IP
	PeerID     string   `json:"peer_id,omitempty"`
	// Revoked (on login) lists keys the operator banned. Clients refuse to
	// exchange messages with them even over a direct connection.
	Revoked []string `json:"revoked,omitempty"`
	// Relay is a relay session ID (hex) for op "relay".
	Relay string `json:"relay,omitempty"`
	// PublicAddr (lookup) is the address the target advertised itself.
	PublicAddr string `json:"public_addr,omitempty"`
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
	// Revoked is the full, current list of banned keys (type "revoked").
	Revoked []string `json:"revoked,omitempty"`
	// Relay is the session the requester will send through (type "relay").
	Relay string `json:"relay,omitempty"`
}

const (
	PushPunch   = "punch"
	PushRevoked = "revoked"
	PushRelay   = "relay"
)

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

// ValidPublicAddr accepts "host:port" where host is an IP or a DNS name
// (letters, digits, dots, hyphens) and port is 1-65535.
func ValidPublicAddr(s string) bool {
	if len(s) > 255 {
		return false
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil || host == "" {
		return false
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	for _, r := range host {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-') {
			return false
		}
	}
	return true
}

// NameKey is the case-insensitive key accounts are unique by, so "Bob"
// cannot register next to "bob".
func NameKey(name string) string { return strings.ToLower(name) }
