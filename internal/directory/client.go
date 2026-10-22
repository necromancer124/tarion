package directory

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/necromancer124/tarion/internal/identity"
	"github.com/necromancer124/tarion/internal/network"
	"github.com/necromancer124/tarion/internal/relay"
	"github.com/necromancer124/tarion/internal/wire"
	"github.com/quic-go/quic-go"
)

const requestTimeout = 10 * time.Second

// ClientConfig configures a directory Client.
type ClientConfig struct {
	Server   string // tariond host:port
	User     string
	Pass     string // optional once this device's key is bound to the account
	ServerID string // pinned server key; empty means trust on first use
	Invite   string // one-time code, needed only to register on an invite-only server

	// AcceptRelay lets others reach this client through the server's relay
	// (and lets it use the relay). Off means no message ever passes through
	// the server.
	AcceptRelay bool
	// PublicAddr is an address the user made reachable (a forwarded port).
	PublicAddr string

	// OnServerID is called once when an unpinned server key is first seen,
	// so the caller can persist the pin.
	OnServerID func(id string)
	// OnLoggedIn is called after each successful login. usedPassword is true
	// when the password was needed, after which the key alone is enough and
	// the caller can stop storing the password.
	OnLoggedIn func(usedPassword bool)
	// OnPunch is called for each punch request the server forwards.
	OnPunch func(Push)
	// OnRevoked receives the server's full list of banned keys at every
	// login and whenever it changes. Callers enforce and persist it.
	OnRevoked func(keys []string)
}

// Client keeps one QUIC connection to tariond open from the chat socket.
// The connection's keep-alives are the heartbeat and also keep this
// socket's NAT mapping open; while it is up, the user is online.
type Client struct {
	nm  *network.NetworkManager
	cfg ClientConfig

	mu         sync.Mutex
	conn       *quic.Conn
	status     string
	serverID   string
	lastPunch  map[string]time.Time
	publicAddr string // may change after login (port mapping)
	seenAddr   string // our address as the server observed it at login
}

// FatalError is a problem retrying will not fix (wrong password, server key
// changed, ...). Run stops and reports it in Status.
type FatalError struct{ Msg string }

func (e *FatalError) Error() string { return e.Msg }

func NewClient(nm *network.NetworkManager, cfg ClientConfig) *Client {
	return &Client{
		nm:         nm,
		cfg:        cfg,
		status:     "connecting to server " + cfg.Server,
		serverID:   strings.ReplaceAll(strings.TrimSpace(cfg.ServerID), " ", ""),
		lastPunch:  map[string]time.Time{},
		publicAddr: cfg.PublicAddr,
	}
}

// Status is a one-line, human-readable connection state.
func (c *Client) Status() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status
}

// Connected reports whether a logged-in connection is up.
func (c *Client) Connected() bool { return c.current() != nil }

func (c *Client) setStatus(s string) {
	c.mu.Lock()
	c.status = s
	c.mu.Unlock()
}

func (c *Client) current() *quic.Conn {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil && c.conn.Context().Err() == nil {
		return c.conn
	}
	return nil
}

// Run keeps the session alive until ctx ends or a FatalError occurs.
func (c *Client) Run(ctx context.Context) {
	backoff := 2 * time.Second
	for ctx.Err() == nil {
		loggedIn, err := c.session(ctx)
		if ctx.Err() != nil {
			return
		}
		var fatal *FatalError
		if errors.As(err, &fatal) {
			c.setStatus("server: " + fatal.Msg)
			return
		}
		if loggedIn {
			backoff = 2 * time.Second
		}
		c.setStatus(fmt.Sprintf("server offline (%v); retrying in %s", err, backoff))
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < time.Minute {
			backoff *= 2
		}
	}
}

func (c *Client) session(ctx context.Context) (bool, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return false, err
	}
	defer conn.CloseWithError(0, "bye")

	resp, usedPassword, err := c.login(ctx, conn)
	if err != nil {
		return false, err
	}
	c.mu.Lock()
	c.conn = conn
	c.seenAddr = resp.YourAddr
	c.status = fmt.Sprintf("server connected as %s (public address %s)", resp.User, resp.YourAddr)
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		if c.conn == conn {
			c.conn = nil
		}
		c.mu.Unlock()
	}()
	if usedPassword {
		c.cfg.Pass = "" // the key is bound now; reconnects log in with it
	}
	if c.cfg.OnLoggedIn != nil {
		c.cfg.OnLoggedIn(usedPassword)
	}
	if c.cfg.OnRevoked != nil {
		c.cfg.OnRevoked(resp.Revoked)
	}
	if srv, ok := conn.RemoteAddr().(*net.UDPAddr); ok && c.nm.Relay() != nil {
		c.nm.Relay().SetServer(srv) // relay packets travel this same path
	}

	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			var appErr *quic.ApplicationError
			if errors.As(err, &appErr) && appErr.Remote {
				switch appErr.ErrorCode {
				case CodeReplaced:
					return true, &FatalError{Msg: "logged in from another device; this session was closed"}
				case CodeBanned:
					return true, &FatalError{Msg: "banned from this server"}
				case CodeDeleted:
					return true, &FatalError{Msg: "this account was deleted"}
				}
			}
			return true, err
		}
		go c.handlePush(stream)
	}
}

func (c *Client) dial(ctx context.Context) (*quic.Conn, error) {
	host, _, err := net.SplitHostPort(c.cfg.Server)
	if err != nil {
		return nil, &FatalError{Msg: fmt.Sprintf("bad server address %q: %v", c.cfg.Server, err)}
	}
	var keyMismatch error
	pinned := c.serverID
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{c.nm.Identity().Cert},
		// No CA: the server is authenticated by its pinned Ed25519 key below.
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, chains [][]*x509.Certificate) error {
			if err := identity.VerifyPeerCertificate(raw, chains); err != nil {
				return err
			}
			cert, _ := x509.ParseCertificate(raw[0])
			id, _ := identity.PeerIDFromCerts([]*x509.Certificate{cert})
			if pinned != "" && !strings.EqualFold(id, pinned) {
				keyMismatch = &FatalError{Msg: fmt.Sprintf(
					"server key changed (pinned %s, got %s); refusing to log in. If the server was really reinstalled, remove server_id from config.json",
					identity.Short(pinned), identity.Short(id))}
				return keyMismatch
			}
			return nil
		},
		NextProtos: []string{ALPN},
		MinVersion: tls.VersionTLS13,
		ServerName: host,
	}
	quicConf := &quic.Config{
		HandshakeIdleTimeout: 5 * time.Second,
		MaxIdleTimeout:       45 * time.Second,
		KeepAlivePeriod:      15 * time.Second,
	}
	// The relay wrapper must recognize the server before the handshake: a
	// client behind a strict NAT accepts packets from nobody else.
	if srv, err := net.ResolveUDPAddr("udp", c.cfg.Server); err == nil && c.nm.Relay() != nil {
		c.nm.Relay().SetServer(srv)
	}
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := c.nm.Dial(dialCtx, c.cfg.Server, tlsConf, quicConf)
	if keyMismatch != nil {
		return nil, keyMismatch
	}
	if err != nil {
		return nil, err
	}
	id, err := identity.PeerIDFromCerts(conn.ConnectionState().TLS.PeerCertificates)
	if err != nil {
		conn.CloseWithError(0, "bad server key")
		return nil, err
	}
	if pinned == "" {
		c.serverID = id
		if c.cfg.OnServerID != nil {
			c.cfg.OnServerID(id)
		}
	}
	return conn, nil
}

func (c *Client) login(ctx context.Context, conn *quic.Conn) (Response, bool, error) {
	local := c.nm.LocalAddrs()
	usedPassword := c.cfg.Pass != ""
	c.mu.Lock()
	public := c.publicAddr
	c.mu.Unlock()
	resp, err := roundTrip(ctx, conn, Request{Op: OpLogin, User: c.cfg.User, Pass: c.cfg.Pass, LocalAddrs: local,
		AcceptRelay: c.cfg.AcceptRelay, PublicAddr: public})
	if err != nil {
		return resp, false, err
	}
	if resp.OK {
		return resp, usedPassword, nil
	}
	switch resp.Error {
	case ErrNoSuchUser:
		if c.cfg.Pass == "" {
			return resp, false, &FatalError{Msg: fmt.Sprintf("account %s does not exist; run once with -pass to create it", c.cfg.User)}
		}
		resp, err = roundTrip(ctx, conn, Request{Op: OpRegister, User: c.cfg.User, Pass: c.cfg.Pass, Invite: c.cfg.Invite, LocalAddrs: local,
			AcceptRelay: c.cfg.AcceptRelay, PublicAddr: public})
		if err != nil {
			return resp, false, err
		}
		if resp.OK {
			return resp, true, nil
		}
		if resp.Error == ErrRateLimited {
			return resp, false, errors.New("rate limited by server")
		}
		return resp, false, loginError(resp)
	case ErrRateLimited:
		return resp, false, errors.New("rate limited by server")
	default:
		return resp, false, loginError(resp)
	}
}

func loginError(resp Response) error {
	switch resp.Error {
	case ErrAuthFailed:
		return &FatalError{Msg: "wrong password"}
	case ErrPasswordRequired:
		return &FatalError{Msg: "this device is not linked to the account yet; run once with -pass"}
	case ErrInvalidName:
		return &FatalError{Msg: "invalid username (1-32 letters/digits, may contain . _ -)"}
	case ErrWeakPassword:
		msg := "password rejected"
		if resp.Detail != "" {
			msg += ": " + resp.Detail
		}
		return &FatalError{Msg: msg}
	case ErrNameTaken:
		return &FatalError{Msg: "username already taken"}
	case ErrBanned:
		return &FatalError{Msg: "banned from this server"}
	case ErrInviteRequired:
		return &FatalError{Msg: "this server is invite-only; run once with -invite CODE (ask the operator for a code)"}
	case ErrBadInvite:
		return &FatalError{Msg: "invite code is wrong or already used"}
	case ErrRegistrationOff:
		return &FatalError{Msg: "this server is not accepting new accounts"}
	}
	return &FatalError{Msg: "login refused: " + resp.Error}
}

// List returns the names of online users (not including you).
func (c *Client) List() ([]string, error) {
	resp, err := c.request(Request{Op: OpList})
	if err != nil {
		return nil, err
	}
	return resp.Users, nil
}

// Relay asks the server for a relay session to target, for when a direct
// connection fails. It returns the address to dial and the target's key.
func (c *Client) Relay(target string) (addr, peerID string, err error) {
	if !c.cfg.AcceptRelay {
		return "", "", errors.New("relay is turned off")
	}
	resp, err := c.request(Request{Op: OpRelay, Target: target})
	if err != nil {
		return "", "", err
	}
	id, ok := relay.ParseID(resp.Relay)
	if !ok {
		return "", "", errors.New("server sent a bad relay session")
	}
	c.nm.Relay().Allow(id)
	return relay.Addr{ID: id}.String(), resp.PeerID, nil
}

// SeenAddr is this client's address as the server observed it at login.
func (c *Client) SeenAddr() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.seenAddr
}

// SetPublicAddr changes the address advertised to peers (for example a
// port the router now forwards) for this and future logins.
func (c *Client) SetPublicAddr(addr string) error {
	c.mu.Lock()
	c.publicAddr = addr
	c.mu.Unlock()
	if !c.Connected() {
		return nil // sent with the next login
	}
	_, err := c.request(Request{Op: OpAdvertise, PublicAddr: addr})
	return err
}

// Probe asks the server to send a test packet, carrying nonce, to the
// advertised public address from a different port.
func (c *Client) Probe(nonce string) error {
	_, err := c.request(Request{Op: OpProbe, Nonce: nonce})
	return err
}

// ChangePassword changes the account password. The new password must meet
// the server's rules; the error says why when it does not.
func (c *Client) ChangePassword(oldPass, newPass string) error {
	return c.accountOp(Request{Op: OpChangePassword, Pass: oldPass, NewPass: newPass})
}

// DeleteAccount deletes the account (the name becomes free) and ends the
// session. Local history and keys stay on this device.
func (c *Client) DeleteAccount(pass string) error {
	return c.accountOp(Request{Op: OpDeleteAccount, Pass: pass})
}

func (c *Client) accountOp(req Request) error {
	conn := c.current()
	if conn == nil {
		return errors.New("not connected to server")
	}
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	resp, err := roundTrip(ctx, conn, req)
	if err != nil {
		return err
	}
	switch {
	case resp.OK:
		return nil
	case resp.Error == ErrAuthFailed:
		return errors.New("wrong password")
	case resp.Error == ErrWeakPassword && resp.Detail != "":
		return errors.New("new password rejected: " + resp.Detail)
	case resp.Error == ErrRateLimited:
		return errors.New("too many attempts; try again later")
	}
	return fmt.Errorf("server: %s", resp.Error)
}

// ErrUserOffline means the server has no online session for the target.
var ErrUserOffline = errors.New("user is offline")

// Lookup returns target's public address, LAN addresses (only if you share
// a public IP) and peer ID. The server also asks target to punch toward you.
func (c *Client) Lookup(target string) (Response, error) {
	resp, err := c.request(Request{Op: OpLookup, Target: target})
	if err != nil {
		return resp, err
	}
	return resp, nil
}

func (c *Client) request(req Request) (Response, error) {
	conn := c.current()
	if conn == nil {
		return Response{}, errors.New("not connected to server")
	}
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	resp, err := roundTrip(ctx, conn, req)
	if err != nil {
		return resp, err
	}
	if !resp.OK {
		if resp.Error == ErrOffline || resp.Error == ErrNoSuchUser {
			return resp, ErrUserOffline
		}
		return resp, fmt.Errorf("server: %s", resp.Error)
	}
	return resp, nil
}

func roundTrip(ctx context.Context, conn *quic.Conn, req Request) (Response, error) {
	var resp Response
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return resp, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.SetDeadline(deadline)
	} else {
		_ = stream.SetDeadline(time.Now().Add(requestTimeout))
	}
	if err := wire.WriteFrame(stream, req); err != nil {
		stream.CancelRead(0)
		_ = stream.Close()
		return resp, err
	}
	if err := stream.Close(); err != nil {
		return resp, err
	}
	err = wire.ReadFrame(stream, &resp)
	return resp, err
}

func (c *Client) handlePush(stream *quic.Stream) {
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
	var push Push
	if err := wire.ReadFrame(stream, &push); err != nil {
		return
	}
	if push.Type == PushRelay {
		if !c.cfg.AcceptRelay {
			return // relay is off here: its packets stay unknown and are dropped
		}
		if id, ok := relay.ParseID(push.Relay); ok && c.nm.Relay() != nil {
			c.nm.Relay().Allow(id)
		}
		return
	}
	if push.Type == PushRevoked {
		if c.cfg.OnRevoked != nil {
			c.cfg.OnRevoked(push.Revoked)
		}
		return
	}
	if push.Type != PushPunch || push.Addr == "" {
		return
	}
	// The server rate-limits punches too; this just avoids repeating one
	// toward the same address in a tight loop.
	c.mu.Lock()
	recent := time.Since(c.lastPunch[push.Addr]) < 2*time.Second
	if !recent {
		c.lastPunch[push.Addr] = time.Now()
		if len(c.lastPunch) > 256 {
			c.lastPunch = map[string]time.Time{push.Addr: time.Now()}
		}
	}
	c.mu.Unlock()
	if recent {
		return
	}
	// LAN addresses first: on a shared router that is the path the
	// requester tries first, and punching it opens our host firewall.
	for i, a := range push.LocalAddrs {
		if i == MaxLocalAddrs {
			break
		}
		_ = c.nm.Punch(a)
	}
	_ = c.nm.Punch(push.Addr)
	if c.cfg.OnPunch != nil {
		c.cfg.OnPunch(push)
	}
}
