package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/necromancer124/tarion/internal/directory"
	"github.com/necromancer124/tarion/internal/identity"
	"github.com/necromancer124/tarion/internal/wire"
	"github.com/quic-go/quic-go"
)

const (
	codeBusy     quic.ApplicationErrorCode = 2
	codeIdentity quic.ApplicationErrorCode = 1

	maxConns         = 10000
	maxConnsPerIP    = 16
	maxHashingAtOnce = 4 // argon2id uses ~19 MiB per hash
)

// Server is tariond: it tracks who is online and where, and tells peers to
// punch toward each other. It never relays chat messages.
type Server struct {
	id       *identity.Identity
	accounts *Accounts

	mu         sync.Mutex
	sessions   map[string]*session // account key -> live session
	connsPerIP map[string]int
	active     int

	connLimit  *limiter // new connections per IP
	authLimit  *limiter // password attempts per IP
	userLimit  *limiter // password attempts per account
	regLimit   *limiter // registrations per IP
	reqLimit   *limiter // requests per session
	punchLimit *limiter // punch signals per requester->target pair
	hashing    chan struct{}
	nextID     atomic.Uint64
}

type session struct {
	id     string
	conn   *quic.Conn
	peerID string
	ip     string
	addr   string // public address the server observes = the client's chat socket

	mu         sync.Mutex
	user       string
	localAddrs []string
}

func (s *session) loggedIn() (string, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.user, s.localAddrs
}

func NewServer(id *identity.Identity, accounts *Accounts) *Server {
	return &Server{
		id:         id,
		accounts:   accounts,
		sessions:   map[string]*session{},
		connsPerIP: map[string]int{},
		connLimit:  newLimiter(2*time.Second, 20),
		authLimit:  newLimiter(10*time.Second, 10),
		userLimit:  newLimiter(30*time.Second, 10),
		regLimit:   newLimiter(10*time.Minute, 3),
		reqLimit:   newLimiter(500*time.Millisecond, 30),
		punchLimit: newLimiter(2*time.Second, 3),
		hashing:    make(chan struct{}, maxHashingAtOnce),
	}
}

func (s *Server) TLSConfig() *tls.Config {
	return &tls.Config{
		Certificates:          []tls.Certificate{s.id.Cert},
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: identity.VerifyPeerCertificate,
		NextProtos:            []string{directory.ALPN},
		MinVersion:            tls.VersionTLS13,
	}
}

func QUICConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout: 5 * time.Second,
		MaxIdleTimeout:       45 * time.Second, // clients send keep-alives every 15s
		MaxIncomingStreams:   16,
	}
}

// Serve accepts connections until the listener is closed.
func (s *Server) Serve(ln *quic.Listener) error {
	go func() {
		for range time.Tick(time.Minute) {
			for _, l := range []*limiter{s.connLimit, s.authLimit, s.userLimit, s.regLimit, s.reqLimit, s.punchLimit} {
				l.sweep()
			}
		}
	}()
	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			return err
		}
		ip := hostOf(conn.RemoteAddr().String())
		if !s.admit(ip) {
			_ = conn.CloseWithError(codeBusy, "too many connections")
			continue
		}
		go func() {
			defer s.release(ip)
			s.handleConn(conn, ip)
		}()
	}
}

func (s *Server) admit(ip string) bool {
	if !s.connLimit.Allow(ip) {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active >= maxConns || s.connsPerIP[ip] >= maxConnsPerIP {
		return false
	}
	s.active++
	s.connsPerIP[ip]++
	return true
}

func (s *Server) release(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active--
	if s.connsPerIP[ip]--; s.connsPerIP[ip] <= 0 {
		delete(s.connsPerIP, ip)
	}
}

func hostOf(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func (s *Server) handleConn(conn *quic.Conn, ip string) {
	peerID, err := identity.PeerIDFromCerts(conn.ConnectionState().TLS.PeerCertificates)
	if err != nil {
		_ = conn.CloseWithError(codeIdentity, err.Error())
		return
	}
	sess := &session{
		id:     strconv.FormatUint(s.nextID.Add(1), 10),
		conn:   conn,
		peerID: peerID,
		ip:     ip,
		addr:   conn.RemoteAddr().String(),
	}
	defer s.endSession(sess)
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go s.handleStream(sess, stream)
	}
}

func (s *Server) endSession(sess *session) {
	user, _ := sess.loggedIn()
	if user == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessions[directory.NameKey(user)] == sess {
		delete(s.sessions, directory.NameKey(user))
		log.Printf("offline: %s", user)
	}
}

func (s *Server) handleStream(sess *session, stream *quic.Stream) {
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(10 * time.Second))
	var req directory.Request
	resp := directory.Response{}
	if err := wire.ReadFrame(stream, &req); err != nil {
		resp.Error = directory.ErrBadRequest
	} else {
		resp = s.handle(sess, req)
	}
	_ = wire.WriteFrame(stream, resp)
}

func fail(code string) directory.Response { return directory.Response{Error: code} }

func (s *Server) handle(sess *session, req directory.Request) directory.Response {
	if !s.reqLimit.Allow(sess.id) {
		return fail(directory.ErrRateLimited)
	}
	switch req.Op {
	case directory.OpRegister:
		return s.register(sess, req)
	case directory.OpLogin:
		return s.login(sess, req)
	case directory.OpList:
		return s.list(sess)
	case directory.OpLookup:
		return s.lookup(sess, req)
	}
	return fail(directory.ErrBadRequest)
}

func (s *Server) register(sess *session, req directory.Request) directory.Response {
	if user, _ := sess.loggedIn(); user != "" {
		return fail(directory.ErrBadRequest)
	}
	if !directory.ValidUsername(req.User) {
		return fail(directory.ErrInvalidName)
	}
	if len(req.Pass) < directory.MinPasswordLen || len(req.Pass) > directory.MaxPasswordLen {
		return fail(directory.ErrWeakPassword)
	}
	if !s.regLimit.Allow(sess.ip) {
		return fail(directory.ErrRateLimited)
	}
	s.hashing <- struct{}{}
	name, err := s.accounts.Create(req.User, req.Pass, sess.peerID)
	<-s.hashing
	switch {
	case errors.Is(err, errNameTaken):
		return fail(directory.ErrNameTaken)
	case err != nil:
		log.Printf("register %q: %v", req.User, err)
		return fail(directory.ErrServer)
	}
	log.Printf("registered: %s (key %s)", name, identity.Short(sess.peerID))
	return s.bind(sess, name, req.LocalAddrs)
}

func (s *Server) login(sess *session, req directory.Request) directory.Response {
	if user, _ := sess.loggedIn(); user != "" {
		return fail(directory.ErrBadRequest)
	}
	if !directory.ValidUsername(req.User) {
		return fail(directory.ErrNoSuchUser)
	}
	var name string
	var err error
	if req.Pass == "" {
		name, err = s.accounts.LoginWithKey(req.User, sess.peerID)
	} else {
		if len(req.Pass) > directory.MaxPasswordLen {
			return fail(directory.ErrAuthFailed)
		}
		if !s.authLimit.Allow(sess.ip) || !s.userLimit.Allow(directory.NameKey(req.User)) {
			return fail(directory.ErrRateLimited)
		}
		var keyChanged bool
		s.hashing <- struct{}{}
		name, keyChanged, err = s.accounts.LoginWithPassword(req.User, req.Pass, sess.peerID)
		<-s.hashing
		if keyChanged {
			log.Printf("key change: %s is now %s", name, identity.Short(sess.peerID))
		}
	}
	switch {
	case errors.Is(err, errNoSuchUser):
		return fail(directory.ErrNoSuchUser)
	case errors.Is(err, errPasswordRequired):
		return fail(directory.ErrPasswordRequired)
	case errors.Is(err, errAuthFailed):
		log.Printf("failed login for %q", req.User)
		return fail(directory.ErrAuthFailed)
	case err != nil:
		log.Printf("login %q: %v", req.User, err)
		return fail(directory.ErrServer)
	}
	return s.bind(sess, name, req.LocalAddrs)
}

// bind makes sess the account's live session. An older session for the same
// account (another device, or a stale connection) is closed.
func (s *Server) bind(sess *session, name string, local []string) directory.Response {
	var clean []string
	for _, a := range local {
		if host, port, err := net.SplitHostPort(a); err == nil && net.ParseIP(host) != nil && port != "" {
			clean = append(clean, a)
			if len(clean) == directory.MaxLocalAddrs {
				break
			}
		}
	}
	sess.mu.Lock()
	sess.user, sess.localAddrs = name, clean
	sess.mu.Unlock()

	key := directory.NameKey(name)
	s.mu.Lock()
	old := s.sessions[key]
	s.sessions[key] = sess
	s.mu.Unlock()
	if old != nil && old != sess {
		_ = old.conn.CloseWithError(directory.CodeReplaced, "logged in elsewhere")
	}
	log.Printf("online: %s", name)
	return directory.Response{OK: true, User: name, YourAddr: sess.addr}
}

func (s *Server) list(sess *session) directory.Response {
	user, _ := sess.loggedIn()
	if user == "" {
		return fail(directory.ErrNotLoggedIn)
	}
	s.mu.Lock()
	names := make([]string, 0, len(s.sessions))
	for _, o := range s.sessions {
		if o != sess {
			n, _ := o.loggedIn()
			names = append(names, n)
		}
	}
	s.mu.Unlock()
	sort.Strings(names)
	resp := directory.Response{OK: true, Users: names}
	if len(names) > directory.MaxListedUsers {
		resp.Users, resp.Truncated = names[:directory.MaxListedUsers], true
	}
	return resp
}

func (s *Server) lookup(sess *session, req directory.Request) directory.Response {
	user, _ := sess.loggedIn()
	if user == "" {
		return fail(directory.ErrNotLoggedIn)
	}
	if !directory.ValidUsername(req.Target) {
		return fail(directory.ErrOffline)
	}
	s.mu.Lock()
	target := s.sessions[directory.NameKey(req.Target)]
	s.mu.Unlock()
	if target == nil || target == sess {
		return fail(directory.ErrOffline)
	}
	targetName, targetLocal := target.loggedIn()
	resp := directory.Response{OK: true, User: targetName, Addr: target.addr, PeerID: target.peerID}
	// LAN addresses only help (and are only shared) when both are behind the
	// same public IP, where dialing the public address needs NAT hairpinning.
	if target.ip == sess.ip {
		resp.LocalAddrs = targetLocal
	}
	if s.punchLimit.Allow(sess.id + ">" + target.id) {
		go s.pushPunch(target, directory.Push{Type: directory.PushPunch, From: user, PeerID: sess.peerID, Addr: sess.addr})
	}
	return resp
}

// pushPunch asks target to send a few packets from its chat socket to the
// requester, opening target's NAT toward the requester's incoming dial.
func (s *Server) pushPunch(target *session, push directory.Push) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := target.conn.OpenStreamSync(ctx)
	if err != nil {
		return
	}
	_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
	_ = wire.WriteFrame(stream, push)
	_ = stream.Close()
}
