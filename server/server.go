package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/necromancer124/tarion/internal/directory"
	"github.com/necromancer124/tarion/internal/identity"
	"github.com/necromancer124/tarion/internal/relay"
	"github.com/necromancer124/tarion/internal/wire"
	"github.com/quic-go/quic-go"
)

const (
	codeBusy     quic.ApplicationErrorCode = 2
	codeIdentity quic.ApplicationErrorCode = 1

	maxConns         = 10000
	maxConnsPerIP    = 16
	maxHashingAtOnce = 2 // argon2id uses ~64 MiB per hash by default
)

// Options are the operator's access rules.
type Options struct {
	Registration string // RegOpen, RegInvite or RegClosed
	InvitesDir   string // one file per unused invite code
	DeletionsDir string // operator requests to delete accounts
	BansPath     string // usernames / peer IDs, re-read when changed
	MinPassword  int

	// Relay forwards (still end-to-end encrypted) packets between peers
	// whose NATs block a direct connection.
	Relay            bool
	RelayRate        int // bytes per second per session
	RelayTotal       int // bytes per second for all sessions
	MaxRelaysPerUser int
}

func DefaultOptions() Options {
	return Options{
		Registration:     RegOpen,
		MinPassword:      directory.DefaultMinPassword,
		Relay:            false, // opt-in: by default no message passes through the server
		RelayRate:        256 * 1024,
		RelayTotal:       8 * 1024 * 1024,
		MaxRelaysPerUser: 8,
	}
}

// Server is tariond: it tracks who is online and where, and tells peers to
// punch toward each other. It never relays chat messages.
type Server struct {
	id        *identity.Identity
	accounts  *Accounts
	opts      Options
	bans      *banList
	invites   invites
	deletions deletions

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

	probe      net.PacketConn // separate socket for reachability tests
	probeLimit *limiter

	relayMu    sync.Mutex
	relays     map[relay.ID]*relaySession
	relayRate  *limiter // bytes per session
	relayTotal *limiter // bytes for all sessions
}

// relaySession joins two logged-in sessions for packet forwarding.
type relaySession struct {
	a, b *session
	last time.Time
}

type session struct {
	id     string
	conn   *quic.Conn
	peerID string
	ip     string
	addr   string   // public address the server observes = the client's chat socket
	udp    net.Addr // the same, as quic-go reports it; relay packets come from here

	mu          sync.Mutex
	user        string
	localAddrs  []string
	publicAddr  string // advertised by the user (e.g. a forwarded port)
	acceptRelay bool
}

func (s *session) loggedIn() (string, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.user, s.localAddrs
}

func NewServer(id *identity.Identity, accounts *Accounts, opts Options) *Server {
	if opts.Registration == "" {
		opts.Registration = RegOpen
	}
	if opts.MinPassword < 1 {
		opts.MinPassword = directory.DefaultMinPassword
	}
	if opts.RelayRate < 1 {
		opts.RelayRate = DefaultOptions().RelayRate
	}
	if opts.RelayTotal < 1 {
		opts.RelayTotal = DefaultOptions().RelayTotal
	}
	if opts.MaxRelaysPerUser < 1 {
		opts.MaxRelaysPerUser = DefaultOptions().MaxRelaysPerUser
	}
	return &Server{
		id:         id,
		accounts:   accounts,
		opts:       opts,
		bans:       newBanList(opts.BansPath),
		invites:    invites{dir: opts.InvitesDir},
		deletions:  deletions{dir: opts.DeletionsDir},
		sessions:   map[string]*session{},
		connsPerIP: map[string]int{},
		connLimit:  newLimiter(2*time.Second, 20),
		authLimit:  newLimiter(10*time.Second, 10),
		userLimit:  newLimiter(30*time.Second, 10),
		regLimit:   newLimiter(10*time.Minute, 3),
		reqLimit:   newLimiter(500*time.Millisecond, 30),
		punchLimit: newLimiter(2*time.Second, 3),
		hashing:    make(chan struct{}, maxHashingAtOnce),
		relays:     map[relay.ID]*relaySession{},
		relayRate:  newByteLimiter(opts.RelayRate),
		relayTotal: newByteLimiter(opts.RelayTotal),
		probeLimit: newLimiter(10*time.Second, 3),
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
			for _, l := range []*limiter{s.connLimit, s.authLimit, s.userLimit, s.regLimit, s.reqLimit, s.punchLimit, s.relayRate} {
				l.sweep()
			}
			s.sweepRelays()
		}
	}()
	go func() {
		for ; ; time.Sleep(2 * time.Second) {
			if s.bans.refresh() {
				s.kickBanned()
				s.broadcastRevoked()
			}
			s.processDeletions()
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
		udp:    conn.RemoteAddr(),
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
	case directory.OpRelay:
		return s.openRelay(sess, req)
	case directory.OpAdvertise:
		return s.advertise(sess, req)
	case directory.OpProbe:
		return s.sendProbe(sess, req)
	case directory.OpChangePassword:
		return s.changePassword(sess, req)
	case directory.OpDeleteAccount:
		return s.deleteAccount(sess, req)
	}
	return fail(directory.ErrBadRequest)
}

func (s *Server) register(sess *session, req directory.Request) directory.Response {
	if user, _ := sess.loggedIn(); user != "" {
		return fail(directory.ErrBadRequest)
	}
	if s.opts.Registration == RegClosed {
		return fail(directory.ErrRegistrationOff)
	}
	if !directory.ValidUsername(req.User) {
		return fail(directory.ErrInvalidName)
	}
	if s.bans.Banned(req.User, sess.peerID) {
		return fail(directory.ErrBanned)
	}
	if problem := passwordProblem(req.User, req.Pass, s.opts.MinPassword); problem != "" {
		return directory.Response{Error: directory.ErrWeakPassword, Detail: problem}
	}
	if s.opts.Registration == RegInvite && req.Invite == "" {
		return fail(directory.ErrInviteRequired)
	}
	if !s.regLimit.Allow(sess.ip) {
		return fail(directory.ErrRateLimited)
	}
	if _, taken := s.accounts.get(req.User); taken {
		return fail(directory.ErrNameTaken)
	}
	if s.opts.Registration == RegInvite {
		if !s.invites.Consume(req.Invite) {
			return fail(directory.ErrBadInvite)
		}
	}
	s.hashing <- struct{}{}
	name, err := s.accounts.Create(req.User, req.Pass, sess.peerID)
	<-s.hashing
	if err != nil && s.opts.Registration == RegInvite {
		s.invites.Restore(req.Invite)
	}
	switch {
	case errors.Is(err, errNameTaken):
		return fail(directory.ErrNameTaken)
	case err != nil:
		log.Printf("register %q: %v", req.User, err)
		return fail(directory.ErrServer)
	}
	log.Printf("registered: %s (key %s)", name, identity.Short(sess.peerID))
	return s.bind(sess, name, req)
}

func (s *Server) login(sess *session, req directory.Request) directory.Response {
	if user, _ := sess.loggedIn(); user != "" {
		return fail(directory.ErrBadRequest)
	}
	if !directory.ValidUsername(req.User) {
		return fail(directory.ErrNoSuchUser)
	}
	if s.bans.Banned(req.User, sess.peerID) {
		return fail(directory.ErrBanned)
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
	return s.bind(sess, name, req)
}

// bind makes sess the account's live session. An older session for the same
// account (another device, or a stale connection) is closed.
func (s *Server) bind(sess *session, name string, req directory.Request) directory.Response {
	var clean []string
	for _, a := range req.LocalAddrs {
		if host, port, err := net.SplitHostPort(a); err == nil && net.ParseIP(host) != nil && port != "" {
			clean = append(clean, a)
			if len(clean) == directory.MaxLocalAddrs {
				break
			}
		}
	}
	public := ""
	if directory.ValidPublicAddr(req.PublicAddr) {
		public = req.PublicAddr
	}
	sess.mu.Lock()
	sess.user, sess.localAddrs = name, clean
	sess.publicAddr, sess.acceptRelay = public, req.AcceptRelay
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
	return directory.Response{OK: true, User: name, YourAddr: sess.addr, Revoked: s.revokedKeys()}
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
	if s.bans.Banned(targetName, target.peerID) {
		return fail(directory.ErrOffline)
	}
	resp := directory.Response{OK: true, User: targetName, Addr: target.addr, PeerID: target.peerID}
	target.mu.Lock()
	resp.PublicAddr = target.publicAddr
	target.mu.Unlock()
	// LAN addresses only help (and are only shared) when both are behind the
	// same public IP, where dialing the public address needs NAT hairpinning.
	push := directory.Push{Type: directory.PushPunch, From: user, PeerID: sess.peerID, Addr: sess.addr}
	if target.ip == sess.ip {
		resp.LocalAddrs = targetLocal
		_, push.LocalAddrs = sess.loggedIn()
	}
	if s.punchLimit.Allow(sess.id + ">" + target.id) {
		go s.pushPunch(target, push)
	}
	return resp
}

// revokedKeys is every banned key: keys listed directly, plus the key
// linked to each banned username.
func (s *Server) revokedKeys() []string {
	names, keys := s.bans.snapshot()
	set := map[string]bool{}
	for _, k := range keys {
		set[k] = true
	}
	for _, n := range names {
		if u, ok := s.accounts.get(n); ok && u.PeerID != "" {
			set[strings.ToLower(u.PeerID)] = true
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	if len(out) > directory.MaxRevoked {
		out = out[:directory.MaxRevoked]
	}
	return out
}

// broadcastRevoked sends the current ban list to every online client.
func (s *Server) broadcastRevoked() {
	push := directory.Push{Type: directory.PushRevoked, Revoked: s.revokedKeys()}
	s.mu.Lock()
	targets := make([]*session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		targets = append(targets, sess)
	}
	s.mu.Unlock()
	for _, t := range targets {
		go s.pushPunch(t, push)
	}
}

// pushPunch sends a push (a punch request, or the ban list) to target on a
// stream the server opens. For a punch, target then sends a few packets from
// its chat socket to the requester, opening its NAT for the incoming dial.
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

// SetProbeConn gives the server a socket, on a different port from its
// main one, for reachability tests. Without it, probes are unavailable.
func (s *Server) SetProbeConn(pc net.PacketConn) { s.probe = pc }

// advertise sets (or clears) the address a user made reachable, such as a
// port their router forwards after login.
func (s *Server) advertise(sess *session, req directory.Request) directory.Response {
	if user, _ := sess.loggedIn(); user == "" {
		return fail(directory.ErrNotLoggedIn)
	}
	if req.PublicAddr != "" && !directory.ValidPublicAddr(req.PublicAddr) {
		return fail(directory.ErrBadRequest)
	}
	sess.mu.Lock()
	sess.publicAddr = req.PublicAddr
	sess.mu.Unlock()
	return directory.Response{OK: true}
}

// sendProbe sends a test packet to the user's advertised address from the
// probe socket, so the client can tell whether strangers can reach it. It
// only goes to the user's own public IP and is rate-limited, so it can't
// be used to send packets anywhere else.
func (s *Server) sendProbe(sess *session, req directory.Request) directory.Response {
	if user, _ := sess.loggedIn(); user == "" {
		return fail(directory.ErrNotLoggedIn)
	}
	if s.probe == nil {
		return fail(directory.ErrProbeOff)
	}
	nonce, ok := relay.ParseID(req.Nonce)
	sess.mu.Lock()
	target := sess.publicAddr
	sess.mu.Unlock()
	if !ok || target == "" {
		return fail(directory.ErrBadRequest)
	}
	if !s.probeLimit.Allow(sess.id) {
		return fail(directory.ErrRateLimited)
	}
	addr, err := net.ResolveUDPAddr("udp", target)
	seen, isUDP := sess.udp.(*net.UDPAddr)
	if err != nil || !isUDP || !addr.IP.Equal(seen.IP) {
		return fail(directory.ErrProbeNotYours)
	}
	if _, err := s.probe.WriteTo(relay.Probe(nonce), addr); err != nil {
		return fail(directory.ErrServer)
	}
	return directory.Response{OK: true}
}

const relayIdle = 2 * time.Minute

// openRelay creates a relay session from sess to the target user and tells
// the target before answering, so its client accepts the first packets.
func (s *Server) openRelay(sess *session, req directory.Request) directory.Response {
	user, _ := sess.loggedIn()
	if user == "" {
		return fail(directory.ErrNotLoggedIn)
	}
	if !s.opts.Relay {
		return fail(directory.ErrRelayOff)
	}
	s.mu.Lock()
	target := s.sessions[directory.NameKey(req.Target)]
	s.mu.Unlock()
	if target == nil || target == sess {
		return fail(directory.ErrOffline)
	}
	targetName, _ := target.loggedIn()
	if s.bans.Banned(targetName, target.peerID) || !s.punchLimit.Allow(sess.id+">relay>"+target.id) {
		return fail(directory.ErrOffline)
	}
	target.mu.Lock()
	accepts := target.acceptRelay
	target.mu.Unlock()
	if !accepts {
		return fail(directory.ErrRelayRefused)
	}

	id := relay.NewID()
	s.relayMu.Lock()
	open := 0
	for _, r := range s.relays {
		if r.a == sess {
			open++
		}
	}
	if open >= s.opts.MaxRelaysPerUser {
		s.relayMu.Unlock()
		return fail(directory.ErrRateLimited)
	}
	s.relays[id] = &relaySession{a: sess, b: target, last: time.Now()}
	s.relayMu.Unlock()

	s.pushPunch(target, directory.Push{Type: directory.PushRelay, From: user, PeerID: sess.peerID, Relay: id.String()})
	log.Printf("relay opened: %s -> %s", user, targetName)
	return directory.Response{OK: true, User: targetName, PeerID: target.peerID, Relay: id.String()}
}

// ServeRelay forwards relay packets arriving on the server's UDP socket
// between the two members of their session. It runs until tr is closed.
func (s *Server) ServeRelay(tr *quic.Transport) {
	buf := make([]byte, 2048)
	for {
		n, from, err := tr.ReadNonQUICPacket(context.Background(), buf)
		if err != nil {
			return
		}
		id, _, ok := relay.Unwrap(buf[:n])
		if !ok {
			continue
		}
		s.relayMu.Lock()
		r := s.relays[id]
		var to net.Addr
		if r != nil {
			switch {
			case sameAddr(from, r.a.udp):
				to = r.b.udp
			case sameAddr(from, r.b.udp):
				to = r.a.udp
			}
			if to != nil {
				r.last = time.Now()
			}
		}
		s.relayMu.Unlock()
		if to == nil || !s.relayRate.AllowN(id.String(), float64(n)) || !s.relayTotal.AllowN("", float64(n)) {
			continue
		}
		_, _ = tr.WriteTo(buf[:n], to)
	}
}

func sameAddr(a, b net.Addr) bool {
	ua, ok1 := a.(*net.UDPAddr)
	ub, ok2 := b.(*net.UDPAddr)
	if ok1 && ok2 {
		return ua.Port == ub.Port && ua.IP.Equal(ub.IP)
	}
	return a != nil && b != nil && a.String() == b.String()
}

// sweepRelays drops idle sessions and ones whose members went offline.
func (s *Server) sweepRelays() {
	s.relayMu.Lock()
	defer s.relayMu.Unlock()
	for id, r := range s.relays {
		if time.Since(r.last) > relayIdle || r.a.conn.Context().Err() != nil || r.b.conn.Context().Err() != nil {
			delete(s.relays, id)
		}
	}
}

// passwordCheck rate-limits and runs a password-verifying account operation.
func (s *Server) passwordCheck(sess *session, user string, op func() error) directory.Response {
	if !s.authLimit.Allow(sess.ip) || !s.userLimit.Allow(directory.NameKey(user)) {
		return fail(directory.ErrRateLimited)
	}
	s.hashing <- struct{}{}
	err := op()
	<-s.hashing
	switch {
	case errors.Is(err, errAuthFailed):
		log.Printf("failed password check for %q", user)
		return fail(directory.ErrAuthFailed)
	case errors.Is(err, errNoSuchUser):
		return fail(directory.ErrNoSuchUser)
	case err != nil:
		log.Printf("account change for %q: %v", user, err)
		return fail(directory.ErrServer)
	}
	return directory.Response{OK: true, User: user}
}

func (s *Server) changePassword(sess *session, req directory.Request) directory.Response {
	user, _ := sess.loggedIn()
	if user == "" {
		return fail(directory.ErrNotLoggedIn)
	}
	if problem := passwordProblem(user, req.NewPass, s.opts.MinPassword); problem != "" {
		return directory.Response{Error: directory.ErrWeakPassword, Detail: problem}
	}
	resp := s.passwordCheck(sess, user, func() error { return s.accounts.ChangePassword(user, req.Pass, req.NewPass) })
	if resp.OK {
		log.Printf("password changed: %s", user)
	}
	return resp
}

func (s *Server) deleteAccount(sess *session, req directory.Request) directory.Response {
	user, _ := sess.loggedIn()
	if user == "" {
		return fail(directory.ErrNotLoggedIn)
	}
	resp := s.passwordCheck(sess, user, func() error {
		if err := s.accounts.CheckPassword(user, req.Pass); err != nil {
			return err
		}
		_, err := s.accounts.Delete(user)
		return err
	})
	if resp.OK {
		log.Printf("account deleted by its owner: %s", user)
		s.endAccount(user, 300*time.Millisecond) // let the reply go out first
	}
	return resp
}

// processDeletions carries out operator requests from `tariond delete`.
func (s *Server) processDeletions() {
	for _, name := range s.deletions.Pending() {
		if existed, err := s.accounts.Delete(name); err != nil {
			log.Printf("delete %q: %v", name, err)
			continue
		} else if existed {
			log.Printf("account deleted by the operator: %s", name)
			s.endAccount(name, 0)
		}
		s.deletions.Done(name)
	}
}

// endAccount closes the live session of a deleted account.
func (s *Server) endAccount(name string, delay time.Duration) {
	s.mu.Lock()
	sess := s.sessions[directory.NameKey(name)]
	delete(s.sessions, directory.NameKey(name))
	s.mu.Unlock()
	if sess != nil {
		go func() {
			time.Sleep(delay)
			_ = sess.conn.CloseWithError(directory.CodeDeleted, "account deleted")
		}()
	}
}

// kickBanned closes the sessions of users or keys that were just banned.
func (s *Server) kickBanned() {
	s.mu.Lock()
	var kick []*session
	for _, sess := range s.sessions {
		if name, _ := sess.loggedIn(); s.bans.Banned(name, sess.peerID) {
			kick = append(kick, sess)
		}
	}
	s.mu.Unlock()
	for _, sess := range kick {
		name, _ := sess.loggedIn()
		log.Printf("banned: disconnecting %s", name)
		_ = sess.conn.CloseWithError(directory.CodeBanned, "banned")
	}
}
