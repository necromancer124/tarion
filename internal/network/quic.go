package network

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/necromancer124/tarion/internal/identity"
	"github.com/necromancer124/tarion/internal/wire"
	"github.com/quic-go/quic-go"
)

const (
	// ALPN changed from "tarion-p2p" because v2 peers require mutual TLS and
	// framed messages; old clients fail the handshake cleanly instead of
	// silently misparsing.
	ALPN            = "tarion/2"
	ProtocolVersion = 2

	MaxFrameSize   = wire.MaxFrameSize
	MaxBodyBytes   = 16 * 1024
	MaxNameBytes   = 64
	maxIDBytes     = 64
	maxActiveConns = 256
	sendTimeout    = 10 * time.Second
	seenTTL        = 10 * time.Minute
	maxSeen        = 4096
)

const (
	errCodeNone     quic.ApplicationErrorCode = 0
	errCodeIdentity quic.ApplicationErrorCode = 1
	errCodeBusy     quic.ApplicationErrorCode = 2
)

// NetworkManager owns the always-on QUIC endpoint. Listening and dialing share
// one UDP socket, so peers see the same address for replies and an outgoing
// message also opens the local NAT mapping for the listening port.
type NetworkManager struct {
	Port        int
	MessageChan chan IncomingMessage

	id       *identity.Identity
	udp      *net.UDPConn
	tr       *quic.Transport
	listener *quic.Listener
	active   atomic.Int32

	mu    sync.Mutex
	conns map[string]*quic.Conn
	seen  map[string]time.Time
}

// IncomingMessage is delivered to the TUI when a peer sends data.
type IncomingMessage struct {
	ID     string
	PeerID string // proven by the TLS handshake
	Name   string // display name the peer claims; not proof of anything
	Addr   string // address the message actually came from
	Body   string
	Sent   time.Time // sender's clock
}

// envelope is the single framed JSON object sent in each direction of a stream.
type envelope struct {
	V     int    `json:"v"`
	Type  string `json:"type"`
	ID    string `json:"id"`
	TS    int64  `json:"ts,omitempty"`
	From  string `json:"from,omitempty"`
	Body  string `json:"body,omitempty"`
	Error string `json:"error,omitempty"`
}

func NewNetworkManager(port int, id *identity.Identity) *NetworkManager {
	return &NetworkManager{
		Port:        port,
		MessageChan: make(chan IncomingMessage, 100),
		id:          id,
		conns:       map[string]*quic.Conn{},
		seen:        map[string]time.Time{},
	}
}

// ID returns this endpoint's own peer ID.
func (nm *NetworkManager) ID() string { return nm.id.ID }

func quicConfig() *quic.Config {
	return &quic.Config{
		MaxIdleTimeout:     3 * time.Minute,
		MaxIncomingStreams: 32,
	}
}

func (nm *NetworkManager) serverTLS() *tls.Config {
	return &tls.Config{
		Certificates:          []tls.Certificate{nm.id.Cert},
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: identity.VerifyPeerCertificate,
		NextProtos:            []string{ALPN},
		MinVersion:            tls.VersionTLS13,
	}
}

func (nm *NetworkManager) clientTLS() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{nm.id.Cert},
		// There is no CA: peers are authenticated by their pinned Ed25519 key
		// (see Send's verify callback), not by a certificate chain.
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: identity.VerifyPeerCertificate,
		ServerName:            "tarion",
		NextProtos:            []string{ALPN},
		MinVersion:            tls.VersionTLS13,
	}
}

// StartListener starts the client's always-on QUIC listener.
func (nm *NetworkManager) StartListener() error {
	udp, err := net.ListenUDP("udp", &net.UDPAddr{Port: nm.Port})
	if err != nil {
		return fmt.Errorf("start QUIC listener on UDP %d: %w", nm.Port, err)
	}
	tr := &quic.Transport{Conn: udp}
	listener, err := tr.Listen(nm.serverTLS(), quicConfig())
	if err != nil {
		_ = udp.Close()
		return fmt.Errorf("start QUIC listener on UDP %d: %w", nm.Port, err)
	}
	nm.udp, nm.tr, nm.listener = udp, tr, listener

	go func() {
		for {
			conn, err := listener.Accept(context.Background())
			if err != nil {
				log.Printf("QUIC accept stopped: %v", err)
				return
			}
			if nm.active.Add(1) > maxActiveConns {
				nm.active.Add(-1)
				_ = conn.CloseWithError(errCodeBusy, "too many connections")
				continue
			}
			go func() {
				defer nm.active.Add(-1)
				nm.handleConnection(conn)
			}()
		}
	}()
	return nil
}

// Close shuts down the listener and every cached connection.
func (nm *NetworkManager) Close() error {
	nm.mu.Lock()
	for addr, conn := range nm.conns {
		_ = conn.CloseWithError(errCodeNone, "shutdown")
		delete(nm.conns, addr)
	}
	nm.mu.Unlock()
	if nm.listener != nil {
		_ = nm.listener.Close()
	}
	if nm.tr != nil {
		_ = nm.tr.Close()
	}
	if nm.udp != nil {
		return nm.udp.Close()
	}
	return nil
}

func (nm *NetworkManager) handleConnection(conn *quic.Conn) {
	peerID, err := identity.PeerIDFromCerts(conn.ConnectionState().TLS.PeerCertificates)
	if err != nil {
		_ = conn.CloseWithError(errCodeIdentity, err.Error())
		return
	}
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go nm.handleStream(conn, peerID, stream)
	}
}

func (nm *NetworkManager) handleStream(conn *quic.Conn, peerID string, stream *quic.Stream) {
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(sendTimeout))

	reply := envelope{V: ProtocolVersion, Type: "ack"}
	var env envelope
	if err := wire.ReadFrame(stream, &env); err != nil {
		reply.Type, reply.Error = "nack", err.Error()
		_ = wire.WriteFrame(stream, reply)
		return
	}
	reply.ID = env.ID
	if err := validateIncoming(env); err != nil {
		reply.Type, reply.Error = "nack", err.Error()
		_ = wire.WriteFrame(stream, reply)
		return
	}

	// A sender may retry after a lost ack; deliver each message ID only once.
	key := peerID + "/" + env.ID
	if nm.markSeen(key) {
		msg := IncomingMessage{
			ID:     env.ID,
			PeerID: peerID,
			Name:   strings.TrimSpace(env.From),
			Addr:   conn.RemoteAddr().String(),
			Body:   env.Body,
			Sent:   time.Unix(env.TS, 0),
		}
		select {
		case nm.MessageChan <- msg:
		default:
			nm.unmarkSeen(key)
			reply.Type, reply.Error = "nack", "receiver busy"
		}
	}
	_ = wire.WriteFrame(stream, reply)
}

func validateIncoming(env envelope) error {
	switch {
	case env.V != ProtocolVersion:
		return fmt.Errorf("unsupported protocol version %d", env.V)
	case env.Type != "msg":
		return fmt.Errorf("unsupported message type %q", env.Type)
	case env.ID == "" || len(env.ID) > maxIDBytes:
		return errors.New("bad message id")
	case env.Body == "":
		return errors.New("empty body")
	case len(env.Body) > MaxBodyBytes:
		return errors.New("body too large")
	case len(env.From) > MaxNameBytes:
		return errors.New("sender name too long")
	case !utf8.ValidString(env.Body) || !utf8.ValidString(env.From):
		return errors.New("message is not valid UTF-8")
	}
	return nil
}

func (nm *NetworkManager) markSeen(key string) bool {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	now := time.Now()
	if t, ok := nm.seen[key]; ok && now.Sub(t) < seenTTL {
		return false
	}
	if len(nm.seen) >= maxSeen {
		for k, t := range nm.seen {
			if now.Sub(t) >= seenTTL {
				delete(nm.seen, k)
			}
		}
		if len(nm.seen) >= maxSeen {
			nm.seen = map[string]time.Time{}
		}
	}
	nm.seen[key] = now
	return true
}

func (nm *NetworkManager) unmarkSeen(key string) {
	nm.mu.Lock()
	delete(nm.seen, key)
	nm.mu.Unlock()
}

// Send delivers one chat message and returns only after the peer acknowledged
// it. verify is called with the peer's proven ID after the handshake and
// before anything is written; returning an error aborts the send. The peer's
// ID is returned whenever the handshake got that far.
func (nm *NetworkManager) Send(peerAddr, from, body string, verify func(peerID string) error) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), sendTimeout)
	defer cancel()
	return nm.SendContext(ctx, peerAddr, from, body, verify)
}

// SendContext is Send with a caller-chosen deadline, used to try a peer's
// LAN address briefly before falling back to its public one.
func (nm *NetworkManager) SendContext(ctx context.Context, peerAddr, from, body string, verify func(peerID string) error) (string, error) {
	if nm.tr == nil {
		return "", errors.New("listener not started")
	}
	if peerAddr == "" {
		return "", errors.New("empty peer address")
	}
	if body == "" {
		return "", errors.New("empty message")
	}
	if len(body) > MaxBodyBytes {
		return "", fmt.Errorf("message too large (max %d bytes)", MaxBodyBytes)
	}
	from = strings.TrimSpace(from)
	if len(from) > MaxNameBytes {
		from = from[:MaxNameBytes]
	}
	env := envelope{V: ProtocolVersion, Type: "msg", ID: newMessageID(), TS: time.Now().Unix(), From: from, Body: body}

	// The first attempt may use a cached connection that has silently died
	// (for example the peer restarted); retry once on a fresh one.
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		conn, cached, err := nm.conn(ctx, peerAddr, attempt > 0)
		if err != nil {
			return "", fmt.Errorf("dial %s: %w", peerAddr, err)
		}
		peerID, err := identity.PeerIDFromCerts(conn.ConnectionState().TLS.PeerCertificates)
		if err != nil {
			nm.dropConn(peerAddr, conn)
			return "", err
		}
		if verify != nil {
			if err := verify(peerID); err != nil {
				nm.dropConn(peerAddr, conn)
				return peerID, err
			}
		}
		lastErr = sendOnStream(ctx, conn, env)
		if lastErr == nil {
			return peerID, nil
		}
		nm.dropConn(peerAddr, conn)
		var rejected *RejectedError
		if !cached || errors.As(lastErr, &rejected) {
			return peerID, lastErr
		}
	}
	return "", lastErr
}

// RejectedError means the peer received the message but refused it.
type RejectedError struct{ Reason string }

func (e *RejectedError) Error() string { return "peer rejected message: " + e.Reason }

func sendOnStream(ctx context.Context, conn *quic.Conn, env envelope) error {
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.SetDeadline(deadline)
	}
	if err := wire.WriteFrame(stream, env); err != nil {
		stream.CancelRead(0)
		_ = stream.Close()
		return fmt.Errorf("write stream: %w", err)
	}
	if err := stream.Close(); err != nil {
		return fmt.Errorf("close stream: %w", err)
	}
	var reply envelope
	if err := wire.ReadFrame(stream, &reply); err != nil {
		return fmt.Errorf("waiting for ack: %w", err)
	}
	if reply.Type != "ack" || reply.ID != env.ID {
		reason := reply.Error
		if reason == "" {
			reason = "unexpected reply " + reply.Type
		}
		return &RejectedError{Reason: reason}
	}
	return nil
}

// conn returns a live connection to addr, reusing a cached one unless fresh.
func (nm *NetworkManager) conn(ctx context.Context, addr string, fresh bool) (*quic.Conn, bool, error) {
	if !fresh {
		nm.mu.Lock()
		conn := nm.conns[addr]
		nm.mu.Unlock()
		if conn != nil && conn.Context().Err() == nil {
			return conn, true, nil
		}
	}
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, false, err
	}
	conn, err := nm.tr.Dial(ctx, udpAddr, nm.clientTLS(), quicConfig())
	if err != nil {
		return nil, false, err
	}
	nm.mu.Lock()
	if old := nm.conns[addr]; old != nil && old != conn {
		_ = old.CloseWithError(errCodeNone, "replaced")
	}
	nm.conns[addr] = conn
	nm.mu.Unlock()
	return conn, false, nil
}

func (nm *NetworkManager) dropConn(addr string, conn *quic.Conn) {
	nm.mu.Lock()
	if nm.conns[addr] == conn {
		delete(nm.conns, addr)
	}
	nm.mu.Unlock()
	_ = conn.CloseWithError(errCodeNone, "dropped")
}

func newMessageID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Identity returns the key this endpoint authenticates with.
func (nm *NetworkManager) Identity() *identity.Identity { return nm.id }

// Dial opens a QUIC connection from the shared chat socket. The directory
// client uses it so the server observes this socket's public address, which
// is exactly the address peers need to reach.
func (nm *NetworkManager) Dial(ctx context.Context, addr string, tlsConf *tls.Config, conf *quic.Config) (*quic.Conn, error) {
	if nm.tr == nil {
		return nil, errors.New("listener not started")
	}
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	return nm.tr.Dial(ctx, udpAddr, tlsConf, conf)
}

// PunchPacket is a tiny non-QUIC datagram. Its first byte has the QUIC
// "fixed bit" (0x40) cleared, so QUIC stacks drop it instead of parsing it.
var PunchPacket = []byte{0x00, 'T', 'P', 'U', 'N', 'C', 'H'}

// Punch sends a few PunchPackets from the chat socket to addr. That opens
// this side's NAT mapping toward a peer that is about to dial us, so its
// QUIC handshake is not dropped by our router.
func (nm *NetworkManager) Punch(addr string) error {
	if nm.tr == nil {
		return errors.New("listener not started")
	}
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	for i := 0; i < 3; i++ {
		if _, err := nm.tr.WriteTo(PunchPacket, udpAddr); err != nil {
			return err
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil
}

// LocalAddrs returns this machine's LAN address with the chat port, so a
// peer behind the same router can connect without NAT hairpinning. Only
// the interface that carries the default route is used: virtual adapters
// (VMware, Hyper-V, Docker) often share IPs across machines and would just
// waste a dial attempt.
func (nm *NetworkManager) LocalAddrs() []string {
	ip := primaryIPv4()
	if ip == nil {
		return nil
	}
	return []string{net.JoinHostPort(ip.String(), fmt.Sprint(nm.Port))}
}

// primaryIPv4 asks the OS which local address it would use to reach the
// internet. Connecting a UDP socket sends no packets.
func primaryIPv4() net.IP {
	conn, err := net.Dial("udp4", "192.0.2.1:9") // TEST-NET-1, never contacted
	if err != nil {
		return nil
	}
	defer conn.Close()
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || addr.IP.IsLoopback() || addr.IP.IsUnspecified() {
		return nil
	}
	return addr.IP.To4()
}
