package network

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/necromancer124/tarion/internal/identity"
	"github.com/quic-go/quic-go"
)

const (
	// ALPN changed from "tarion-p2p" because v2 peers require mutual TLS and
	// framed messages; old clients fail the handshake cleanly instead of
	// silently misparsing.
	ALPN            = "tarion/2"
	ProtocolVersion = 2

	MaxFrameSize   = 64 * 1024
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

func requireTarionIdentity(raw [][]byte, _ [][]*x509.Certificate) error {
	if len(raw) == 0 {
		return errors.New("peer presented no certificate")
	}
	cert, err := x509.ParseCertificate(raw[0])
	if err != nil {
		return err
	}
	_, err = identity.PeerIDFromCerts([]*x509.Certificate{cert})
	return err
}

func (nm *NetworkManager) serverTLS() *tls.Config {
	return &tls.Config{
		Certificates:          []tls.Certificate{nm.id.Cert},
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: requireTarionIdentity,
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
		VerifyPeerCertificate: requireTarionIdentity,
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
	if err := readFrame(stream, &env); err != nil {
		reply.Type, reply.Error = "nack", err.Error()
		_ = writeFrame(stream, reply)
		return
	}
	reply.ID = env.ID
	if err := validateIncoming(env); err != nil {
		reply.Type, reply.Error = "nack", err.Error()
		_ = writeFrame(stream, reply)
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
	_ = writeFrame(stream, reply)
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

	ctx, cancel := context.WithTimeout(context.Background(), sendTimeout)
	defer cancel()

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
	if err := writeFrame(stream, env); err != nil {
		stream.CancelRead(0)
		_ = stream.Close()
		return fmt.Errorf("write stream: %w", err)
	}
	if err := stream.Close(); err != nil {
		return fmt.Errorf("close stream: %w", err)
	}
	var reply envelope
	if err := readFrame(stream, &reply); err != nil {
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

// Frames are a 4-byte big-endian length followed by that many bytes of JSON.
func writeFrame(w io.Writer, env envelope) error {
	data, err := json.Marshal(env)
	if err != nil {
		return err
	}
	if len(data) > MaxFrameSize {
		return errors.New("frame too large")
	}
	buf := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(buf, uint32(len(data)))
	copy(buf[4:], data)
	_, err = w.Write(buf)
	return err
}

func readFrame(r io.Reader, env *envelope) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return fmt.Errorf("read frame header: %w", err)
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > MaxFrameSize {
		return fmt.Errorf("frame size %d out of range", n)
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(r, data); err != nil {
		return fmt.Errorf("read frame: %w", err)
	}
	return json.Unmarshal(data, env)
}
