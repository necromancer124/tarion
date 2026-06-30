package network

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"time"

	"github.com/quic-go/quic-go"
)

const ALPN = "tarion-p2p"

// NetworkManager owns the always-on QUIC listener and outbound peer dials.
type NetworkManager struct {
	Port        int
	listener    *quic.Listener
	MessageChan chan IncomingMessage
}

// IncomingMessage is delivered to the TUI when a peer sends data.
type IncomingMessage struct {
	From string
	Body string
}

func NewNetworkManager(port int) *NetworkManager {
	return &NetworkManager{
		Port:        port,
		MessageChan: make(chan IncomingMessage, 100),
	}
}

// StartListener starts the client's always-on QUIC listener.
func (nm *NetworkManager) StartListener() error {
	addr := fmt.Sprintf(":%d", nm.Port)
	listener, err := quic.ListenAddr(addr, generateTLSConfig(), nil)
	if err != nil {
		return fmt.Errorf("start QUIC listener on UDP %d: %w", nm.Port, err)
	}
	nm.listener = listener

	go func() {
		for {
			conn, err := listener.Accept(context.Background())
			if err != nil {
				log.Printf("QUIC accept error: %v", err)
				return
			}
			go nm.handleConnection(conn)
		}
	}()
	return nil
}

func (nm *NetworkManager) handleConnection(conn *quic.Conn) {
	defer conn.CloseWithError(0, "done")

	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		log.Printf("accept stream: %v", err)
		return
	}
	defer stream.Close()

	data, err := io.ReadAll(stream)
	if err != nil {
		log.Printf("read stream: %v", err)
		return
	}

	nm.MessageChan <- IncomingMessage{
		From: conn.RemoteAddr().String(),
		Body: string(data),
	}
}

// SendMessage dials a peer directly over QUIC and writes a single chat payload.
func (nm *NetworkManager) SendMessage(peerAddr string, message string) error {
	if peerAddr == "" {
		return fmt.Errorf("empty peer address")
	}

	tlsConf := &tls.Config{
		InsecureSkipVerify: true, // prototype: peers use self-signed certs
		NextProtos:         []string{ALPN},
	}
	conn, err := quic.DialAddr(context.Background(), peerAddr, tlsConf, nil)
	if err != nil {
		return fmt.Errorf("dial %s: %w", peerAddr, err)
	}
	// Do not immediately close the QUIC connection after closing the stream.
	// A connection-level close can race the peer's stream reader and cancel the
	// message before it is delivered. For Tarion's single-message prototype,
	// closing the stream is the delivery boundary; the connection can idle out.

	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}

	if _, err := stream.Write([]byte(message)); err != nil {
		_ = stream.Close()
		return fmt.Errorf("write stream: %w", err)
	}
	return stream.Close()
}

func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{ALPN},
	}
}
