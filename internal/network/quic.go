package network

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"

	"github.com/quic-go/quic-go"
)

// NetworkManager handles the QUIC listener and peer connections
type NetworkManager struct {
	Port    int
	Listen  *quic.Listener
	MessageChan chan string
}

func NewNetworkManager(port int) *NetworkManager {
	return &NetworkManager{
		Port:        port,
		MessageChan: make(chan string, 100),
	}
}

// StartListener begins the background QUIC server to receive P2P messages
func (nm *NetworkManager) StartListener() error {
	addr := fmt.Sprintf(":%d", nm.Port)
	
	// For P2P, we use a self-signed cert for TLS 1.3 requirement of QUIC
	tlsConf := generateTLSConfig()
	
	listener, err := quic.ListenAddr(addr, tlsConf, nil)
	if err != nil {
		return fmt.Errorf("failed to start QUIC listener on %d: %v", nm.Port, err)
	}
	
	nm.Listen = listener
	
	go func() {
		for {
			conn, err := nm.Listen.Accept(context.Background())
			if err != nil {
				log.Printf("Accept error: %v", err)
				continue
			}
			go nm.handleConnection(conn)
		}
	}()
	
	return nil
}

func (nm *NetworkManager) handleConnection(conn quic.Connection) {
	defer conn.CloseIfNeeded()
	
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		log.Printf("Stream accept error: %v", err)
		return
	}
	defer stream.Close()

	buf := make([]byte, 4096)
	n, err := stream.Read(buf)
	if err != nil && err != io.EOF {
		log.Printf("Read error: %v", err)
		return
	}

	message := string(buf[:n])
	nm.MessageChan <- message
}

// SendMessage initiates a QUIC connection to a peer and sends a payload
func (nm *NetworkManager) SendMessage(peerAddr string, message string) error {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true, // Required for P2P self-signed certs
	}

	conn, err := quic.DialAddr(context.Background(), peerAddr, tlsConf, nil)
	if err != nil {
		return fmt.Errorf("failed to dial peer %s: %v", peerAddr, err)
	}
	defer conn.CloseIfNeeded()

	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		return fmt.Errorf("failed to open stream: %v", err)
	}
	defer stream.Close()

	_, err = stream.Write([]byte(message))
	return err
}

// Helper to generate a dummy self-signed TLS config for QUIC
func generateTLSConfig() *tls.Config {
	// In a real production P2P app, we would use Noise protocol or 
	// exchange keys via the directory server.
	// For the prototype, we use a permissive config.
	return &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"tarion-p2p"},
	}
}
