package network

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"strings"

	"github.com/quic-go/quic-go"
)

// NetworkManager handles the QUIC listener and peer connections
type NetworkManager struct {
	Port        int
	Listen      *quic.Listener
	MessageChan chan string
}

func NewNetworkManager(port int) *NetworkManager {
	return &NetworkManager{
		Port:        port,
		MessageChan: make(chan string, 100),
	}
}

// StartListener begins the background QUIC server and the UDP signaling listener
func (nm *NetworkManager) StartListener() error {
	// 1. Start QUIC Listener for P2P Chat Payloads
	addr := fmt.Sprintf(":%d", nm.Port)
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
				log.Printf("QUIC Accept error: %v", err)
				continue
			}
			go nm.handleConnection(conn)
		}
	}()

	// 2. Start UDP Listener for Server Signaling (NAT Punching)
	// The client is ALWAYS listening on this port for both QUIC and Server signals
	udpAddr, _ := net.ResolveUDPAddr("udp", addr)
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		// Note: On some OSs, we might need to use SO_REUSEPORT to share the port between QUIC and UDP
		log.Printf("UDP Signaling listener started on %d", nm.Port)
	}

	go func() {
		buf := make([]byte, 1024)
		for {
			n, remoteAddr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				continue
			}
			payload := string(buf[:n])
			if strings.HasPrefix(payload, "PCH|") {
				peerAddr := strings.Split(payload, "|")[1]
				log.Printf("[NAT PUNCH] Received signal from server. Peer %s is calling. Opening hole...", peerAddr)
				// To "open the hole", we send a dummy packet to the peer
				nm.sendDummyPacket(peerAddr)
			}
		}
	}()

	return nil
}

func (nm *NetworkManager) sendDummyPacket(addr string) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return
	}
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.Write([]byte("PUNCH"))
}

func (nm *NetworkManager) handleConnection(conn quic.Connection) {
	defer conn.CloseIfNeeded()
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		return
	}
	defer stream.Close()

	buf := make([]byte, 4096)
	n, err := stream.Read(buf)
	if err != nil && err != io.EOF {
		return
	}

	nm.MessageChan <- string(buf[:n])
}

func (nm *NetworkManager) SendMessage(peerAddr string, message string) error {
	tlsConf := &tls.Config{InsecureSkipVerify: true}
	conn, err := quic.DialAddr(context.Background(), peerAddr, tlsConf, nil)
	if err != nil {
		return err
	}
	defer conn.CloseIfNeeded()

	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		return err
	}
	defer stream.Close()

	_, err = stream.Write([]byte(message))
	return err
}

func generateTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"tarion-p2p"},
	}
}
