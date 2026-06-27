package main

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

// Protocol Commands
const (
	CmdRegister  = "REG" // REG|user|pass
	CmdHeartbeat = "HBT" // HBT|user|pass
	CmdQuery     = "QRY" // QRY|user|pass|target
	CmdPunch     = "PCH" // PCH|target_addr (Sent from server to client)
)

func main() {
	port := 63425
	registry := NewRegistry()

	// Start the Reaper (Table Aging)
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		for range ticker.C {
			registry.ReapStaleUsers()
		}
	}()

	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatal(err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	fmt.Printf("TarionD started on UDP port %d\n", port)
	fmt.Println("Signaling active. Monitoring NAT Punching...")

	buf := make([]byte, 1024)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("Read error: %v", err)
			continue
		}

		payload := string(buf[:n])
		parts := strings.Split(payload, "|")
		if len(parts) < 2 {
			continue
		}

		command := parts[0]
		username := parts[1]

		switch command {
		case CmdRegister, CmdHeartbeat:
			if len(parts) < 3 {
				continue
			}
			password := parts[2]
			err := registry.RegisterOrUpdate(username, password, remoteAddr.String())
			if err != nil {
				conn.WriteToUDP([]byte("ERR|AUTH_FAILED"), remoteAddr)
				log.Printf("Auth failed for %s", username)
			} else {
				conn.WriteToUDP([]byte("OK|REGISTERED"), remoteAddr)
			}

		case CmdQuery:
			if len(parts) < 4 {
				continue
			}
			password := parts[2]
			target := parts[3]

			// 1. Authenticate the requester
			err := registry.RegisterOrUpdate(username, password, remoteAddr.String())
			if err != nil {
				conn.WriteToUDP([]byte("ERR|AUTH_FAILED"), remoteAddr)
				continue
			}

			// 2. Find the target
			targetAddr, err := registry.GetUserAddr(target)
			if err != nil {
				conn.WriteToUDP([]byte("ERR|OFFLINE"), remoteAddr)
				continue
			}

			// 3. Trigger NAT Hole Punch: Tell Target to open a port for Requester
			punchMsg := fmt.Sprintf("%s|%s", CmdPunch, remoteAddr.String())
			targetUDP, _ := net.ResolveUDPAddr("udp", targetAddr)
			conn.WriteToUDP([]byte(punchMsg), targetUDP)
			
			log.Printf("[SIGNAL] Triggered punch: %s -> %s", username, target)

			// 4. Send target address back to requester
			conn.WriteToUDP([]byte(fmt.Sprintf("OK|ADDR|%s", targetAddr)), remoteAddr)
		}
	}
}
