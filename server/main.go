package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

const (
	CmdRegister  = "REG" // REG|username|password
	CmdHeartbeat = "HBT" // HBT|username|password
	CmdQuery     = "QRY" // QRY|username|password|target
	CmdList      = "LST" // LST|username|password
)

func main() {
	port := flag.Int("port", 63425, "UDP port for Tarion directory signaling")
	usersPath := flag.String("users", "users.db", "flat-file user hash database")
	leaseTTL := flag.Duration("ttl", 60*time.Second, "online lease TTL")
	sweepEvery := flag.Duration("sweep", 10*time.Second, "stale-entry sweep interval")
	flag.Parse()

	registry, err := NewRegistry(*usersPath, *leaseTTL)
	if err != nil {
		log.Fatalf("load registry: %v", err)
	}

	go func() {
		ticker := time.NewTicker(*sweepEvery)
		defer ticker.Stop()
		for range ticker.C {
			registry.ReapStaleUsers()
		}
	}()

	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	log.Printf("tariond listening on UDP/%d", *port)
	buf := make([]byte, 2048)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("read: %v", err)
			continue
		}
		response := handlePacket(registry, strings.TrimSpace(string(buf[:n])), remoteAddr.String())
		if _, err := conn.WriteToUDP([]byte(response), remoteAddr); err != nil {
			log.Printf("write to %s: %v", remoteAddr, err)
		}
	}
}

func handlePacket(registry *Registry, payload, remoteAddr string) string {
	parts := strings.Split(payload, "|")
	if len(parts) < 3 {
		return "ERR|BAD_REQUEST"
	}

	command, username, password := parts[0], strings.TrimSpace(parts[1]), parts[2]
	if username == "" || password == "" {
		return "ERR|BAD_REQUEST"
	}

	switch command {
	case CmdRegister, CmdHeartbeat:
		if err := registry.RegisterOrUpdate(username, password, remoteAddr); err != nil {
			log.Printf("auth failed for %q from %s: %v", username, remoteAddr, err)
			return "ERR|AUTH_FAILED"
		}
		return "OK|REGISTERED"

	case CmdQuery:
		if len(parts) < 4 || strings.TrimSpace(parts[3]) == "" {
			return "ERR|BAD_REQUEST"
		}
		target := strings.TrimSpace(parts[3])

		if err := registry.RegisterOrUpdate(username, password, remoteAddr); err != nil {
			log.Printf("auth failed for %q from %s: %v", username, remoteAddr, err)
			return "ERR|AUTH_FAILED"
		}

		// The server never relays chat data and does not initiate contact with clients.
		// It only returns the target's currently observed public UDP address.
		targetAddr, err := registry.GetUserAddr(target)
		if err != nil {
			return "ERR|OFFLINE"
		}
		log.Printf("query: %s requested %s -> %s", username, target, targetAddr)
		return "OK|ADDR|" + targetAddr

	case CmdList:
		if err := registry.RegisterOrUpdate(username, password, remoteAddr); err != nil {
			log.Printf("auth failed for %q from %s: %v", username, remoteAddr, err)
			return "ERR|AUTH_FAILED"
		}
		return "OK|USERS|" + registry.ListOnline(username)

	default:
		return "ERR|UNKNOWN_COMMAND"
	}
}
