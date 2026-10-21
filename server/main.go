// tariond is Tarion's directory server. Clients log in over QUIC from their
// chat socket; tariond tells them each other's public address and peer key
// and signals NAT hole punching. It never sees or relays chat messages.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/necromancer124/tarion/internal/directory"
	"github.com/necromancer124/tarion/internal/identity"
	"github.com/quic-go/quic-go"
)

func main() {
	port := flag.Int("port", directory.DefaultServerPort, "UDP port to listen on")
	usersPath := flag.String("users", "users.json", "account database (JSON)")
	legacyPath := flag.String("legacy-users", "users.db", "old users.db to import when -users does not exist yet")
	keyPath := flag.String("key", "tariond.key", "server identity key (created if missing)")
	showID := flag.Bool("id", false, "print the server ID and exit")
	flag.Parse()

	id, err := identity.LoadOrCreate(*keyPath)
	if err != nil {
		log.Fatalf("load server key: %v", err)
	}
	if *showID {
		fmt.Println(identity.Fingerprint(id.ID))
		return
	}
	accounts, err := LoadAccounts(*usersPath, *legacyPath)
	if err != nil {
		log.Fatalf("load accounts: %v", err)
	}

	udp, err := net.ListenUDP("udp", &net.UDPAddr{Port: *port})
	if err != nil {
		log.Fatalf("listen UDP/%d: %v", *port, err)
	}
	tr := &quic.Transport{Conn: udp}
	srv := NewServer(id, accounts)
	ln, err := tr.Listen(srv.TLSConfig(), QUICConfig())
	if err != nil {
		log.Fatalf("listen QUIC: %v", err)
	}

	log.Printf("tariond listening on UDP/%d", *port)
	log.Printf("server ID: %s (clients pin this; give it to users as server_id)", identity.Fingerprint(id.ID))

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		log.Printf("shutting down")
		_ = ln.Close()
	}()
	if err := srv.Serve(ln); err != nil {
		log.Printf("stopped: %v", err)
	}
	_ = tr.Close()
	_ = udp.Close()
}
