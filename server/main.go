// tariond is Tarion's directory server. Clients log in over QUIC from their
// chat socket; tariond tells them each other's public address and peer key
// and signals NAT hole punching. It never sees or relays chat messages.
//
//	tariond [serve flags]          run the server
//	tariond invite [-n 5]          create one-time invite codes
//	tariond accounts               list accounts
//	tariond ban <name|peer-id>     ban (takes effect within seconds)
//	tariond unban <name|peer-id>
//	tariond delete <name>          delete an account (frees the name)
//	tariond id                     print the server ID
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/necromancer124/tarion/internal/directory"
	"github.com/necromancer124/tarion/internal/identity"
	"github.com/quic-go/quic-go"
)

// paths are tariond's files. They live in one data folder (-data, or the
// TARIOND_DATA environment variable) so Docker needs a single volume and
// operator commands find the same files as the running server.
type paths struct {
	data, users, legacy, key, invites, bans, deletions string
}

func addPathFlags(fs *flag.FlagSet) func() paths {
	def := os.Getenv("TARIOND_DATA")
	if def == "" {
		def = "."
	}
	data := fs.String("data", def, "folder for all server files (env TARIOND_DATA)")
	users := fs.String("users", "", "account database (default <data>/users.json)")
	legacy := fs.String("legacy-users", "", "old users.db to import once (default <data>/users.db)")
	key := fs.String("key", "", "server identity key (default <data>/tariond.key)")
	inv := fs.String("invites", "", "invite code folder (default <data>/invites)")
	bans := fs.String("bans", "", "ban list (default <data>/bans.txt)")
	return func() paths {
		or := func(v, name string) string {
			if v != "" {
				return v
			}
			return filepath.Join(*data, name)
		}
		return paths{
			data:      *data,
			users:     or(*users, "users.json"),
			legacy:    or(*legacy, "users.db"),
			key:       or(*key, "tariond.key"),
			invites:   or(*inv, "invites"),
			bans:      or(*bans, "bans.txt"),
			deletions: filepath.Join(*data, "deletions"),
		}
	}
}

func main() {
	log.SetFlags(log.LstdFlags)
	args := os.Args[1:]
	cmd := "serve"
	if len(args) > 0 {
		switch args[0] {
		case "serve", "invite", "accounts", "ban", "unban", "delete", "id":
			cmd, args = args[0], args[1:]
		}
	}
	var err error
	switch cmd {
	case "serve":
		err = serve(args)
	case "invite":
		err = runInvite(args)
	case "accounts":
		err = runAccounts(args)
	case "ban", "unban":
		err = runBan(args, cmd == "ban")
	case "delete":
		err = runDelete(args)
	case "id":
		err = runID(args)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "tariond:", err)
		os.Exit(1)
	}
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	port := fs.Int("port", directory.DefaultServerPort, "UDP port to listen on")
	reg := fs.String("registration", RegOpen, "who may create accounts: open, invite or closed")
	minPass := fs.Int("min-password", directory.DefaultMinPassword, "minimum password length for new accounts")
	argonMem := fs.Int("argon-memory", int(DefaultArgon.MemoryKiB/1024), "argon2id memory per hash, MiB")
	argonTime := fs.Int("argon-time", int(DefaultArgon.Time), "argon2id passes")
	relayOn := fs.Bool("relay", true, "relay encrypted packets between peers whose NATs block direct connections")
	relayKBps := fs.Int("relay-kbps", 256, "relay bandwidth per session, KiB/s")
	relayTotalKBps := fs.Int("relay-total-kbps", 8192, "relay bandwidth for all sessions, KiB/s")
	showID := fs.Bool("id", false, "print the server ID and exit (same as `tariond id`)")
	getPaths := addPathFlags(fs)
	_ = fs.Parse(args)
	p := getPaths()

	switch *reg {
	case RegOpen, RegInvite, RegClosed:
	default:
		return fmt.Errorf("-registration must be open, invite or closed")
	}
	if *minPass < 8 || *argonMem < 8 || *argonTime < 1 {
		return fmt.Errorf("refusing weak settings: -min-password >= 8, -argon-memory >= 8, -argon-time >= 1")
	}
	if err := os.MkdirAll(p.data, 0700); err != nil {
		return err
	}
	id, err := identity.LoadOrCreate(p.key)
	if err != nil {
		return fmt.Errorf("load server key: %w", err)
	}
	if *showID {
		fmt.Println(identity.Fingerprint(id.ID))
		return nil
	}
	accounts, err := LoadAccounts(p.users, p.legacy)
	if err != nil {
		return fmt.Errorf("load accounts: %w", err)
	}
	accounts.SetArgon(argonParams{MemoryKiB: uint32(*argonMem) * 1024, Time: uint32(*argonTime), Threads: 1})

	udp, err := net.ListenUDP("udp", &net.UDPAddr{Port: *port})
	if err != nil {
		return fmt.Errorf("listen UDP/%d: %w", *port, err)
	}
	tr := &quic.Transport{Conn: udp}
	srv := NewServer(id, accounts, Options{
		Registration: *reg,
		InvitesDir:   p.invites,
		DeletionsDir: p.deletions,
		Relay:        *relayOn,
		RelayRate:    *relayKBps * 1024,
		RelayTotal:   *relayTotalKBps * 1024,
		BansPath:     p.bans,
		MinPassword:  *minPass,
	})
	ln, err := tr.Listen(srv.TLSConfig(), QUICConfig())
	if err != nil {
		return fmt.Errorf("listen QUIC: %w", err)
	}

	if *relayOn {
		go srv.ServeRelay(tr)
	}
	log.Printf("tariond listening on UDP/%d, data in %s, registration %s, relay %v", *port, p.data, *reg, *relayOn)
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
	return udp.Close()
}

func runInvite(args []string) error {
	fs := flag.NewFlagSet("invite", flag.ExitOnError)
	n := fs.Int("n", 1, "how many codes to create")
	getPaths := addPathFlags(fs)
	_ = fs.Parse(args)
	if *n < 1 || *n > 1000 {
		return fmt.Errorf("-n must be 1-1000")
	}
	codes, err := invites{dir: getPaths().invites}.Create(*n)
	if err != nil {
		return err
	}
	for _, c := range codes {
		fmt.Println(c)
	}
	fmt.Fprintln(os.Stderr, "Each code works once. Users pass it with: tarion start -server ... -user NAME -pass ... -invite CODE")
	return nil
}

func runAccounts(args []string) error {
	fs := flag.NewFlagSet("accounts", flag.ExitOnError)
	getPaths := addPathFlags(fs)
	_ = fs.Parse(args)
	p := getPaths()
	a, err := LoadAccounts(p.users, "")
	if err != nil {
		return err
	}
	bans := newBanList(p.bans)
	list := a.List()
	if len(list) == 0 {
		fmt.Println("No accounts.")
		return nil
	}
	for _, u := range list {
		key, note := "(not linked yet)", ""
		if u.PeerID != "" {
			key = identity.Fingerprint(u.PeerID)
		}
		if bans.Banned(u.Name, u.PeerID) {
			note = "  BANNED"
		}
		fmt.Printf("%-20s %s  created %s%s\n", u.Name, key, u.Created.Format("2006-01-02"), note)
	}
	return nil
}

func runBan(args []string, ban bool) error {
	verb := map[bool]string{true: "ban", false: "unban"}[ban]
	fs := flag.NewFlagSet(verb, flag.ExitOnError)
	getPaths := addPathFlags(fs)
	rest := parseInterspersed(fs, args)
	if len(rest) != 1 {
		return fmt.Errorf("usage: tariond %s <username or peer ID>  (quote a spaced peer ID)", verb)
	}
	entry := rest[0]
	if k := normalizeKey(entry); k != "" {
		entry = k
	} else if !directory.ValidUsername(entry) {
		return fmt.Errorf("%q is neither a valid username nor a peer ID", entry)
	}
	changed, err := editBans(getPaths().bans, entry, ban)
	if err != nil {
		return err
	}
	switch {
	case !changed && ban:
		fmt.Println(entry, "was already banned")
	case !changed:
		fmt.Println(entry, "was not banned")
	case ban:
		fmt.Println("banned", entry, "(a running server disconnects them within a few seconds)")
	default:
		fmt.Println("unbanned", entry)
	}
	return nil
}

// parseInterspersed parses flags that may come before or after positional
// arguments ("tariond ban bob -data /srv" as well as "-data /srv bob"); the
// standard flag package stops at the first positional one.
func parseInterspersed(fs *flag.FlagSet, args []string) []string {
	var positional []string
	for {
		_ = fs.Parse(args)
		if fs.NArg() == 0 {
			return positional
		}
		positional = append(positional, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func runDelete(args []string) error {
	fs := flag.NewFlagSet("delete", flag.ExitOnError)
	getPaths := addPathFlags(fs)
	rest := parseInterspersed(fs, args)
	if len(rest) != 1 || !directory.ValidUsername(rest[0]) {
		return fmt.Errorf("usage: tariond delete <username>")
	}
	if err := (deletions{dir: getPaths().deletions}).Request(rest[0]); err != nil {
		return err
	}
	fmt.Printf("deletion of %s requested; a running server applies it within a few seconds (otherwise at its next start)\n", rest[0])
	return nil
}

func runID(args []string) error {
	fs := flag.NewFlagSet("id", flag.ExitOnError)
	getPaths := addPathFlags(fs)
	_ = fs.Parse(args)
	id, err := identity.LoadOrCreate(getPaths().key)
	if err != nil {
		return err
	}
	fmt.Println(identity.Fingerprint(id.ID))
	return nil
}
