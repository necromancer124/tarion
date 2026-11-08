package main

import (
	"crypto/rand"
	"errors"
	"log"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/necromancer124/tarion/internal/devices"
	"github.com/necromancer124/tarion/internal/directory"
	"github.com/necromancer124/tarion/internal/identity"
	"github.com/quic-go/quic-go"
)

// sessKey is the sessions map key: one live session per device.
func sessKey(name, peerID string) string { return directory.NameKey(name) + "/" + peerID }

// userSessions returns an account's online devices, the most recent login
// first. Callers must not hold s.mu.
func (s *Server) userSessions(name string) []*session {
	prefix := directory.NameKey(name) + "/"
	s.mu.Lock()
	var out []*session
	for k, sess := range s.sessions {
		if strings.HasPrefix(k, prefix) {
			out = append(out, sess)
		}
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].since.After(out[j].since) })
	return out
}

// cleanDeviceName keeps a device name printable and short.
func cleanDeviceName(name string) string {
	var b strings.Builder
	n := 0
	for _, r := range strings.TrimSpace(name) {
		if n == devices.MaxNameRunes {
			break
		}
		if unicode.IsPrint(r) {
			b.WriteRune(r)
			n++
		}
	}
	return b.String()
}

// pendingDevice is a device that logged in with the right password but
// isn't on the account yet. It waits, with a pairing code, for one of the
// account's devices to approve it.
type pendingDevice struct {
	peerID  string
	pubKey  []byte
	name    string
	code    string
	expires time.Time
}

const (
	pendingTTL        = 15 * time.Minute
	maxPendingPerUser = 4
)

type pendingDevices struct {
	mu     sync.Mutex
	byUser map[string][]*pendingDevice // account key -> waiting devices
}

// codeAlphabet avoids look-alike characters (0/O, 1/I/L).
const codeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

func newCode() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	out := make([]byte, 0, 9)
	for i, v := range b {
		if i == 4 {
			out = append(out, '-')
		}
		out = append(out, codeAlphabet[int(v)%len(codeAlphabet)])
	}
	return string(out)
}

// add registers a waiting device and returns its pairing code. A device
// that asks again keeps its code.
func (p *pendingDevices) add(user, peerID string, pub []byte, name string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.byUser == nil {
		p.byUser = map[string][]*pendingDevice{}
	}
	key := directory.NameKey(user)
	now := time.Now()
	list := p.byUser[key][:0]
	for _, d := range p.byUser[key] {
		if now.Before(d.expires) {
			list = append(list, d)
		}
	}
	for _, d := range list {
		if d.peerID == peerID {
			d.expires = now.Add(pendingTTL)
			p.byUser[key] = list
			return d.code
		}
	}
	if len(list) >= maxPendingPerUser {
		list = list[1:]
	}
	d := &pendingDevice{peerID: peerID, pubKey: pub, name: name, code: newCode(), expires: now.Add(pendingTTL)}
	p.byUser[key] = append(list, d)
	return d.code
}

// find returns the device waiting on user's account with code.
func (p *pendingDevices) find(user, code string) *pendingDevice {
	p.mu.Lock()
	defer p.mu.Unlock()
	code = strings.ToUpper(strings.TrimSpace(code))
	for _, d := range p.byUser[directory.NameKey(user)] {
		if d.code == code && time.Now().Before(d.expires) {
			return d
		}
	}
	return nil
}

func (p *pendingDevices) done(user, peerID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := directory.NameKey(user)
	list := p.byUser[key][:0]
	for _, d := range p.byUser[key] {
		if d.peerID != peerID {
			list = append(list, d)
		}
	}
	p.byUser[key] = list
}

// devicesOp returns an account's device chain: Target's (public, like a
// lookup), or your own.
func (s *Server) devicesOp(sess *session, req directory.Request) directory.Response {
	user, _ := sess.loggedIn()
	if user == "" {
		return fail(directory.ErrNotLoggedIn)
	}
	name := user
	if req.Target != "" {
		if !directory.ValidUsername(req.Target) {
			return fail(directory.ErrNoSuchUser)
		}
		name = req.Target
	}
	certs, ok := s.accounts.Devices(name)
	if !ok {
		return fail(directory.ErrNoSuchUser)
	}
	var online []directory.Device
	if name == user {
		for _, o := range s.userSessions(name) {
			online = append(online, directory.Device{PeerID: o.peerID, Addr: o.addr})
		}
	}
	return directory.Response{OK: true, User: name, Certs: certs, Devices: online}
}

// devicePending shows the device waiting with a code, so the approving
// device can show its name and ID before signing anything.
func (s *Server) devicePending(sess *session, req directory.Request) directory.Response {
	user, _ := sess.loggedIn()
	if user == "" {
		return fail(directory.ErrNotLoggedIn)
	}
	if !s.authLimit.Allow(sess.ip) {
		return fail(directory.ErrRateLimited) // codes are short; don't let them be guessed
	}
	d := s.pending.find(user, req.Code)
	if d == nil {
		return fail(directory.ErrNoSuchCode)
	}
	return directory.Response{OK: true, Pending: &directory.Pending{PeerID: d.peerID, PubKey: d.pubKey, Name: d.name}}
}

// deviceApprove adds the waiting device, with the certificate this device
// signed for it.
func (s *Server) deviceApprove(sess *session, req directory.Request) directory.Response {
	user, _ := sess.loggedIn()
	if user == "" {
		return fail(directory.ErrNotLoggedIn)
	}
	d := s.pending.find(user, req.Code)
	if d == nil {
		return fail(directory.ErrNoSuchCode)
	}
	c := req.Cert
	if c == nil || c.PeerID != d.peerID || c.By != sess.peerID || string(c.PubKey) != string(d.pubKey) {
		return directory.Response{Error: directory.ErrDevice, Detail: "the approval doesn't match the waiting device"}
	}
	if err := s.accounts.AddDevice(user, *c); err != nil {
		return directory.Response{Error: directory.ErrDevice, Detail: err.Error()}
	}
	s.pending.done(user, d.peerID)
	log.Printf("device added: %s %q (%s), approved by %s", user, c.Name, identity.Short(c.PeerID), identity.Short(sess.peerID))
	return directory.Response{OK: true, User: user}
}

// deviceRemove takes one of your devices off the account and disconnects it.
func (s *Server) deviceRemove(sess *session, req directory.Request) directory.Response {
	user, _ := sess.loggedIn()
	if user == "" {
		return fail(directory.ErrNotLoggedIn)
	}
	err := s.accounts.RemoveDevice(user, req.Target)
	if errors.Is(err, errLastDevice) {
		return directory.Response{Error: directory.ErrDevice, Detail: "that is your only device; add another first, or delete the account"}
	}
	if err != nil {
		return directory.Response{Error: directory.ErrDevice, Detail: err.Error()}
	}
	log.Printf("device removed: %s %s", user, identity.Short(req.Target))
	s.dropDevice(user, req.Target, directory.CodeRemoved, "this device was removed from the account")
	return directory.Response{OK: true, User: user}
}

// dropDevice disconnects one device and deletes its mailbox.
func (s *Server) dropDevice(user, peerID string, code quic.ApplicationErrorCode, why string) {
	if s.mailbox != nil {
		_ = s.mailbox.RemoveDevice(user, peerID)
	}
	s.mu.Lock()
	sess := s.sessions[sessKey(user, peerID)]
	delete(s.sessions, sessKey(user, peerID))
	s.mu.Unlock()
	if sess != nil {
		go func() {
			time.Sleep(300 * time.Millisecond) // let a reply to this device go out first
			_ = sess.conn.CloseWithError(code, why)
		}()
	}
}

// processResets carries out `tariond devices reset` requests.
func (s *Server) processResets() {
	for _, name := range s.resets.Pending() {
		existed, err := s.accounts.ResetDevices(name)
		if err != nil {
			log.Printf("reset devices of %q: %v", name, err)
			continue
		}
		if existed {
			log.Printf("devices reset by the operator: %s (the next password login becomes the first device)", name)
			if s.mailbox != nil {
				_ = s.mailbox.Remove(name)
			}
			for _, o := range s.userSessions(name) {
				s.dropDevice(name, o.peerID, directory.CodeRemoved, "the operator reset this account's devices")
			}
		}
		s.resets.Done(name)
	}
}
