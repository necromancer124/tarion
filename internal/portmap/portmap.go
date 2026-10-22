// Package portmap asks the home router to forward the chat port (UPnP-IGD,
// then NAT-PMP), so peers behind strict NATs can reach this client directly
// without any server relay. When that is impossible it explains why in
// plain words and lists what the user can do instead.
package portmap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// Mapping is a port the router forwards to this computer.
type Mapping struct {
	Method       string // "UPnP" or "NAT-PMP"
	ExternalIP   net.IP
	ExternalPort int
	InternalPort int
	Lease        time.Duration // 0 = permanent until removed

	renew  func(ctx context.Context) error
	remove func(ctx context.Context) error
}

// Addr is the public address peers can dial.
func (m *Mapping) Addr() string {
	return net.JoinHostPort(m.ExternalIP.String(), fmt.Sprint(m.ExternalPort))
}

// Renew refreshes the lease; call it before half the lease has passed.
func (m *Mapping) Renew(ctx context.Context) error {
	if m.renew == nil {
		return nil
	}
	return m.renew(ctx)
}

// Remove deletes the mapping from the router.
func (m *Mapping) Remove(ctx context.Context) error {
	if m.remove == nil {
		return nil
	}
	return m.remove(ctx)
}

// Mapper opens a mapping one way.
type Mapper interface {
	Name() string
	Map(ctx context.Context, localIP net.IP, port int, lease time.Duration) (*Mapping, error)
}

// Default tries UPnP, then NAT-PMP.
func Default() []Mapper { return []Mapper{UPnP{}, NATPMP{}} }

// Attempt is what went wrong with one method, in plain words.
type Attempt struct {
	Method  string
	Problem string
}

// Failure explains why no method worked and what to do about it.
type Failure struct {
	Port     int
	Attempts []Attempt
	Final    string // set when a mapping existed but turned out useless
}

func (f *Failure) Error() string {
	var b strings.Builder
	b.WriteString("automatic port forwarding did not work:\n")
	for _, a := range f.Attempts {
		fmt.Fprintf(&b, "  - %s: %s\n", a.Method, a.Problem)
	}
	if f.Final != "" {
		fmt.Fprintf(&b, "  - %s\n", f.Final)
	}
	b.WriteString(Advice(f.Port))
	return b.String()
}

// Advice lists the user's options when the port can't be opened.
func Advice(port int) string {
	return fmt.Sprintf(`What you can do:
  - turn on UPnP or NAT-PMP in your router's settings, then run: tarion portmap
  - or forward UDP port %d to this computer by hand, then run: tarion start -public-addr YOUR_PUBLIC_IP:%d
  - or turn the relay on (-relay on): messages then pass through the server, still end-to-end encrypted
Without one of these, people behind strict NATs may not reach you. Most home routers still work through hole punching.
`, port, port)
}

// Open tries each mapper in turn and returns the first mapping whose
// external address is actually public.
func Open(ctx context.Context, mappers []Mapper, localIP net.IP, port int, lease time.Duration) (*Mapping, error) {
	f := &Failure{Port: port}
	if localIP == nil {
		f.Attempts = append(f.Attempts, Attempt{"network", "this computer has no LAN address (not connected to a router?)"})
		return nil, f
	}
	for _, m := range mappers {
		mctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		mapping, err := m.Map(mctx, localIP, port, lease)
		cancel()
		if err != nil {
			f.Attempts = append(f.Attempts, Attempt{m.Name(), err.Error()})
			continue
		}
		if problem := NotPublic(mapping.ExternalIP); problem != "" {
			rctx, rcancel := context.WithTimeout(ctx, 3*time.Second)
			_ = mapping.Remove(rctx)
			rcancel()
			f.Attempts = append(f.Attempts, Attempt{m.Name(), "the router forwarded the port, but " + problem})
			// Another method would see the same router address.
			return nil, f
		}
		return mapping, nil
	}
	return nil, f
}

var cgnat = mustCIDR("100.64.0.0/10")

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// NotPublic explains why a router's external address can't be reached
// from the internet, or returns "" if it can.
func NotPublic(ip net.IP) string {
	switch {
	case ip == nil || ip.IsUnspecified():
		return "the router did not report its internet address (it may not be connected yet)"
	case cgnat.Contains(ip):
		return fmt.Sprintf("its internet address %s belongs to your ISP's shared NAT (carrier-grade NAT, common on mobile and some fiber plans): your ISP blocks incoming connections before they reach your router, and forwarding can't change that. Ask your ISP for a public IP address", ip)
	case ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast():
		return fmt.Sprintf("its internet address %s is a private one: your router sits behind another router (double NAT). Forward the port on the outer router too, or put the inner one in bridge mode", ip)
	}
	return ""
}

// DoubleNAT explains a router address that differs from the address the
// server sees for this client.
func DoubleNAT(routerIP, seenIP string) string {
	return fmt.Sprintf("your router reports the internet address %s, but the server sees you as %s: there is another NAT between your router and the internet (often your ISP's), so the forwarded port can't be reached", routerIP, seenIP)
}

// Unreachable explains a mapping that a test packet could not get through.
func Unreachable(addr string, port int) string {
	return fmt.Sprintf("the router says UDP port %d is forwarded, but a test packet the server sent to %s from another port did not arrive. Usually a firewall blocks it: allow tarion (UDP %d) in Windows Firewall or your router's firewall, then run: tarion portmap", port, addr, port)
}

var errTimeout = errors.New("timed out")
