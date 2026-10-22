package portmap

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/huin/goupnp/soap"
)

// fake is a router that answers with a fixed result.
type fake struct {
	name    string
	ext     net.IP
	err     error
	removed bool
}

func (f *fake) Name() string { return f.name }
func (f *fake) Map(ctx context.Context, localIP net.IP, port int, lease time.Duration) (*Mapping, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &Mapping{Method: f.name, ExternalIP: f.ext, ExternalPort: port, InternalPort: port, Lease: lease,
		remove: func(context.Context) error { f.removed = true; return nil }}, nil
}

var lan = net.ParseIP("192.168.1.10")

func TestOpenUsesFirstWorkingMethod(t *testing.T) {
	upnp := &fake{name: "UPnP", err: errors.New("no UPnP router answered")}
	pmp := &fake{name: "NAT-PMP", ext: net.ParseIP("203.0.113.7")}
	m, err := Open(context.Background(), []Mapper{upnp, pmp}, lan, 63426, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if m.Method != "NAT-PMP" || m.Addr() != "203.0.113.7:63426" {
		t.Fatalf("mapping: %+v", m)
	}
}

func TestOpenExplainsEveryFailure(t *testing.T) {
	_, err := Open(context.Background(), []Mapper{
		&fake{name: "UPnP", err: errors.New("no UPnP router answered on your network")},
		&fake{name: "NAT-PMP", err: errors.New("your router (192.168.1.1) did not answer")},
	}, lan, 63426, time.Hour)
	var f *Failure
	if !errors.As(err, &f) || len(f.Attempts) != 2 {
		t.Fatalf("expected a Failure listing both methods, got %v", err)
	}
	msg := err.Error()
	for _, want := range []string{"UPnP: no UPnP router", "NAT-PMP: your router", "tarion portmap", "-public-addr", "-relay on"} {
		if !strings.Contains(msg, want) {
			t.Errorf("explanation lacks %q:\n%s", want, msg)
		}
	}
}

func TestOpenRejectsNonPublicRouterAddress(t *testing.T) {
	for ip, want := range map[string]string{
		"100.72.4.9":   "carrier-grade NAT",
		"192.168.0.20": "double NAT",
		"0.0.0.0":      "did not report",
	} {
		r := &fake{name: "UPnP", ext: net.ParseIP(ip)}
		_, err := Open(context.Background(), []Mapper{r, &fake{name: "NAT-PMP", ext: net.ParseIP("203.0.113.7")}}, lan, 63426, time.Hour)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: expected %q, got %v", ip, want, err)
		}
		if !r.removed {
			t.Errorf("%s: a useless mapping must be removed again", ip)
		}
	}
	if NotPublic(net.ParseIP("203.0.113.7")) != "" {
		t.Error("a public address was rejected")
	}
}

func TestOpenWithoutLANAddress(t *testing.T) {
	if _, err := Open(context.Background(), Default(), nil, 63426, time.Hour); err == nil || !strings.Contains(err.Error(), "no LAN address") {
		t.Fatalf("got %v", err)
	}
}

func TestExplainUPnPErrors(t *testing.T) {
	fault := func(code int) error {
		f := &soap.SOAPFaultError{FaultString: "UPnPError"}
		f.Detail.UPnPError.Errorcode = code
		return f
	}
	for code, want := range map[int]string{
		606: "not port forwarding changes",
		718: "another device",
		728: "table is full",
		999: "refused the request",
	} {
		if got := explainUPnP(fault(code)); !strings.Contains(got, want) {
			t.Errorf("code %d: %q", code, got)
		}
	}
	if got := explainUPnP(errors.New("connection reset")); !strings.Contains(got, "did not answer correctly") {
		t.Errorf("plain error: %q", got)
	}
}
