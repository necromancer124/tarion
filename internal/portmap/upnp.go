package portmap

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"time"

	"github.com/huin/goupnp/dcps/internetgateway2"
	"github.com/huin/goupnp/soap"
)

// UPnP opens a mapping with UPnP-IGD (WANIPConnection 1/2 or
// WANPPPConnection 1), the most common way routers allow it.
type UPnP struct{}

func (UPnP) Name() string { return "UPnP" }

// igd is the part of the WANIPConnection/WANPPPConnection services we use.
type igd interface {
	GetExternalIPAddressCtx(ctx context.Context) (string, error)
	AddPortMappingCtx(ctx context.Context, remoteHost string, externalPort uint16, protocol string,
		internalPort uint16, internalClient string, enabled bool, description string, leaseSeconds uint32) error
	DeletePortMappingCtx(ctx context.Context, remoteHost string, externalPort uint16, protocol string) error
}

func discover(ctx context.Context) []igd {
	var out []igd
	if cs, _, err := internetgateway2.NewWANIPConnection2ClientsCtx(ctx); err == nil {
		for _, c := range cs {
			out = append(out, c)
		}
	}
	if cs, _, err := internetgateway2.NewWANIPConnection1ClientsCtx(ctx); err == nil {
		for _, c := range cs {
			out = append(out, c)
		}
	}
	if cs, _, err := internetgateway2.NewWANPPPConnection1ClientsCtx(ctx); err == nil {
		for _, c := range cs {
			out = append(out, c)
		}
	}
	return out
}

// UPnP error codes from the IGD specification.
const (
	upnpActionFailed    = 501
	upnpNotAuthorized   = 606
	upnpConflict        = 718
	upnpSamePortOnly    = 724
	upnpPermanentOnly   = 725
	upnpWildcardExtOnly = 727
	upnpNoMapsAvailable = 728
)

func faultCode(err error) int {
	var fault *soap.SOAPFaultError
	if errors.As(err, &fault) {
		return fault.Detail.UPnPError.Errorcode
	}
	return 0
}

// explainUPnP turns a router's answer into something a person can act on.
func explainUPnP(err error) string {
	switch faultCode(err) {
	case upnpNotAuthorized, 401:
		return "the router refused: it allows UPnP queries but not port forwarding changes (look for a UPnP 'allow port mapping' or 'secure mode' setting)"
	case upnpConflict:
		return "the router already forwards that port to another device on your network"
	case upnpNoMapsAvailable:
		return "the router's port forwarding table is full"
	case upnpWildcardExtOnly:
		return "the router only supports forwarding every external port, which Tarion won't ask for"
	case upnpActionFailed:
		return "UPnP is on, but the router failed to add the forward (error 501, \"Action Failed\"), even as a permanent one and on other ports. Some routers need an extra setting such as \"Allow port mapping\" or \"UPnP port forwarding\", or don't allow UDP forwards through UPnP"
	case 0:
		if errors.Is(err, context.DeadlineExceeded) {
			return "the router stopped answering UPnP requests in time"
		}
		return fmt.Sprintf("the router did not answer correctly (%v)", err)
	}
	return fmt.Sprintf("the router refused the request (%v)", err)
}

// explainRefusesEverything covers routers that answer UPnP discovery but
// refuse every request, even asking for their internet address.
func explainRefusesEverything(err error) string {
	if faultCode(err) == 0 {
		return "the router answers UPnP discovery but " + explainUPnP(err) + "; its UPnP may be limited or switched off for changes"
	}
	if faultCode(err) == upnpActionFailed {
		return "the router answers UPnP but refuses every request, even asking for its internet address (error 501, \"Action Failed\"). Its UPnP is probably limited or locked, which ISP routers often do, or this router isn't the one connected to the internet because another box from your ISP sits in front of it"
	}
	return "the router answers UPnP but refused to say what its internet address is: " + explainUPnP(err)
}

func (UPnP) Map(ctx context.Context, localIP net.IP, port int, lease time.Duration) (*Mapping, error) {
	clients := discover(ctx)
	if len(clients) == 0 {
		return nil, errors.New("no UPnP router answered on your network; UPnP is probably turned off in the router's settings")
	}
	problem := ""
	for _, c := range clients {
		// Some routers refuse this question but still forward ports; the
		// caller then takes the address from the server, and the server's
		// test packet decides whether it works.
		extIP, extErr := c.GetExternalIPAddressCtx(ctx)
		if extErr != nil && faultCode(extErr) == 0 {
			// No proper answer at all (timeout, broken HTTP): asking it
			// to forward a port would only wait out the same way.
			problem = explainRefusesEverything(extErr)
			continue
		}
		// The usual port first; if another device took it, a few others.
		ports := []int{port, port + 1, 49152 + rand.IntN(16000)}
		for i, ext := range ports {
			if ext > 65535 {
				continue
			}
			leaseSec := uint32(lease.Seconds())
			add := func(ctx context.Context) error {
				return c.AddPortMappingCtx(ctx, "", uint16(ext), "UDP", uint16(port), localIP.String(), true, "Tarion", leaseSec)
			}
			err := add(ctx)
			if code := faultCode(err); code == upnpPermanentOnly || code == upnpActionFailed {
				// Many routers answer the generic 501 instead of 725 when
				// they don't support leases. A permanent forward is
				// removed when Tarion exits.
				leaseSec = 0
				err = add(ctx)
			}
			if err == nil {
				extPort := ext
				var external net.IP // nil: unknown, see above
				if extErr == nil {
					external = net.ParseIP(extIP)
				}
				return &Mapping{
					Method:       "UPnP",
					ExternalIP:   external,
					ExternalPort: extPort,
					InternalPort: port,
					Lease:        time.Duration(leaseSec) * time.Second,
					renew:        add,
					remove: func(ctx context.Context) error {
						return c.DeletePortMappingCtx(ctx, "", uint16(extPort), "UDP")
					},
				}, nil
			}
			problem = explainUPnP(err)
			if extErr != nil {
				// The router refused even the read-only question; that is
				// the more telling failure.
				problem = explainRefusesEverything(extErr)
			}
			code := faultCode(err)
			if code == upnpSamePortOnly && i == 0 {
				break // only the same port works and it was refused
			}
			if code != upnpConflict && code != upnpActionFailed {
				break // 718/501 might be about this port; anything else won't change
			}
		}
	}
	return nil, errors.New(problem)
}
