package portmap

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/jackpal/gateway"
	natpmp "github.com/jackpal/go-nat-pmp"
)

// NATPMP opens a mapping with NAT-PMP (used by Apple routers and many
// others; PCP-capable routers usually still answer it).
type NATPMP struct{}

func (NATPMP) Name() string { return "NAT-PMP" }

// within runs f, giving up when ctx ends (the library calls block).
func within[T any](ctx context.Context, f func() (T, error)) (T, error) {
	type result struct {
		v   T
		err error
	}
	ch := make(chan result, 1)
	go func() {
		v, err := f()
		ch <- result{v, err}
	}()
	select {
	case r := <-ch:
		return r.v, r.err
	case <-ctx.Done():
		var zero T
		return zero, errTimeout
	}
}

func explainNATPMP(gw net.IP, err error) string {
	msg := err.Error()
	switch {
	case err == errTimeout || strings.Contains(msg, "timed out") || strings.Contains(msg, "timeout"):
		return fmt.Sprintf("your router (%s) did not answer; NAT-PMP is probably not supported or turned off", gw)
	case strings.Contains(msg, "result code 2"):
		return "the router refused: NAT-PMP is turned off or not allowed for this computer"
	case strings.Contains(msg, "result code 3"):
		return "the router has no internet connection right now"
	case strings.Contains(msg, "result code 4"):
		return "the router's port forwarding table is full"
	case strings.Contains(msg, "version 2"):
		return "the router only speaks PCP, the newer protocol, which Tarion doesn't support yet"
	}
	return fmt.Sprintf("the router did not answer correctly (%v)", err)
}

func (NATPMP) Map(ctx context.Context, localIP net.IP, port int, lease time.Duration) (*Mapping, error) {
	gw, err := within(ctx, gateway.DiscoverGateway)
	if err != nil {
		return nil, fmt.Errorf("couldn't find your router's address (%v)", err)
	}
	c := natpmp.NewClientWithTimeout(gw, 4*time.Second)
	ext, err := within(ctx, c.GetExternalAddress)
	if err != nil {
		return nil, fmt.Errorf("%s", explainNATPMP(gw, err))
	}
	add := func(ctx context.Context, seconds int) (*natpmp.AddPortMappingResult, error) {
		return within(ctx, func() (*natpmp.AddPortMappingResult, error) {
			return c.AddPortMapping("udp", port, port, seconds)
		})
	}
	res, err := add(ctx, int(lease.Seconds()))
	if err != nil {
		return nil, fmt.Errorf("%s", explainNATPMP(gw, err))
	}
	return &Mapping{
		Method:       "NAT-PMP",
		ExternalIP:   net.IP(ext.ExternalIPAddress[:]),
		ExternalPort: int(res.MappedExternalPort),
		InternalPort: port,
		Lease:        time.Duration(res.PortMappingLifetimeInSeconds) * time.Second,
		renew: func(ctx context.Context) error {
			_, err := add(ctx, int(lease.Seconds()))
			return err
		},
		remove: func(ctx context.Context) error {
			_, err := add(ctx, 0) // lifetime 0 deletes the mapping
			return err
		},
	}, nil
}
