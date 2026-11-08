# network: ports, NAT and how a message finds its way

| Who | Protocol | Default | Change it with |
|---|---|---|---|
| Client: chat and server traffic | UDP | 63426 | `-p` / "port" |
| Client: background control socket (local only) | TCP | `-p` plus 10000 (53426) | `-cp` / "control_port" |
| Server (tariond) | UDP | 63425 | `tariond -port`, and the client's `-server host:port` |

The client uses one UDP port for everything, so the address the server sees
is exactly the one peers can reach, even behind a router.

## How a message finds its way

1. The client keeps a QUIC connection to the server open. Its keep-alives
   are the heartbeat and keep your router's mapping for the port open.
2. To message bob, the client asks the server for bob: his online devices,
   their public addresses and keys, and his LAN address if you share a
   router.
3. At the same moment the server asks bob's devices to send a few tiny
   packets toward you, which opens bob's router for you (hole punching).
4. Your client connects straight to each of bob's devices: LAN address
   first, then a port bob forwarded, then the public address.
5. If none answer: the relay, if you both turned it on; else bob's server
   mailbox, if you both use it and he's offline (or unreachable for a
   minute); else your outbox, which keeps retrying for 7 days.

Hole punching works with most home routers. For strict ("symmetric") NATs,
see `tarion help portmap` and `tarion help relay`. Networks that block UDP
completely can't use Tarion yet.

See also: portmap, firewall, relay, mailbox, outbox.
