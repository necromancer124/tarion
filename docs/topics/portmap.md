# portmap: let your router forward the chat port

By default (while the relay is off) Tarion asks your router to forward its
chat port, with UPnP first, then NAT-PMP. It checks the result for real: the
server sends a test packet from a different port, the way a stranger would,
and only if it arrives is the forward kept and given to people who look you
up.

```
tarion portmap        # try again now and explain the result
```

The forward is renewed while Tarion runs and removed when it exits. If
Tarion is killed instead, the router drops it within an hour (it asks for a
one-hour lease), except routers that only allow permanent forwards: those
keep it until Tarion's next start replaces it, or you delete it in the
router's settings.

## When it fails, Tarion says why

- No UPnP or NAT-PMP router answered (turn it on in the router's settings).
- The router refused, or the port is taken by another device.
- Your ISP shares one address between customers (carrier-grade NAT, common
  on mobile and some fiber plans): forwarding can't help; ask for a public IP.
- There's a second router (double NAT): forward on the outer one too.
- A firewall dropped the test packet: on Windows, Tarion checks Windows
  Firewall and tells you if it's the cause (see `tarion help firewall`).

## Doing it yourself

Forward UDP to your chat port on the router, then tell Tarion:

```
tarion start -public-addr YOUR_PUBLIC_IP:63426     # a DNS name works too
```

`-public-addr none` clears it. `-port-mapping off` stops the automatic
forwarding; `-port-mapping on` uses it even with the relay on.

See also: firewall, relay, network.
