# relay: when no direct path exists

When both people are behind strict NATs and no port is forwarded, the
server can forward the encrypted packets between you. It's off by default
and only works when all three agree:

- the operator runs `tariond -relay`,
- you run with `-relay on`,
- and so does the other person.

You still run your own end-to-end encrypted handshake inside it and keys are
checked as usual, so the server only sees ciphertext, but your traffic does
pass through it. A client with the relay off never uses it and refuses
relayed connections.

After needing the relay, messages to that contact use it right away for 10
minutes, so they don't wait for direct attempts to time out first.

```
tarion start -relay on      # saved; -relay off turns it off again
```

Testing: set `TARION_SIMULATE_STRICT_NAT=1` before starting a client. It
then drops every direct packet from peers, like a strict NAT.

See also: portmap, network, mailbox.
