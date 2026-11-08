# keys: identity, peer IDs, verifying contacts and key changes

Every Tarion install has its own Ed25519 identity key (`identity.key`). Your
peer ID is a hash of its public key, shown in groups of four:

```
tarion id        # your peer ID; read it to contacts so they can verify you
tarion peers     # contacts you've pinned and their IDs
tarion forget bob
```

## Pinning (trust on first use)

The first time you talk to someone, Tarion remembers ("pins") their key.
From then on it only talks to that key under that name. Every connection
proves the key with mutual TLS 1.3, so nobody can claim an ID without
owning the private key.

To rule out a fake on the very first contact, compare IDs another way
(in person, on a call), or put their ID in config.json:

```json
{ "name": "carol", "addr": "203.0.113.7:63426", "id": "owft vlcv d5sm kq6u f7hm 7dj5 6geo f2ni" }
```

## "identity of bob changed"

Tarion refuses to send when a pinned contact answers with a different key.
That is either an impostor or a real reinstall. Check the new ID with them;
if it's really them:

```
tarion forget bob
```

The next key that answers for "bob" gets pinned.

A contact's new device is not a key change: devices are approved and signed
by their other devices, and Tarion verifies that (see `tarion help devices`).

## Someone else using a pinned name

A new key that claims a name you've already pinned shows up as
`bob~1a2b3c4d`, never as "bob".

See also: devices, protect.
