# Tarion protocol

This describes what goes over the wire, so others can build compatible
clients or servers. The reference implementation is this repository; where
the two disagree, the code wins and this page is a bug.

## Transport and identity

- Everything is QUIC (RFC 9000) over UDP with TLS 1.3. Key exchange prefers
  the post-quantum hybrid X25519MLKEM768.
- Every endpoint authenticates with an **Ed25519 identity key** carried in a
  self-signed X.509 certificate. Both sides present one (mutual TLS); no CA
  is involved. The certificate is only a container: peers check the key.
- **Peer ID** = the first 20 bytes of SHA-256(raw Ed25519 public key),
  base32 lower case without padding (32 characters). It's displayed in
  groups of four.
- A client uses **one UDP socket** for chat, the directory connection,
  relay and probe packets, so the address the server observes is the one
  peers can reach.

## Framing

Each request or message uses one bidirectional QUIC stream. Each direction
sends one frame: a 4-byte big-endian length, then that many bytes of JSON.
Frames are at most 64 KiB.

## Chat (ALPN `tarion/2`)

No SNI is sent. The sender opens a stream and writes:

```json
{"v":2,"type":"msg","id":"<hex, up to 64 bytes>","ts":1767225600,"from":"alice","body":"hi"}
```

The receiver answers with one of:

```json
{"v":2,"type":"ack","id":"<same id>"}
{"v":2,"type":"nack","id":"<same id>","error":"receiver busy"}
```

- `body` is UTF-8, 1 to 16 KiB; `from` is a display name the sender claims
  (at most 64 bytes) and proves nothing: the TLS key is the identity.
- A receiver delivers each (peer ID, id) once for 10 minutes, so senders can
  retry after a lost ack. All of a user's devices get the same id.
- `nack` with an error is final ("this user only accepts messages from
  contacts", a banned key), except "receiver busy", which a sender may retry.

## Directory (ALPN `tarion-dir/1`)

Requests and responses are the `Request` and `Response` structs in
[internal/directory/proto.go](../internal/directory/proto.go). A response
has `ok` and, on failure, an `error` code and sometimes a human-readable
`detail`.

| Op | Purpose |
|---|---|
| register | create an account; this device becomes its first |
| login | with a password, or with a device key already on the account |
| list | names of online users |
| lookup | a user's online devices (address, key, LAN address when sharing a public IP) and signed device chain; also asks each device to punch toward you |
| relay | open a relay session to one of a user's devices |
| advertise | set or clear an address you made reachable yourself |
| probe | ask for a test packet to that address from another port |
| change_password, delete_account | account management, with the current password |
| mailbox_key, mailbox_put, mailbox_fetch, mailbox_ack | the optional mailbox |
| devices, device_pending, device_approve, device_remove | device chains and approval |

The server also opens streams to a logged-in client to push:
`punch` (send a few punch packets to this address), `revoked` (the full ban
list), `relay` (accept packets for this relay session) and `mail` (a letter
arrived). The QUIC connection's close code tells a client why it was
signed out: 3 replaced by a newer login of the same device, 4 banned,
5 account deleted, 6 device removed.

A password login from a device that isn't on the account fails with
`device_not_approved` and a pairing code in `detail`.

## Device chains

An account's devices are certificates (`internal/devices`):

```
account, peer_id, pub_key, name, added, by, sig, removed
```

The first device has no `by`. Every other one is signed by the device that
approved it, over:

```
"tarion-device-v1" \n account \n peer_id \n hex(pub_key) \n name \n added \n by
```

Clients pin a contact's first device and accept another key for that name
only if a signature chain leads to it from the pin. Trust only flows from
an approver to the device it approved, never back up. Removed devices stay
in the chain, marked removed.

## Small UDP packets

These share the client's socket with QUIC; their first byte is 0x00, which
QUIC ignores.

| Packet | Format |
|---|---|
| Punch | `0x00 'T' 'P' 'U' 'N' 'C' 'H'` (7 bytes) |
| Relay | `0x00 'T' 'R' 'L'` + 8-byte session ID + an unchanged QUIC packet |
| Probe | `0x00 'T' 'P' 'R'` + 8-byte nonce, from the server's second port |

The server forwards relay packets only between the two addresses of a
session, which it learned from their logged-in connections.

## Mailbox letters

Each device publishes an X25519 **box key**, derived from its Ed25519 seed
(SHA-512, first 32 bytes, clamped), with an Ed25519 signature over
`"tarion-mailbox-key-v1:" || box_key`. A letter is JSON:

```json
{"v":1,"id":"...","ts":1767225600,"from":"alice","from_key":"<base64>","to":"<recipient peer ID>","body":"...","sig":"<base64>"}
```

`sig` is Ed25519 by `from_key` over
`"tarion-letter-v1" \n id \n ts \n from \n hex(from_key) \n to \n body`.
The JSON is sealed to the recipient device's box key with NaCl's anonymous
box (X25519 + XSalsa20-Poly1305) and stored by the server as opaque bytes,
at most 40 KiB.
