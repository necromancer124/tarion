# Tarion Client

Tarion is a hybrid peer-to-peer CLI chat client using QUIC over UDP port `63425` by default. Every install has its own Ed25519 identity key, and peers authenticate each other with it (see [Security model](#security-model)).

## Commands

Open the interactive menu/TUI:

```powershell
.\tarion.exe menu
```

Start the interactive client and connect/listen:

```powershell
.\tarion.exe start -server 127.0.0.1:63425 -user alice -pass secret
```

Run the listener detached, without keeping the terminal open:

```powershell
.\tarion.exe background --detach -server 127.0.0.1:63425 -user alice -pass secret
```

This works on Windows and Linux. It starts a detached Tarion background process that keeps running after you close the terminal. Incoming messages are saved to local history. You can open another terminal and run `tarion.exe menu` to read saved chats and send through the background process. The menu talks to the background process over a local control socket, so the background process owns the QUIC listener port.

Stop the detached background process:

```powershell
.\tarion.exe stop
```

Logs are written to:

```text
%APPDATA%\tarion\background.log
```

Direct/self-test chat:

```powershell
.\tarion.exe start -p 63426 -u Myself -i 127.0.0.1:63426
```

Show your peer ID (read it to contacts so they can verify you):

```powershell
.\tarion.exe id
```

List pinned contacts, or forget one whose key legitimately changed (for example after they reinstalled):

```powershell
.\tarion.exe peers
.\tarion.exe forget bob
```

Run a second instance with its own identity on the same machine:

```powershell
$env:TARION_HOME = "$env:TEMP\tarion-bob"; .\tarion.exe start -p 63426
```

Delete local chat history:

```powershell
.\tarion.exe start -wipe-history
```

## Menu behavior

- The menu always includes saved history chats, even when they are offline.
- Offline saved chats are tagged `[offline]`.
- Online users are refreshed from the server when configured.
- New incoming messages mark chats as `[NEW]`.
- `r` refreshes immediately; the menu also refreshes automatically.

## Config

The config is saved to:

```text
%APPDATA%\tarion\config.json
```

It can contain contacts:

```json
{
  "server_addr": "127.0.0.1:63425",
  "username": "alice",
  "password": "secret",
  "port": 63425,
  "contacts": [
    { "name": "bob", "addr": "127.0.0.1:63426" },
    { "name": "carol", "addr": "203.0.113.7:63425", "id": "owft vlcv d5sm kq6u f7hm 7dj5 6geo f2ni" }
  ]
}
```

`id` is optional. When set, Tarion only talks to the peer holding that key. Without it, the first key that answers for a name gets pinned (trust on first use).

The folder also holds `identity.key` (your private key, keep it secret), `peers.json` (pinned contacts) and, while the background process runs, `control.token`.

## Controls

- `↑` / `↓` or `k` / `j`: navigate contacts
- `Enter`: open selected chat / send typed message
- `Esc`: leave chat view and return to menu
- `h` or `?`: open/close help
- `r`: refresh directory/history now
- `q` or `Ctrl+C`: quit

## Security model

- **Identity.** `identity.key` is an Ed25519 key created on first run. Your peer ID is a hash of its public key. Both sides present their key in the QUIC/TLS 1.3 handshake (mutual TLS), so a peer ID cannot be claimed without owning the private key.
- **Pinning.** The first time you talk to a name, its peer ID is pinned in `peers.json`. If that name later answers with a different key, sending is refused. A new key that claims a pinned name shows up as a separate chat such as `bob~1a2b3c4d`, so it can't pose as Bob. The name a peer sends is only a display hint and never overrides a pin.
- **Delivery.** Each message carries an ID and waits for the receiver's acknowledgement. The menu shows `delivered` or `not delivered: <reason>`, and failed sends are marked in the history. Duplicate deliveries are dropped.
- **Limits.** Frames are capped at 64 KiB and message bodies at 16 KiB. Concurrent connections are capped. Control characters are stripped from incoming text so a peer can't inject terminal escape sequences.
- **Local control.** The background process's control port only accepts requests carrying the random token from `control.token`, which only your OS user can read.

### Wire protocol (v2)

ALPN `tarion/2`. One bidirectional QUIC stream per message. Each direction sends one frame: a 4-byte big-endian length followed by JSON.

```json
{"v":2,"type":"msg","id":"<128-bit hex>","ts":1767225600,"from":"alice","body":"hi"}
{"v":2,"type":"ack","id":"<same id>"}
{"v":2,"type":"nack","id":"<same id>","error":"receiver busy"}
```

Listening and dialing share one UDP socket, so the receiver sees your real reply address, and connections to a peer are reused. v1 clients (`tarion-p2p`) are not compatible and fail the handshake.

### Known limitations

- The directory server protocol is still plain-text UDP (`REG|user|pass`), so the directory password is visible on the network. The server needs to change for this to be fixed: key-signed registration instead of a password, and a marker byte so its replies can share the QUIC socket for NAT hole punching. Pinning means a lying directory can't impersonate a contact you already talked to, but it can still pick who you reach on first contact.
- There is no NAT hole punching or relay yet, so peers behind different NATs may not reach each other.
- Messages to offline peers fail instead of being queued.

## Privacy

The server is only for authentication and peer address discovery. Chat payloads are sent directly peer-to-peer over mutually authenticated TLS 1.3 and are not relayed through the server. Local history is stored as plain text in the config folder with owner-only permissions.
