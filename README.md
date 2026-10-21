# Tarion

Tarion is a hybrid peer-to-peer CLI chat over QUIC. Chats go directly between peers. A small directory server, `tariond` in [`server/`](server/README.md), tells peers where to find each other and helps them through home routers (NAT). Every install has its own Ed25519 identity key, and peers authenticate each other with it (see [Security model](#security-model)).

## Ports

| Who | Port | Default | Change it with |
|---|---|---|---|
| Client: chat **and** server traffic | UDP | `63426` | `-p` / `"port"` |
| Client: background control socket (local only) | TCP | `-p` ± 10000 (`53426`) | `-cp` / `"control_port"` |
| Server (`tariond`) | UDP | `63425` | `tariond -port`, and in the client's `-server host:port` |

The client uses **one** UDP port for everything. The server only sees the public address of the socket that talks to it, so logging in from the chat socket means the address the server hands out is exactly the one peers can reach, including behind a router.

## Commands

Start the interactive client, log in, and listen:

```powershell
.\tarion.exe start -server SERVER:63425 -user alice -pass "a long passphrase"
```

`-pass` is only needed the first time on each device. That login links the device's key to your account, and the password is then removed from `config.json`. After that, `.\tarion.exe start` is enough. The first login with a new name creates the account (10+ characters, not containing your username). If the server is invite-only, add `-invite CODE` the first time; the operator creates codes with `tariond invite`.

Run the listener detached, without keeping the terminal open:

```powershell
.\tarion.exe background --detach -server SERVER:63425 -user alice -pass "a long passphrase"
```

This works on Windows and Linux. The background process keeps running after you close the terminal and saves incoming messages to local history. Run `tarion.exe menu` in another terminal to read chats and send through it. The menu talks to it over the local control socket, so the background process owns the UDP port.

Send one message through the background process, print incoming messages as JSON lines, or show a chat (handy for scripts and bots; see the [local API](docs/local-api.md) to build an app):

```powershell
.\tarion.exe send bob "hello"
.\tarion.exe listen
.\tarion.exe history -n 20 bob
```

Only accept messages from people you know (contacts in `config.json`, people you messaged, and people who messaged you before):

```powershell
.\tarion.exe start -accept contacts
```

Stop the detached background process:

```powershell
.\tarion.exe stop
```

Logs are written to:

```text
%APPDATA%\tarion\background.log
```

Direct/self-test chat, without a server:

```powershell
.\tarion.exe start -u Myself -i 127.0.0.1:63426
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
$env:TARION_HOME = "$env:TEMP\tarion-bob"; .\tarion.exe start -p 63427
```

Delete local chat history:

```powershell
.\tarion.exe start -wipe-history
```

## Menu behavior

- The menu always includes saved history chats, even when they are offline.
- Offline saved chats are tagged `[offline]`.
- Online users come from the server's list; the server connection state is shown under the list.
- New incoming messages mark chats as `[NEW]`.
- `r` refreshes immediately; the menu also refreshes automatically.

## Config

The config is saved to:

```text
%APPDATA%\tarion\config.json
```

```json
{
  "server_addr": "198.51.100.5:63425",
  "server_id": "obzxpkfgynwsfxwfv4ysohdj2d4euri7",
  "username": "alice",
  "port": 63426,
  "contacts": [
    { "name": "bob", "addr": "192.168.1.20:63426" },
    { "name": "carol", "addr": "203.0.113.7:63426", "id": "owft vlcv d5sm kq6u f7hm 7dj5 6geo f2ni" }
  ]
}
```

- `server_id` is the server's key. It's pinned automatically on the first connection. If the server's key ever changes, the client refuses to log in. Delete the field only if you know the server was reinstalled. Server operators can print it with `tariond id`.
- `contacts` are optional. A contact with an `addr` can be reached without the server. Its `id` is also optional: when set, Tarion only talks to the peer holding that key. Without it, the first key that answers gets pinned (trust on first use).
- `control_port` is optional (see [Ports](#ports)).
- `accept` is `anyone` (default) or `contacts` (see above). Strangers who write to you then get "this user only accepts messages from contacts".

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
- **Encryption.** Every connection is QUIC with TLS 1.3 (AES-GCM) and a post-quantum hybrid key exchange (X25519MLKEM768), so recorded traffic stays private even against a future quantum computer. The Ed25519 identity keys are not post-quantum.
- **Server login.** The password is only ever sent inside that encrypted connection. It links your account to your device's key; later logins use the key alone, and the password isn't stored on your device. The server stores argon2id hashes (64 MiB, 3 passes), requires 10+ character passwords for new accounts, rate-limits logins and registrations, and checks usernames (1–32 letters/digits plus `. _ -`, not case-sensitive). Operators can make the server invite-only and ban users or keys.
- **Server pinning.** The client pins the server's key (`server_id`), so an impostor server can't collect passwords.
- **Pinning.** The first time you talk to a name, its peer ID is pinned in `peers.json`. If that name later answers with a different key, sending is refused. When the server knows a user, it also reports their key, and the key that answers must match it too. A new key that claims a pinned name shows up as a separate chat such as `bob~1a2b3c4d`, so it can't pose as Bob.
- **Delivery.** Each message carries an ID and waits for the receiver's acknowledgement. The menu shows `delivered` or `not delivered: <reason>`, and failed sends are marked in the history. Duplicate deliveries are dropped.
- **Limits.** Frames are capped at 64 KiB and message bodies at 16 KiB. Connections and requests are capped. Control characters are stripped from incoming text so a peer can't inject terminal escape sequences.
- **Local control.** The background process's control port only accepts requests carrying the random token from `control.token`, which only your OS user can read.

### How a message finds its way

1. The client keeps a QUIC connection to `tariond` open from its chat port. Its keep-alives are the heartbeat, and they also keep the router's mapping for that port open.
2. To message bob, the client asks the server for bob. The server answers with bob's public address, his key, and (only if you're behind the same router) his LAN address.
3. At the same moment, the server tells bob, over his open connection, to send a few tiny packets toward your address. That opens bob's router for your incoming connection (NAT hole punching).
4. The client connects to bob directly: LAN address first, public address second. The message never passes through the server.

### Wire protocol

Chat uses ALPN `tarion/2`, with one bidirectional QUIC stream per message. Each direction sends one frame: a 4-byte big-endian length followed by JSON.

```json
{"v":2,"type":"msg","id":"<128-bit hex>","ts":1767225600,"from":"alice","body":"hi"}
{"v":2,"type":"ack","id":"<same id>"}
{"v":2,"type":"nack","id":"<same id>","error":"receiver busy"}
```

The directory uses ALPN `tarion-dir/1` with the same framing; see [`internal/directory/proto.go`](internal/directory/proto.go). Punch packets are 7-byte UDP datagrams whose first byte is `0x00`, so QUIC ignores them.

### Firewalls

- **What a firewall can see:** UDP packets between your IP and the server or peers, their sizes and timing, and that they are QUIC with the ALPN `tarion/2` or `tarion-dir/1`. Chat connections send no server name (SNI). The certificates, and so the identity keys, are encrypted in TLS 1.3.
- **What it can't see:** messages, usernames, passwords, or the server's password hashes (those never leave the server). There is nothing in the traffic to "crack".
- **TLS-inspecting firewalls** (company proxies with their own root certificate) can't read Tarion either. Peers and the server are pinned by key, not trusted through certificate authorities, so an interception attempt makes the connection fail instead of being decrypted.
- **Blocking:** a firewall can still block Tarion, either by ALPN or by blocking UDP altogether (common on company and school networks). Tarion then can't connect; a TCP/relay fallback is tracked in #13.
- **Your own PC's firewall** (Windows Defender may ask the first time): allowing it is best. If you decline, connections still work, because Tarion punches outward first, which opens a temporary opening for that peer.
- **Server:** open UDP 63425 inbound. Clients need no inbound rules or port forwarding.

### Known limitations

- Hole punching works with most home routers but can fail when both sides are behind strict ("symmetric") NATs, such as some mobile carriers, or on networks that block UDP. A relay fallback is tracked in #13.
- Messages to offline peers fail instead of being queued (#14).
- One device per account (#15).
- `identity.key` and the history are stored unencrypted, protected by file permissions (#16).
- Trust on first use: on the very first contact you trust the key the server reports. Compare `tarion id` with your contact, or put their `id` in `config.json`, to rule that out.

## Privacy

The server handles login and address lookup only. Chats go directly peer-to-peer over mutually authenticated TLS 1.3 and are never relayed through the server. The server's user list shows names only, not IP addresses. Local history is stored as plain text in the config folder with owner-only permissions.
