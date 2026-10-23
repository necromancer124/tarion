# Tarion

**No middleman. No doorman. You open your own doors.**

Tarion is a hybrid peer-to-peer CLI chat over QUIC. Chats go directly between peers. A small directory server, `tariond` in [`server/`](server/README.md), tells peers where to find each other and helps them through home routers (NAT). Every install has its own Ed25519 identity key, and peers authenticate each other with it (see [Security model](#security-model)).

## Why I built Tarion

I got tired of hearing about data. Data, data and more data: who collects it, who sells it, who reads it, which company is training on it this week. Every app wants to sit between me and the people I talk to, and every one of them promises it's safe there. I find that obnoxious.

So this is my answer: **no middleman, no doorman. You open your own doors.**

- **No middleman.** Your messages go straight from your device to the other person's. Nobody stores them, nobody forwards them, and nobody can read them on the way, because they're end-to-end encrypted with keys that never leave your device. There's a relay for networks that make a direct connection impossible, and a mailbox for people who are offline, but both are off unless you, the other person and the server operator all turn them on. Even then the relay only passes along encrypted packets it can't read, and the mailbox only holds letters sealed to the recipient's key.
- **No doorman.** Your identity is a key on your own computer. The server keeps just enough to help people find you (a username linked to that key, and a password hash) and nothing about your conversations. You can run your own (`tariond`), or skip it and connect by address.
- **You open your own doors.** Tarion asks *your* router to open *your* port, tells you plainly when it can't and why, and lets you do it by hand instead. You decide who may message you (`-accept contacts`), whose bans you respect (`-server-bans`), and whether anything may ever pass through a server (`-relay`, `-mailbox`).

Being honest about the one helper that remains: the directory server knows your username, your key, your IP address while you're online, and which usernames you look up. It never sees what you say. If even that is too much, host the server yourself.

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

If someone is offline or can't be reached, the message is **queued** instead of lost. The background process (or the open menu) retries automatically: right away when the server shows them online, otherwise with growing gaps, for up to 7 days. The chat then shows `✓ delivered later`, and late messages show when they were written.

See what's waiting, and what was given up on or refused (also printed in `background.log`):

```powershell
.\tarion.exe outbox
.\tarion.exe dropped
```

Only accept messages from people you know (contacts in `config.json`, people you messaged, and people who messaged you before):

```powershell
.\tarion.exe start -accept contacts
```

Change your password, or delete your account on the server (both ask for the current password; deleting also asks you to type your username):

```powershell
.\tarion.exe passwd
.\tarion.exe delete-account
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
- `server_bans` is `on` (default) or `off` (`-server-bans`): whether your client refuses keys your server's operator banned.
- `relay` is `off` (default) or `on` (`-relay`): whether messages may pass through the server when no direct path exists. See [Getting through strict NATs](#getting-through-strict-nats).
- `mailbox` is `off` (default) or `on` (`-mailbox`): whether the server may hold sealed messages for you while you're offline, and whether you leave them for contacts who are offline. See [The server mailbox](#the-server-mailbox).
- `public_addr` (`-public-addr`): an address peers can reach you at directly, such as a port you forwarded by hand.
- `port_mapping` is `auto` (default), `on` or `off` (`-port-mapping`): whether to ask your router to forward the chat port automatically. `auto` does it while the relay is off.

The folder also holds `identity.key` (your private key, keep it secret), `peers.json` (pinned contacts), `outbox.json` (messages waiting to be delivered), `dropped.log` (messages given up on or refused), `revoked.json` (keys your server banned) and, while the background process runs, `control.token`.

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
- **Server login.** The password is only ever sent inside that encrypted connection. It links your account to your device's key; later logins use the key alone, and the password isn't stored on your device. The server stores argon2id hashes (64 MiB, 3 passes), requires 10+ character passwords for new accounts, rate-limits logins and registrations, and checks usernames (1–32 letters/digits plus `. _ -`, not case-sensitive). Operators can make the server invite-only and ban users or keys. Your client also receives the server's list of banned keys and, unless you set `-server-bans off`, refuses to exchange messages with them, even over a direct connection.
- **Server pinning.** The client pins the server's key (`server_id`), so an impostor server can't collect passwords.
- **Pinning.** The first time you talk to a name, its peer ID is pinned in `peers.json`. If that name later answers with a different key, sending is refused. When the server knows a user, it also reports their key, and the key that answers must match it too. A new key that claims a pinned name shows up as a separate chat such as `bob~1a2b3c4d`, so it can't pose as Bob.
- **Delivery.** Each message carries an ID and waits for the receiver's acknowledgement. The menu shows `delivered` or `not delivered: <reason>`, and failed sends are marked in the history. Duplicate deliveries are dropped.
- **Limits.** Frames are capped at 64 KiB and message bodies at 16 KiB. Connections and requests are capped. Control characters are stripped from incoming text so a peer can't inject terminal escape sequences.
- **Local control.** The background process's control port only accepts requests carrying the random token from `control.token`, which only your OS user can read.

### How a message finds its way

1. The client keeps a QUIC connection to `tariond` open from its chat port. Its keep-alives are the heartbeat, and they also keep the router's mapping for that port open.
2. To message bob, the client asks the server for bob. The server answers with bob's public address, his key, and (only if you're behind the same router) his LAN address.
3. At the same moment, the server tells bob, over his open connection, to send a few tiny packets toward your address. That opens bob's router for your incoming connection (NAT hole punching).
4. The client connects to bob directly: LAN address first, then an address bob made reachable himself (a forwarded port), then the public address the server sees.
5. If none work and you both use the mailbox, the message is sealed and left in bob's server mailbox. Otherwise it's queued on your device and retried. **No message passes through the server** unless you, bob and the server operator all turned the relay or the mailbox on (see below).

### Getting through strict NATs

Hole punching works with most home routers. When both sides are behind strict ("symmetric") NATs, Tarion has these options:

- **Automatic port forwarding (on by default while the relay is off).** At start, the client asks your router to forward its chat port, with UPnP first, then NAT-PMP. It checks that the router's internet address matches what the server sees, announces the address, and has the server send a test packet from a *different* port, the way a stranger would. Only if that packet arrives is the forward kept and given to people who look you up. The mapping is renewed while Tarion runs and removed when it exits (quitting the menu, Ctrl+C or `tarion stop`). If Tarion is killed instead, the router drops it by itself within an hour, because it is requested with a one-hour lease. The exception is routers that only allow permanent forwards: those keep it until Tarion's next start replaces it, or you delete it in the router's settings.

  If it doesn't work, Tarion says why: no UPnP/NAT-PMP router answered, the router refused, the port is taken, your ISP shares one address between customers (carrier-grade NAT), there's a second router (double NAT), or a firewall blocked the test packet. It also lists what you can do. You see this in `background.log` and in the menu's status line, and `tarion portmap` retries at any time and prints the full explanation:

  ```powershell
  .\tarion.exe portmap
  ```

  `-port-mapping off` turns it off, and `-port-mapping on` uses it even with the relay on.
- **Forward a port by hand (no server involved).** On your router, forward UDP to your chat port (default 63426), then tell Tarion: `-public-addr YOUR_PUBLIC_IP:63426` (a DNS name works too). The server passes it to people who look you up, and they connect straight to you. Setting this turns the automatic forwarding off.
- **The relay (opt-in, off by default).** With `-relay on` on both clients and `tariond -relay` on the server, the server forwards the QUIC packets between you. You still run your own encrypted handshake inside it and keys are checked as usual, so the server only sees ciphertext, but your traffic does go through it. A client with the relay off never uses it and refuses relayed connections. After needing it, messages to that contact use the relay right away for 10 minutes.

### The server mailbox

Without it, a message to someone who is offline waits on *your* device until you're both online at the same time. With it, the server holds the message for them, without being able to read it.

It's **off by default** and only works when all three agree: the operator runs `tariond -mailbox`, the recipient turned theirs on (`-mailbox on`), and so did you.

- **Sealed.** Each device derives a mailbox key from its identity key and publishes it at login, signed by the identity key. To leave a message, your client fetches that key, checks the signature and that the identity key matches the one you pinned for that contact (or the `id` in `config.json`), then seals the message to it (X25519 + XSalsa20-Poly1305, NaCl's anonymous box). Only the recipient's device can open it.
- **Signed.** Inside the seal, the message is signed with your identity key. The recipient checks the signature, that it was addressed to them, and then applies the same rules as a direct message: banned keys, `-accept contacts`, pinned names, duplicates. The server can't forge, change or redirect a letter.
- **What the server does see:** who left a letter for whom, when, and how big it is. Not the text.
- **Delivery.** The recipient's client fetches letters at login, when the server says one arrived, and every 2 minutes. A letter is deleted from the server only after it was received. The sender sees `✉ left in their server mailbox`.
- **Limits.** Up to 200 letters or 4 MiB waiting per person, 50 from any one sender, 10 per minute per sender. Letters nobody fetches are deleted after 7 days (`tariond -mailbox-days`).
- **Turning it off** (`-mailbox off`) deletes the letters waiting for you at your next login, and the server refuses new ones. When the operator turns it off, the server deletes everything it held at the next start.
- Letters are sealed to one device's key. After you move your account to a new device, letters sealed to the old one stay for that device until they expire.

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
- **Blocking:** a firewall can still block Tarion, either by ALPN or by blocking UDP altogether (common on company and school networks). Strict NATs can be handled by a forwarded port or the opt-in relay, but a network that blocks UDP stops Tarion completely; a TCP transport is tracked in #13.
- **Your own PC's firewall** (Windows Defender may ask the first time): allowing it is best. If you decline, connections still work, because Tarion punches outward first, which opens a temporary opening for that peer.
- **Server:** open UDP 63425 inbound. Clients need no inbound rules or port forwarding.

### Known limitations

- Networks that block UDP entirely can't use Tarion yet; a TCP transport is tracked in #13.
- Without the mailbox, queued messages wait on the *sender's* device, so both of you need to be online at the same moment eventually. With it (opt-in), the server holds them sealed.
- One device per account (#15).
- `identity.key` and the history are stored unencrypted, protected by file permissions (#16).
- Trust on first use: on the very first contact you trust the key the server reports. Compare `tarion id` with your contact, or put their `id` in `config.json`, to rule that out.

### Testing strict NATs

Set `TARION_SIMULATE_STRICT_NAT=1` before starting a client. It then drops every direct packet from peers, like a strict NAT. With the relay on (both clients and the server), messages take the relay; with it off, they're queued.

## Privacy

The server handles login and address lookup. By default it never carries messages: chats go directly between the two people. Only if everyone involved turns the relay on does it forward encrypted packets it can't read, and only if everyone turns the mailbox on does it hold letters sealed to the recipient, which it can't read either. Either way, chats are end-to-end encrypted with mutually authenticated TLS 1.3. The server's user list shows names only, not IP addresses. Local history is stored as plain text in the config folder with owner-only permissions.
