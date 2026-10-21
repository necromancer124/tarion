# Tarion Server (`tariond`)

`tariond` is Tarion's directory server. It tells peers where to find each other and signals NAT hole punching. It **never sees or relays chat messages**.

## Build

```bash
go build -o tariond.exe ./server
```

## Run

```bash
./tariond.exe -port 63425 -users users.json -key tariond.key
```

| Flag | Default | Meaning |
|---|---|---|
| `-port` | `63425` | UDP port to listen on |
| `-users` | `users.json` | Account database |
| `-legacy-users` | `users.db` | Old v1 database, imported once if `-users` doesn't exist yet |
| `-key` | `tariond.key` | Server identity key (created on first run; back it up) |
| `-id` | | Print the server ID and exit |

On startup it prints the **server ID**. Clients pin it the first time they connect, and you can hand it to users as `server_id` so they can verify it.

## What it does

- **Accounts.** The first login with a new name creates the account and links it to that device's key. Usernames are 1–32 letters/digits plus `. _ -` and aren't case-sensitive. Passwords are 6–256 characters, stored as argon2id hashes. `users.json` is replaced atomically, so a crash can't corrupt it.
- **Login.** Logins go over QUIC/TLS 1.3 (ALPN `tarion-dir/1`) with mutual TLS. A device whose key is linked to the account logs in with the key alone. A password login from a new device links that device instead. A newer login closes the older session.
- **Presence.** A user is online while their connection is open. Clients send keep-alives every 15 seconds, and the server drops a connection after 45 seconds of silence.
- **Lookup.** The server returns the target's public chat address and key, and their LAN address only if both users share a public IP. It also tells the target to punch toward the requester.
- **List.** The server returns the names of online users (not their addresses), capped at 500.

## Abuse limits

- New connections: 16 at once and a burst of 20 per IP, plus 10,000 in total.
- Password attempts: a burst of 10 per IP and 10 per account, refilling slowly.
- Registrations: 3 per IP, then one every 10 minutes.
- Requests: a burst of 30 per session, then 2 per second. Punch signals are limited per user pair.
- At most 4 argon2id hashes are computed at once (each uses about 19 MiB).
- QUIC itself checks the sender's address before replying with much data, so the server can't be used to flood a faked address.

## Upgrading from v1

The old server used plain-text UDP (`REG|user|pass`) and a `users.db` file. On first start with no `users.json`, `tariond` imports `users.db`:

- Old SHA-256 hashes are kept until that user's next password login, then upgraded to argon2id.
- A name that appears **more than once** in `users.db` is dropped and logged. The old server let usernames contain newlines, which could plant a second record for someone else's name, so there's no safe way to tell which record is real. That user simply registers again.

v1 clients can't talk to this server. Everyone needs the current client.
