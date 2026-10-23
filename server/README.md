# Tarion Server (`tariond`)

`tariond` is Tarion's directory server. It tells peers where to find each other and signals NAT hole punching. It **never sees chat messages**. Two opt-in features, both off by default, let messages pass through it without it being able to read them: the relay (encrypted packets) and the mailbox (sealed letters for offline users).

## Quick start

```bash
go build -o tariond ./server
./tariond -data ./tariond-data
```

On startup it prints the **server ID**. Clients pin it the first time they connect, and you can hand it to users as `server_id` so they can verify it. Open **UDP 63425** inbound in every firewall between the internet and the server.

## Files

Everything lives in one data folder: `-data`, or the `TARIOND_DATA` environment variable, default `.`.

| File | What | Back it up? |
|---|---|---|
| `tariond.key` | Server identity. If you lose it, every client refuses the "new" server until users delete `server_id` | **Yes** |
| `users.json` | Accounts: name, argon2id hash, linked device key | **Yes** |
| `invites/` | One file per unused invite code | |
| `bans.txt` | Banned usernames and peer IDs, one per line, `#` for comments | |
| `mailbox/` | With `-mailbox`: one folder per user with their published mailbox key and the sealed letters waiting for them. Deleted at start when `-mailbox` is off | |
| `users.db` | Old v1 database; imported once if `users.json` doesn't exist | |

## Server flags

| Flag | Default | Meaning |
|---|---|---|
| `-port` | `63425` | UDP port |
| `-data` | `.` | Folder for all files (see above) |
| `-registration` | `open` | Who can create accounts: `open`, `invite` or `closed` |
| `-min-password` | `10` | Minimum password length for new accounts (8 or more) |
| `-argon-memory` | `64` | argon2id memory per hash, in MiB |
| `-argon-time` | `3` | argon2id passes |
| `-relay` | `false` | Relay encrypted packets between peers whose NATs block a direct connection. Both clients must also turn it on (`tarion -relay on`) |
| `-relay-kbps` | `256` | Relay bandwidth per session, KiB/s |
| `-relay-total-kbps` | `8192` | Relay bandwidth for all sessions together, KiB/s |
| `-mailbox` | `false` | Hold sealed letters for offline users. Both users must also turn it on (`tarion -mailbox on`). The server can't read them |
| `-mailbox-days` | `7` | Delete letters nobody fetched after this many days (1–90) |

`-users`, `-key`, `-invites`, `-bans` and `-legacy-users` override single file paths.

## Controlling who has access

```bash
tariond -registration invite        # run the server invite-only
tariond invite -n 3                 # create 3 one-time codes (safe while the server runs)
tariond accounts                    # list accounts, their keys, and bans
tariond ban bob                     # ban a username...
tariond ban "x5u5 zbuk qp3a g4dj hpyl ztgg u7z3 siop"   # ...or a device key
tariond unban bob
tariond delete bob                  # delete an account (frees the name)
tariond id                          # print the server ID
```

Operator commands take the same `-data` flag (or `TARIOND_DATA`) as the server.

- **Invites:** a user registers once with `tarion start -server HOST:63425 -user NAME -pass PASSWORD -invite CODE`. Each code works exactly once; a failed registration gives the code back.
- **Bans:** take effect within about 2 seconds, with no restart. A banned user is disconnected, can't log in or register, and doesn't show up in lookups. Banning a key blocks that device under any name. Every logged-in client also receives the list of banned keys (up to 1000) and, unless its user set `-server-bans off`, refuses to exchange messages with them, even over a direct connection or when it already knows their address.
- **Deleting:** `tariond delete NAME` takes effect within about 2 seconds, or at the next start if the server isn't running. Users can also delete their own account with `tarion delete-account`.
- **Limit:** someone who never logs in to your server never receives its ban list, so two people using Tarion without any server can still talk directly with `-i`.

## What it does

- **Accounts.** The first login with a new name creates the account (if registration allows it) and links it to that device's key. Usernames are 1–32 letters or digits plus `. _ -`, not case-sensitive. New passwords need 10+ characters, can't contain the username, and can't be one repeated character. Passwords are stored as argon2id hashes (64 MiB, 3 passes by default); each hash records its own settings and is redone at the next password login if you change them. `users.json` is replaced atomically, so a crash can't corrupt it.
- **Login.** Logins go over QUIC/TLS 1.3 (ALPN `tarion-dir/1`) with mutual TLS and a post-quantum hybrid key exchange (X25519MLKEM768). A device whose key is linked to the account logs in with the key alone. A password login from a new device links that device instead. A newer login closes the older session.
- **Presence.** A user is online while their connection is open. Clients send keep-alives every 15 seconds, and the server drops a connection after 45 seconds of silence.
- **Lookup.** The server returns the target's public chat address and key, and their LAN address only if both users share a public IP. It also tells the target to punch toward the requester, including the requester's LAN address in that case.
- **List.** The server returns the names of online users (not their addresses), capped at 500.
- **Relay (off by default).** With `-relay`, when two peers can't connect directly, one asks for a relay session. The target must have the relay turned on too, otherwise the server answers `relay_refused`. The server forwards packets between the two members' known addresses only, without being able to decrypt them (the peers' TLS runs end to end inside). Sessions close after 2 minutes without traffic.
- **Mailbox (off by default).** With `-mailbox`, a user who logs in with `-mailbox on` publishes a mailbox key signed by their identity key. Others can then leave letters for them while they're offline (`mailbox_key`, `mailbox_put`). The letters are sealed to that key and signed by the sender, so the server stores only ciphertext and can't forge or redirect them; it does see who wrote to whom, when, and the size. The owner fetches them (`mailbox_fetch`) and they are deleted once acknowledged (`mailbox_ack`). If the recipient is online, the server tells them a letter arrived. A user who logs in with the mailbox off has their letters deleted and gets no new ones (`mailbox_refused`). Deleting an account deletes its mailbox.
- **Forwarded ports.** A client can advertise an address it made reachable itself (`tarion -public-addr`, or a port its router forwards automatically, announced after login). The server checks that it's `host:port` and hands it out in lookups.
- **Reachability test.** On request, the server sends a 12-byte test packet to a client's advertised address from a second UDP port (opened at start, random), so the client knows whether strangers can really reach it. It only goes to the client's own public IP and is rate-limited, so it can't be aimed at anyone else.
- **Accounts can be changed.** Users can change their password (`tarion passwd`) or delete their account (`tarion delete-account`), both with the current password and rate-limited like logins.

## Abuse limits

- New connections: 16 at once and a burst of 20 per IP, plus 10,000 in total.
- Password attempts: a burst of 10 per IP and 10 per account, refilling slowly.
- Registrations: 3 per IP, then one every 10 minutes.
- Requests: a burst of 30 per session, then 2 per second. Punch signals are limited per user pair.
- At most 2 argon2id hashes are computed at once.
- Mailbox: 200 letters or 4 MiB waiting per user, 50 from any one sender, 40 KiB per letter, and a burst of 20 letters per sender, then one every 6 seconds.
- Relay: 8 sessions per user, 256 KiB/s per session and 8 MiB/s in total (configurable).
- QUIC itself checks the sender's address before replying with much data, so the server can't be used to flood a faked address.

## Running it for real

### Docker (Linux host)

```bash
docker build -t tariond .
docker run -d --name tariond --restart unless-stopped \
  -p 63425:63425/udp -v tariond-data:/data tariond -registration invite
docker logs tariond                 # shows the server ID
docker exec tariond /tariond invite # operator commands
```

- Use a **Linux** host. Docker Desktop on Windows and macOS rewrites client source addresses, which breaks the addresses the server hands out and hole punching. On Linux, `-p ...:63425/udp` keeps the real addresses; `--network host` also works.
- Keep the `/data` volume. Without it, a recreated container gets a new server key and every client refuses it.
- The image runs as a non-root user with no shell.

### systemd (Linux)

[`deploy/tariond.service`](../deploy/tariond.service) is a hardened unit. Install steps are at the top of the file. Logs go to `journalctl -u tariond`.

### Windows Server

Run these in an elevated PowerShell. *These steps are documented but weren't run as part of testing.*

```powershell
New-Item -ItemType Directory -Force C:\tariond\data | Out-Null
Copy-Item .\tariond.exe C:\tariond\
New-NetFirewallRule -DisplayName "tariond" -Direction Inbound -Protocol UDP -LocalPort 63425 -Action Allow
icacls C:\tariond\data /grant "NT AUTHORITY\LOCAL SERVICE:(OI)(CI)M"

$action    = New-ScheduledTaskAction -Execute "cmd.exe" -Argument '/c C:\tariond\tariond.exe -data C:\tariond\data >> C:\tariond\data\tariond.log 2>&1'
$trigger   = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\LOCAL SERVICE" -LogonType ServiceAccount
$settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName "tariond" -Action $action -Trigger $trigger -Principal $principal -Settings $settings
Start-ScheduledTask -TaskName "tariond"
```

The server ID appears in `C:\tariond\data\tariond.log`. Run operator commands with `-data C:\tariond\data`.

## Upgrading from v1

The old server used plain-text UDP (`REG|user|pass`) and a `users.db` file. On first start with no `users.json`, `tariond` imports `users.db`:

- Old SHA-256 hashes are kept until that user's next password login, then upgraded to argon2id.
- A name that appears **more than once** in `users.db` is dropped and logged. The old server let usernames contain newlines, which could plant a second record for someone else's name, so there's no safe way to tell which record is real. That user simply registers again.

v1 clients can't talk to this server. Everyone needs the current client.
