# Operator guide: running tariond

`tariond` tells clients where to find each other and helps them through
NATs. It never sees chat messages. This guide covers deployment, access
control, backups and upgrades; every flag is in `tariond(8)`
(docs/man/tariond.8) and in [server/README.md](../server/README.md).

## Deploy

**Docker on a Linux host:**

```bash
docker build -t tariond .
docker run -d --name tariond --restart unless-stopped \
  -p 63425:63425/udp -v tariond-data:/data tariond -registration invite
docker logs tariond                  # the server ID
docker exec tariond /tariond invite  # operator commands use the same /data
```

Run Docker on Linux, not Docker Desktop (Windows/macOS): Desktop rewrites
client source addresses, so the server would hand out wrong addresses and
hole punching would fail.

**systemd:** `deploy/tariond.service` runs it as an unprivileged user with
`/var/lib/tariond` as its data folder and a hardened sandbox. Operator
commands then run as that user:
`sudo -u tariond tariond invite -data /var/lib/tariond`.

**Firewall:** open UDP 63425 (or your `-port`) inbound. Reachability probes
for clients' forwarded ports go out from a second, random port; nothing
else needs opening.

**UDP buffers:** quic-go may log that it couldn't increase the receive
buffer size. On busy servers raise the limits:

```bash
sudo sysctl -w net.core.rmem_max=7500000 net.core.wmem_max=7500000
# make it permanent in /etc/sysctl.d/99-tariond.conf
```

## Give users the server ID

The server prints its ID at start (`tariond id` prints it any time). Clients
pin it on first contact; give it to your users so they can check it, or as
`server_id` in their config.

## Who can join

```bash
tariond -registration invite     # open (default), invite or closed
tariond invite -n 5              # one-time codes; safe while the server runs
tariond accounts                 # accounts, devices and bans
```

- **Bans** (`tariond ban NAME` or a peer ID, `unban`): applied within about
  2 seconds without a restart. Banned users are disconnected, can't log in,
  don't appear in lookups, and every client receives the list of banned
  keys (and by default refuses them even over direct connections).
- **Deleting** (`tariond delete NAME`): frees the name, signs out all its
  devices and deletes its mailbox.
- **Lost devices** (`tariond devices NAME`, `tariond devices reset NAME`):
  a user who lost every device can't approve a new one; a reset lets their
  next password login become the first device again. Their contacts see a
  key change, as they should. Check it's really them before resetting.

## Optional features

Both are off by default, and users have to turn them on too:

- `-relay`: forwards encrypted packets between clients whose NATs block a
  direct connection. Bandwidth: `-relay-kbps` per session, `-relay-total-kbps`
  overall. Your server then carries those users' traffic (it can't read it).
- `-mailbox`: holds sealed letters for offline users, for `-mailbox-days`
  (default 7). You store ciphertext and see who wrote to whom, when and how
  much. Turning it off deletes what it held at the next start.

## Backups

Back up **`tariond.key`** and **`users.json`** from the data folder.

- Losing `tariond.key` makes every client refuse the "new" server until each
  user removes `server_id` from their config.
- Losing `users.json` loses every account; users would sign up again and
  their contacts would see key changes.
- `invites/`, `bans.txt` and `mailbox/` are optional to keep.

`users.json` is written atomically, so copying it while the server runs is
safe.

## Upgrades

Replace the binary or rebuild the image and restart; the data folder stays.
Account files are migrated automatically (for example, accounts from before
multi-device support get their key as the first device). Clients keep
working across server upgrades: a server that doesn't support a newer
feature simply doesn't offer it.

## Abuse limits

Built in, no configuration needed: connections per IP, password attempts per
IP and per account, registrations per IP, requests per session, punch
signals per pair, mailbox letters per sender, and at most two argon2id
hashes computed at once. See server/README.md for the numbers.
