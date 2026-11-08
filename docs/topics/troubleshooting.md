# troubleshooting: common problems and what to do

**"server offline ... retrying"**: the server can't be reached. Check the
address and port (`-server host:63425`), that the server runs, and that UDP
63425 is open on the server's firewall. Networks that block UDP (some
offices and schools) stop Tarion completely for now.

**"server key changed ... refusing to log in"**: the server answered with a
different key than the one pinned in config.json. Only if you know the
server was reinstalled, remove `server_id` from config.json.

**"this device is waiting to be added to ..."**: the account exists on
another device. Approve this one there: `tarion devices approve CODE`.

**"wrong password" / "this device is not on the account yet"**: run once
with `-pass`; on an account with other devices, approve it from one of them.

**"identity of bob changed"**: see `tarion help keys`.

**A message is "queued"**: they're offline or unreachable; it's retried for
7 days (`tarion outbox`). For people behind strict NATs, see `tarion help
portmap` and `tarion help relay`.

**"automatic port forwarding did not work"**: the message explains why and
what to do; `tarion portmap` retries. Most people can still reach you
through hole punching.

**The firewall warning at startup**: `tarion firewall allow` (see
`tarion help firewall`).

**"could not unlock your Tarion data"**: with a passphrase, type it again;
"Windows could not unlock" means the folder was copied from another PC or
Windows account (see `tarion help protect`).

**"is another Tarion using UDP 63426?"**: a background process or another
instance holds the port. `tarion stop`, or pick another with `-p`.

**Where's the log?** `background.log` in the Tarion folder (`tarion help
config`). Running `tarion background` without `--detach` shows it live.

Still stuck? Open an issue: https://github.com/necromancer124/tarion/issues
(never paste identity.key, a password or control.token).

See also: network, portmap, firewall, devices, keys, protect.
