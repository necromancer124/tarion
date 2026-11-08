# config: config.json, files and environment variables

## Where

The Tarion folder is `%APPDATA%\tarion` on Windows, `~/.config/tarion` on
Linux and `~/Library/Application Support/tarion` on macOS, or whatever
`TARION_HOME` says.

## config.json

| Field | Meaning |
|---|---|
| server_addr | directory server host:port (`-server`) |
| server_id | the server's key, pinned on the first connection; a changed key means Tarion refuses to log in. Remove it only if the server was really reinstalled (operators print it with `tariond id`) |
| username | your account (`-user`) |
| password, invite | only until the first successful login, then removed |
| port | UDP port for chat and the server (`-p`, default 63426) |
| control_port | local TCP port of the background process (`-cp`, default port plus 10000) |
| accept | anyone (default) or contacts (`-accept`) |
| server_bans | on (default) or off (`-server-bans`) |
| relay | off (default) or on (`-relay`) |
| mailbox | off (default) or on (`-mailbox`) |
| public_addr | an address peers can reach you at directly (`-public-addr`) |
| port_mapping | auto (default), on or off (`-port-mapping`) |
| contacts | optional list of name, addr, id (see `tarion help contacts`) |

## Files

| File | What |
|---|---|
| identity.key | your private key (encrypted; keep it secret) |
| vault.json | the data key, protected by Windows or your passphrase |
| peers.json | pinned contacts and their verified devices |
| history/*.txt | one chat per file |
| outbox.json | messages waiting to be delivered |
| dropped.log | messages given up on or refused |
| revoked.json | keys your server banned |
| background.log | the background process's log |
| control.token | secret for the local API, while the background process runs |

## Environment

| Variable | Effect |
|---|---|
| TARION_HOME | use another folder (e.g. a second identity on one machine) |
| TARION_NO_AUTO_PROTECT=1 | don't encrypt a new Windows install automatically |
| TARION_SIMULATE_STRICT_NAT=1 | testing: drop direct packets from peers |

See also: protect, contacts, start.
