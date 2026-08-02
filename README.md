# Tarion Server (`tariond`)

`tariond` is the lightweight UDP directory/signaling daemon for Tarion.

## Responsibilities

- Register authenticated users by observed public `IP:port`.
- Store salted SHA-256 password hashes in a flat file (`users.db`); plaintext passwords are never written to disk.
- Maintain an in-memory CAM-table-style map: `username -> observed public IP:port + last_seen`.
- Reject wrong passwords before updating a user's address.
- Refresh online leases on heartbeat.
- Return peer addresses for NAT/direct-QUIC setup.
- Send a `PCH` punch signal to the target peer during lookup so the target can open its UDP NAT mapping toward the requester.

The server **does not relay chat messages** and **does not initiate chat connections**. Chat payloads remain peer-to-peer.

## Build

```bash
go build -o tariond.exe ./server
```

## Run

```bash
./tariond.exe -port 63425 -users users.db -ttl 60s
```

## UDP Protocol

Pipe-delimited text messages:

- `REG|username|password` → `OK|REGISTERED` or `ERR|AUTH_FAILED`
- `HBT|username|password` → refreshes the lease
- `QRY|username|password|target` → `OK|ADDR|ip:port` or `ERR|OFFLINE`
  - On success, `tariond` also sends `PCH|username|requester_ip:port` to the target's stored address.
- `LST|username|password` → `OK|USERS|name=ip:port,name2=ip:port`

