# Tarion Client

Tarion is a secure hybrid peer-to-peer CLI chat client using QUIC over UDP port `63425` by default.

## What the client does

- `tarion.exe start` starts the client, tries to register/heartbeat with the directory server, and begins listening for direct QUIC peer messages.
- The opening menu is intentionally clean: contacts plus controls only.
- Detailed setup/network/history information lives in the in-app help menu (`h` or `?`).
- The menu refreshes periodically and when messages arrive.
- New incoming messages mark contacts with `[NEW]` in the menu.
- Known/online users are refreshed from the directory server when it supports `LST`.
- Chat history is local under your OS config directory in `tarion/history`.

## Build

```powershell
go build -o tarion.exe .
```

## Start connected to a server

```powershell
.\tarion.exe start -server 127.0.0.1:63425 -user alice -pass secret
```

The values are saved to:

```text
%APPDATA%\tarion\config.json
```

You can later run:

```powershell
.\tarion.exe start
```

## Direct/self-test chat

```powershell
.\tarion.exe start -p 63426 -u Myself -i 127.0.0.1:63426
```

## Delete local history

```powershell
.\tarion.exe start -wipe-history
```

## Controls

- `↑` / `↓` or `k` / `j`: navigate contacts
- `Enter`: open selected chat / send typed message
- `Esc`: leave chat view and return to menu
- `h` or `?`: open/close help
- `r`: refresh directory now
- `q` or `Ctrl+C`: quit

## Privacy

The server is only for authentication and peer address discovery. Chat payloads are sent directly peer-to-peer and are not relayed through the server.
