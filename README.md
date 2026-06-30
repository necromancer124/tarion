# Tarion Client

Tarion is a secure hybrid peer-to-peer CLI chat client using QUIC over UDP port `63425` by default.

## What the client does

- Runs an always-on QUIC listener for direct peer-to-peer chat messages.
- Stores chat history locally in your OS config directory under `tarion/history`.
- Supports manual/direct chats by IP address without needing discovery first.
- Shows setup/help text directly in the opening menu.
- Shows a `[NEW]` marker for contacts whose history file changed recently.

## Build

```bash
go build -o tarion.exe .
```

## Run

Open the menu:

```bash
./tarion.exe
```

Open a direct chat with a peer IP and assign it a display name:

```bash
./tarion.exe -u Friend -i 203.0.113.10:63425
```

Use a different local test port:

```bash
./tarion.exe -p 63426 -u LocalPeer -i 127.0.0.1:63425
```

Delete all local chat history:

```bash
./tarion.exe -wipe-history
```

## Controls

- `↑` / `↓` or `k` / `j`: navigate contacts
- `Enter`: open selected chat / send typed message
- `Esc`: leave chat view and return to the menu
- `q` or `Ctrl+C`: quit

## Privacy

The server is only for authentication and peer address discovery. Chat payloads are sent directly peer-to-peer and are not relayed through the server.
