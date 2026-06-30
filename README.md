# Tarion Client

Tarion is a secure hybrid peer-to-peer CLI chat client using QUIC over UDP port `63425` by default.

## Commands

Open the interactive menu/TUI:

```powershell
.\tarion.exe menu
```

Start the interactive client and connect/listen:

```powershell
.\tarion.exe start -server 127.0.0.1:63425 -user alice -pass secret
```

Run the listener in a background terminal process, without opening the menu:

```powershell
.\tarion.exe background -server 127.0.0.1:63425 -user alice -pass secret
```

The background command keeps running until you stop it with `Ctrl+C` or close that terminal. While it is running, incoming messages are saved to local history. You can open another terminal and run `tarion.exe menu` to read saved chats.

Direct/self-test chat:

```powershell
.\tarion.exe start -p 63426 -u Myself -i 127.0.0.1:63426
```

Delete local chat history:

```powershell
.\tarion.exe start -wipe-history
```

## Menu behavior

- The menu always includes saved history chats, even when they are offline.
- Offline saved chats are tagged `[offline]`.
- Online users are refreshed from the server when configured.
- New incoming messages mark chats as `[NEW]`.
- `r` refreshes immediately; the menu also refreshes automatically.

## Config

The config is saved to:

```text
%APPDATA%\tarion\config.json
```

It can contain contacts:

```json
{
  "server_addr": "127.0.0.1:63425",
  "username": "alice",
  "password": "secret",
  "port": 63425,
  "contacts": [
    { "name": "bob", "addr": "127.0.0.1:63426" }
  ]
}
```

## Controls

- `↑` / `↓` or `k` / `j`: navigate contacts
- `Enter`: open selected chat / send typed message
- `Esc`: leave chat view and return to menu
- `h` or `?`: open/close help
- `r`: refresh directory/history now
- `q` or `Ctrl+C`: quit

## Privacy

The server is only for authentication and peer address discovery. Chat payloads are sent directly peer-to-peer and are not relayed through the server.
