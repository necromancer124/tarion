# start: log in, open the menu and chat

`tarion start` (or just `tarion`) opens the interactive menu. If no background
process is running, it also listens for messages itself while it's open.

## First time on a device

```
tarion start -server SERVER:63425 -user alice -pass "a long passphrase"
```

- The first login with a new name creates the account. Passwords need 10+
  characters and must not contain the username.
- Invite-only servers also need `-invite CODE` once (the operator creates
  codes with `tariond invite`).
- If the account already exists on another device, this device waits for
  approval instead (see `tarion help devices`).
- After that first login the password is removed from config.json, and
  `tarion start` is enough: this device logs in with its key.

## The menu

- The list shows online users and saved chats; offline ones are tagged
  `[offline]`, chats with new messages `[NEW]`.
- `Up`/`Down` or `k`/`j`: move. `Enter`: open a chat, or send what you typed.
- `Esc`: back to the list. `r`: refresh now. `h` or `?`: help. `q` or
  `Ctrl+C`: quit.
- The line under the list shows the server connection and port forwarding.

## Without a server

Chat straight to an address, for example on your own network:

```
tarion start -u Bob -i 192.168.1.20:63426
```

## Options

Every option marked "saved" is written to config.json and stays in effect:
`-server`, `-user`, `-pass`, `-invite`, `-p`, `-cp`, `-accept`,
`-server-bans`, `-relay`, `-mailbox`, `-public-addr`, `-port-mapping`.
`tarion start -h` lists them all. `-wipe-history` deletes all local chat
history and exits.

See also: background, devices, keys, config.
