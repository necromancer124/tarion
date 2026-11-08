# background: stay reachable without a window open

The background process keeps your chat port open, logged in and listening,
saves incoming messages to history and retries queued ones. Other commands
talk to it over a local control socket.

```
tarion background --detach        # start it; survives closing the terminal
tarion menu                       # read and write chats through it
tarion send bob "hello"           # send one message
tarion listen                     # print incoming messages as JSON lines
tarion history -n 20 bob          # the last 20 lines of a chat
tarion stop                       # stop it
```

- It writes a log: `background.log` in your Tarion folder (see `tarion help
  config`). Startup problems (port forwarding, firewall) are explained there.
- Without `--detach` it runs in the terminal, which is handy for watching
  the log live.
- If your data is protected with a passphrase, `--detach` asks for it once
  and hands the unlocked key to the background process.
- `-p` and `-cp` pick the UDP and control ports when you run more than one
  Tarion on a machine (each also needs its own folder: set `TARION_HOME`).

## Scripts and apps

`tarion listen` and the local API let other programs use Tarion: one JSON
object per line over TCP on 127.0.0.1, protected by a token. See
docs/local-api.md.

See also: start, outbox, api.
