# api: use Tarion from scripts and apps

The background process accepts commands on a local TCP socket
(127.0.0.1, port `-cp`, default 53426), one JSON object per line, each with
the token from `control.token` in the Tarion folder.

```
{"token":"...","cmd":"send","to":"bob","body":"hello"}
{"token":"...","cmd":"subscribe"}
```

- Commands: ping, send, online, history, subscribe, portmap, devices,
  change_password, delete_account, stop.
- `subscribe` streams events as JSON lines: message, status, delivered,
  mailed, dropped, portmap.
- `send` answers `ok`, or `queued` / `mailed` with the reason it wasn't
  delivered directly.

The quick way from a shell: `tarion send`, `tarion listen` (events as JSON
lines) and `tarion history`.

The full reference with examples is docs/local-api.md.

See also: background.
