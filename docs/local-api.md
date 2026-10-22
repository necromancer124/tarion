# Local API

`tarion background` exposes a small local API, so you can build a GUI, bot or script on top of Tarion in any language. The background process does the networking, encryption and server login. Your app only reads and writes JSON.

## Connecting

- **Address:** TCP `127.0.0.1:<control port>`. The default is the chat port + 10000, or − 10000 when that would exceed 65535 (`53426` for the default chat port `63426`). It can be set with `-cp` / `"control_port"`.
- **Format:** one JSON object per line, in both directions.
- **Auth:** every request carries `"token"`, read from `control.token` in Tarion's folder. A new token is written each time the background starts, and only your OS user can read the file.

| OS | Tarion folder |
|---|---|
| Windows | `%APPDATA%\tarion` |
| Linux | `~/.config/tarion` |
| macOS | `~/Library/Application Support/tarion` |
| any | `$TARION_HOME` if set |

## Commands

| `cmd` | Fields | Reply |
|---|---|---|
| `ping` | | `{"ok":true}` |
| `send` | `to`, `body`, optional `addr` | `{"ok":true}` once the peer acknowledged it; `{"ok":true,"queued":true,"error":"bob is offline"}` if it was queued for automatic retry; `{"ok":false,"error":"..."}` if it can't be sent (wrong or banned key, refused) |
| `online` | | `{"ok":true,"status":"...","users":["bob",...]}` |
| `history` | `to`, optional `limit` | `{"ok":true,"lines":["bob: hi","Me: hello"]}` |
| `subscribe` | | `{"ok":true,"status":"..."}`, then the connection **stays open** and streams events |
| `change_password` | `pass`, `new_pass` | `{"ok":true}` or an error explaining why |
| `delete_account` | `pass` | `{"ok":true}`; the server then ends the session |
| `stop` | | `{"ok":true}`, then the background exits |

`send` doesn't add a `Me: ...` line to the history; write it yourself if your app needs it (the `tarion send` command does).

### Events (after `subscribe`)

```json
{"type":"message","chat":"bob","peer_id":"x5u5zbukqp3ag4djhpylztggu7z3siop","body":"hi","time":"2026-10-21T16:39:02+03:00"}
{"type":"status","status":"server connected as alice (public address 203.0.113.7:63426)"}
{"type":"delivered","chat":"bob","body":"queued earlier","time":"..."}
{"type":"dropped","chat":"bob","body":"never arrived","reason":"gave up after 7 days: bob is offline","time":"..."}
```

- `delivered`: a queued message finally arrived.
- `dropped`: a message will never be delivered. If it was yours, `body` holds what was lost; if you refused someone's message, there's no `body`. Every drop is also written to `dropped.log` (`tarion dropped`).

- `chat` is the name the message is filed under. A stranger who claims a name you've already pinned shows up as `name~1a2b3c4d`.
- `body` is the raw text. Escape it before displaying it in a terminal or as HTML.
- A subscriber that reads too slowly misses events instead of slowing Tarion down. Use `history` to catch up.

## Example: a Python echo bot

```python
import json, os, socket, sys
from pathlib import Path

if os.environ.get("TARION_HOME"):
    home = Path(os.environ["TARION_HOME"])
elif sys.platform == "win32":
    home = Path(os.environ["APPDATA"]) / "tarion"
elif sys.platform == "darwin":
    home = Path.home() / "Library/Application Support/tarion"
else:
    home = Path.home() / ".config/tarion"

cfg = json.loads((home / "config.json").read_text(encoding="utf-8"))
token = (home / "control.token").read_text().strip()
port = cfg.get("control_port") or (cfg["port"] + 10000 if cfg["port"] + 10000 <= 65535 else cfg["port"] - 10000)

def call(cmd, **fields):
    with socket.create_connection(("127.0.0.1", port)) as s:
        s.sendall((json.dumps({"token": token, "cmd": cmd, **fields}) + "\n").encode())
        return json.loads(s.makefile(encoding="utf-8").readline())

print(call("online"))

with socket.create_connection(("127.0.0.1", port)) as s:
    s.sendall((json.dumps({"token": token, "cmd": "subscribe"}) + "\n").encode())
    stream = s.makefile(encoding="utf-8")
    print(json.loads(stream.readline()))
    for line in stream:
        ev = json.loads(line)
        if ev["type"] == "message":
            print(call("send", to=ev["chat"], body="echo: " + ev["body"]))
```

## From the command line

```bash
tarion send bob "hello"      # send through the background
tarion listen                # print events as JSON lines
tarion history -n 50 bob     # recent history
```
