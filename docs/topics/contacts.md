# contacts: who may message you, and contacts without a server

## Only people you know

```
tarion start -accept contacts     # saved; -accept anyone undoes it
```

Then only contacts in config.json, people you messaged and people who
messaged you before can reach you. Strangers get "this user only accepts
messages from contacts", and you see who in `tarion dropped`.

## Contacts in config.json

```json
"contacts": [
  { "name": "bob", "addr": "192.168.1.20:63426" },
  { "name": "carol", "addr": "203.0.113.7:63426", "id": "owft vlcv d5sm kq6u f7hm 7dj5 6geo f2ni" }
]
```

- A contact with an `addr` can be reached without the server.
- `id` is optional. When set, Tarion only talks to the peer holding that
  key (or one of their verified devices), even on the very first contact.

## Server bans

Your server's operator can ban users or keys. By default your client refuses
to exchange messages with banned keys too, even directly. To decide for
yourself:

```
tarion start -server-bans off     # saved; on is the default
```

See also: keys, config, outbox.
