# Tutorial: from nothing to your first message

This walks through setting up a server, signing up, verifying a contact and
chatting, with the commands to type at each step. It takes about fifteen
minutes. Every command has more detail behind `tarion help <topic>`.

## 1. Get Tarion

Download `tarion` and `tariond` for your system from
[Releases](https://github.com/necromancer124/tarion/releases) and unpack
them, or build them with Go 1.25+:

```bash
go build -o out/ . ./server
```

On Linux you can install the manual pages too:

```bash
sudo install -m 644 docs/man/tarion.1 /usr/local/share/man/man1/
sudo install -m 644 docs/man/tariond.8 /usr/local/share/man/man8/
```

## 2. Run a server

Chats don't go through the server; it only helps people find each other.
You need one that everyone can reach. Three options:

**A small Linux VPS with Docker** (recommended):

```bash
docker build -t tariond .
docker run -d --name tariond --restart unless-stopped -p 63425:63425/udp -v tariond-data:/data tariond -registration invite
docker logs tariond          # shows the server ID
```

**A VPS without Docker**: see `deploy/tariond.service` for a systemd unit.

**Your own PC**, for trying it out on your network: `tariond -data ./tariond-data`.

Open **UDP 63425** inbound in every firewall in front of the server
(`sudo ufw allow 63425/udp`, plus your hosting provider's firewall if it
has one). Note the **server ID** from the log: it's how your users check
they reached the real server.

## 3. Invite people

With `-registration invite`, only people with a code can sign up:

```bash
docker exec tariond /tariond invite -n 2     # two one-time codes
```

Give each person a code, the server address and the server ID.

## 4. Sign up

On each person's computer:

```
tarion start -server YOUR.SERVER:63425 -user alice -pass "a long passphrase" -invite CODE
```

That creates the account. The password needs 10+ characters and must not
contain the username. From now on, `tarion start` is enough: this device
logs in with its own key.

Check the server ID: open `config.json` in your Tarion folder (`tarion help
config`) and compare `server_id` with the ID from step 2. Tarion pinned it,
and refuses to log in if it ever changes.

## 5. Verify each other

```
tarion id
```

Read your peer ID to your contact over a call or in person, and check theirs
in `tarion peers` after you've talked once. If they match, nobody is in the
middle. You only have to do this once: Tarion remembers ("pins") the key,
and warns loudly if it ever changes (`tarion help keys`).

## 6. Chat

`tarion start` opens the menu: pick a contact with the arrow keys, `Enter`
to open the chat, type, `Enter` to send, `Esc` to go back, `q` to quit.

To stay reachable without keeping a window open:

```
tarion background --detach
tarion send bob "are you there?"
tarion stop
```

Messages to someone who's offline are queued and retried for 7 days
(`tarion outbox`). With the server mailbox, which the operator and both of
you have to turn on, the server holds them sealed instead (`tarion help
mailbox`).

## 7. Your other devices

Log in on your laptop with your password, and approve it from the device
you already have:

```
tarion devices approve 7WMW-26Z2
```

(`tarion help devices`). Your contacts accept it automatically.

## 8. When people can't reach each other

Most home routers work out of the box (hole punching). If not:

- Tarion asks your router to forward its port, tests it, and explains
  what went wrong: `tarion portmap`.
- On Windows, the firewall may be in the way: `tarion firewall allow`.
- Or forward the port yourself: `-public-addr YOUR_IP:63426`.
- Or, if the operator and both of you agree, use the relay: `-relay on`.

Details: `tarion help network`, `tarion help portmap`, `tarion help relay`.

## 9. Something's wrong?

`tarion help troubleshooting` covers the common messages. The background
process's log (`background.log`) explains what it tried.
