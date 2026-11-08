# mailbox: messages for people who are offline

Without the mailbox, a message to someone offline waits on your device
until you're both online at the same time. With it, the server holds the
message for them, without being able to read it.

It's off by default and only works when all three agree: the operator runs
`tariond -mailbox`, the recipient uses `-mailbox on`, and so do you.

```
tarion start -mailbox on     # saved; -mailbox off turns it off
```

Direct delivery always comes first:

- **Offline** (the server says so): the message goes to their mailbox
  right away. A message already queued for them moves there as soon as
  they go offline.
- **Online but unreachable**: it's retried directly (and through the relay
  if on) for about a minute, then goes to their mailbox; they're online,
  so they get it within seconds.

## Why the server can't read it

Each device publishes a mailbox key, signed by its identity key. Your
client checks that signature and that the device really belongs to the
recipient, then seals one copy per device (NaCl anonymous box). Inside the
seal, the message is signed by you, so the server can't forge, change or
redirect it. The server does see who wrote to whom, when, and how much.

## Limits and cleanup

- Up to 200 letters or 4 MiB waiting per device, 50 from any one sender,
  10 per minute per sender. Unread letters are deleted after 7 days
  (`tariond -mailbox-days`).
- A letter is deleted from the server only after it arrived.
- Turning your mailbox off deletes what's waiting for you at your next
  login. When the operator turns it off, the server deletes everything.

See also: relay, outbox, network.
