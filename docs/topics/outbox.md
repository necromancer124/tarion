# outbox: queued, delivered later, and dropped messages

If someone can't be reached, your message is queued instead of lost:

- The background process (or the open menu) retries it: right away when the
  server shows them online, otherwise with growing gaps, for up to 7 days.
- The chat then shows `✓ delivered later`, and late messages show when they
  were written.
- With the mailbox on, it may be left in their mailbox instead (see
  `tarion help mailbox`).

```
tarion outbox        # what's waiting, with the last error and next try
tarion dropped       # what was given up on or refused
```

## Dropped messages

`dropped.log` records every message that will never arrive: one you sent
that was given up on (after 7 days, or because the key was wrong or banned),
or one you refused (from a banned key, or a stranger while you accept only
contacts). For your own messages it keeps the text so nothing is lost
silently; for refused ones it keeps only who and why.

The same events go to `background.log` and to apps using the local API.

See also: background, mailbox, contacts.
