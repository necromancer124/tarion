# Security policy

Tarion is built so that nobody in the middle can read or forge your messages. If you find a way around that, please tell us privately first.

## Reporting a vulnerability

- Use **[Report a vulnerability](https://github.com/necromancer124/tarion/security/advisories/new)** (a private GitHub security advisory). Please don't open a public issue.
- Include what an attacker can do, the steps to reproduce it, and the version or commit.
- You'll get a reply within about a week. Once a fix is released, the advisory is published and you're credited unless you'd rather not be.

## What counts

Anything that breaks the promises in the [security model](README.md#security-model), for example:

- reading, forging, changing or redirecting messages, including relayed traffic and mailbox letters;
- impersonating a user or a server, or getting a key accepted that doesn't match the pinned one;
- a way for the server to learn more than the README says it can;
- logging in to someone else's account, or bypassing bans, invites or rate limits;
- crashing or exhausting a client or `tariond` remotely.

Known limitations listed in the README (for example, contact names visible in history file names) are tracked as normal issues. A way to read encrypted local data without the Windows login or the passphrase does count.

## Supported versions

Only the latest release and `master` get security fixes.
