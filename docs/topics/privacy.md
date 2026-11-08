# privacy: what the server and others can and can't see

**Never visible to the server:** what you write. Chats are end-to-end
encrypted between the two devices (QUIC with mutually authenticated TLS 1.3
and a post-quantum hybrid key exchange), with keys that never leave them.

**What the server knows:** your username, your devices' public keys, a
password hash (argon2id), your IP address while you're online, who you look
up, and, only if you turned them on, who you exchange relayed traffic or
mailbox letters with, when, and how much.

**What a network observer sees:** UDP packets between your IP and the server
or peers, their sizes and timing, and that they're QUIC with the ALPN
`tarion/2` or `tarion-dir/1`. Not messages, names or passwords.

**On your computer:** history, contacts and keys are encrypted (see `tarion
help protect`).

**Who decides:** you. The relay and the mailbox are off unless you, the
other person and the server operator all turn them on. If even the
directory server knowing your IP is too much, run your own (`tariond`), or
connect by address without one.

The full threat model is in docs/security.md.

See also: protect, relay, mailbox, keys.
