# protect: how your data on this computer is encrypted

Your identity key, chat history, contacts (peers.json), queued messages and
dropped-message log are encrypted on disk (XChaCha20-Poly1305 with a random
data key). Someone who copies the folder, from a backup, a synced folder or
a stolen laptop, can't read them or pose as you.

`vault.json` holds the data key, protected one of two ways:

- **Your Windows login (DPAPI), the default on Windows.** On automatically,
  nothing to type. Only your Windows user on this PC can unlock it.
- **A passphrase, on any OS** (argon2id). Tarion asks for it when it starts.

```
tarion protect              # how is my data protected?
tarion protect passphrase   # use a passphrase (asks twice)
tarion protect windows      # back to the Windows login
tarion protect off          # store it unencrypted again
```

Stop the background process first (`tarion stop`).

## Good to know

- Forgetting the passphrase means the data can't be recovered. Log in again
  with your password; on an account with other devices, approve this one
  from them (see `tarion help devices`).
- A Windows password *reset* by an administrator (not a normal change)
  makes DPAPI-protected data unreadable. Use a passphrase if that's a risk.
- Not encrypted: config.json (server, username and settings; the password
  only until your first login), revoked.json, and history file names, which
  are your contacts' names.
- On Linux and macOS, data is only encrypted if you set a passphrase.
- To skip automatic encryption on a new Windows install, set
  `TARION_NO_AUTO_PROTECT=1`.

See also: keys, config.
