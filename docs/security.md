# Security model

What Tarion protects, against whom, and where its limits are. To report a
vulnerability, see [SECURITY.md](../SECURITY.md).

## Goals

1. Nobody but the two people can read a conversation: not the server, not
   the network, not the relay.
2. Nobody can pose as someone else, including the server.
3. The server learns as little as possible, and nothing passes through it
   unless everyone involved agreed.
4. Data on a lost or copied computer stays unreadable.

## Who we defend against

| Adversary | Can | Can't |
|---|---|---|
| Network observer (ISP, Wi-Fi, firewall) | see that you use Tarion (QUIC with ALPN `tarion/2`, `tarion-dir/1`), packet sizes and timing, your peers' IP addresses | read messages, names or passwords; inject or alter messages; decrypt recorded traffic later, even with a quantum computer (hybrid post-quantum key exchange) |
| TLS-inspecting proxy | block Tarion | read it: keys are pinned, not trusted through certificate authorities, so interception fails the connection |
| The directory server | see usernames, device keys, IPs while online, who looks up whom; with the relay or mailbox on, who talks to whom, when and how much; refuse service | read messages; forge a message or a mailbox letter; add a device to someone's account; redirect a contact you've already pinned |
| The server on first contact | hand you its own key instead of your contact's | survive verification: compare `tarion id` out of band, or set the contact's `id` in config.json |
| Someone with your password | wait for approval | log in on a new device: that needs approval from one of your devices |
| Someone with a copy of your Tarion folder | see your contacts' names (history file names) and config.json | read history, contacts or queued messages, or use your identity key, without your Windows login or passphrase |
| Another program running as you, on your unlocked computer | read what you can read | (out of scope: no app can defend against this) |

## How each goal is met

- **Encryption in transit:** QUIC with TLS 1.3, mutual authentication with
  Ed25519 identity keys, X25519MLKEM768 key exchange.
- **Identity:** a peer ID is the hash of a public key, and TLS proves
  possession of the private key. Contacts are pinned on first contact
  (trust on first use); a changed key stops sending and asks the user.
- **Devices:** new devices are approved by an existing one, which signs a
  certificate. Contacts verify the chain from their pin, so the server
  can't add a key. Trust only flows down the chain, so a forged
  "approver" doesn't help.
- **Relay:** forwards QUIC packets whose end-to-end handshake it isn't part
  of. Opt-in for the operator and both users.
- **Mailbox:** letters are signed by the sender and sealed to each recipient
  device's box key, whose signature the sender checks along with the device
  chain. Opt-in for the operator and both users.
- **At rest:** identity key, history, contacts, outbox and dropped log are
  encrypted with XChaCha20-Poly1305 under a data key protected by Windows
  DPAPI or an argon2id passphrase. Each file's kind is authenticated, so
  files can't be swapped.
- **Server accounts:** argon2id password hashes, rate limits on every
  password check, constant-time comparisons, atomic account file writes,
  strict name validation (nothing in a name can break a file, a log line or
  a terminal).

## Known limits

- **Metadata:** the server knows who is online and who looks up whom. Run
  your own server, or connect by address, if that matters.
- **Trust on first use:** the first key you see is trusted until you
  verify it. Verify, or configure contacts' IDs.
- **Removed devices:** a removed device stays in the signed chain marked
  removed; a malicious server could show it as active again (it can't add
  a new one). Its key could then receive messages again.
- **Linux and macOS** encrypt local data only with a passphrase.
- **Ed25519 identity keys are not post-quantum.** A future quantum computer
  could forge identities, though not read recorded traffic.
- **No forward secrecy for mailbox letters:** they're sealed to a device's
  long-term box key, so someone who later steals that device's identity key
  and the server's stored letters could read letters still waiting.
