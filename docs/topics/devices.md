# devices: use your account on more than one device

Each device keeps its own key; an account holds up to 8. A new device needs
your password and approval from a device you already have, so a stolen
password alone gets nobody in.

## Adding a device

1. On the new device, log in with your password:
   `tarion start -server SERVER:63425 -user alice -pass "..."`
   It waits and shows a code:
   `this device is waiting to be added to alice. On a device already signed in, run: tarion devices approve 7WMW-26Z2`
2. On a device that's already signed in:
   `tarion devices approve 7WMW-26Z2`
   It shows the new device's name and ID and asks you to confirm. Compare
   the ID with `tarion id` on the new device. The new device then logs in by
   itself within a few seconds.

Codes last 15 minutes. If it expired, log in on the new device again.

## Managing devices

```
tarion devices                   # list them (name, ID, who approved it, online)
tarion devices remove laptop     # take one off; it is signed out at once
```

You can remove a device by name or ID, but not your only one.

## What your contacts see

Nothing changes for them. The approving device signs the new one into your
account, and their Tarion checks that signature chain back to the key they
pinned, so they accept your new device with no "key changed" warning, and
the server can't add a device of its own.

All your online devices receive every message. Each keeps its own history;
history isn't synced between devices.

## Lost every device?

Your server's operator can run `tariond devices reset NAME`. Your next
password login becomes the account's first device again. Your contacts then
see a key change, which is correct: they should check it's really you.

See also: keys, start.
