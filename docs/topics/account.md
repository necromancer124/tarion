# account: password, deleting your account

```
tarion passwd             # change your password (asks for the current one)
tarion delete-account     # delete your account on the server
```

- Both ask for your current password and are rate-limited like logins.
- New passwords need 10+ characters (the operator may require more) and
  must not contain your username.
- Deleting asks you to type your username, frees the name, signs out all
  your devices and deletes your server mailbox. Local history and keys stay
  on your devices.
- The password is only needed to create the account and to add a device:
  devices on the account log in with their keys.

See also: devices, start.
