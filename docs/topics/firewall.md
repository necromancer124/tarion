# firewall: when your computer's firewall keeps people out

Windows Firewall blocks incoming connections by default. Its "Allow access"
prompt only appears for a program in a window, never for the background
process, and clicking "Cancel" on it creates a rule that blocks Tarion.

Without an allow rule you can still message people and they can answer:
Tarion sends outward first, which opens a temporary path. But a forwarded
port won't work, and people can't connect to you first.

```
tarion firewall            # does Windows Firewall let people reach you?
tarion firewall allow      # add a rule (Windows asks for administrator permission once)
tarion firewall remove     # delete it again
```

- The rule covers only incoming UDP to tarion.exe on its chat port.
  `allow` first removes old rules for the program, including a block rule
  from a "Cancel" click.
- The background process warns at startup when the firewall is in the way,
  and `tarion portmap` names it when it's why a test packet was dropped.
- To add the rule yourself, in an administrator terminal:
  `netsh advfirewall firewall add rule name="Tarion chat (UDP 63426)" dir=in action=allow protocol=UDP localport=63426 program="C:\path\to\tarion.exe"`
- Linux and macOS firewalls aren't checked. Allow the port yourself, for
  example `sudo ufw allow 63426/udp`.

Moving or updating tarion.exe to a new path needs the rule again: Windows
rules name the program's path.

See also: portmap, network, troubleshooting.
