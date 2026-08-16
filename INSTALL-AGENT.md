# Installing the JBound agent on a resolver

`deploy/bootstrap-agent.sh` takes an Unbound server and leaves a running agent
the panel can manage it through. It installs the dependencies, fetches the
source, builds the agent, installs the binary and the unit, hands the
configuration to `deploy/setup-agent.sh`, opens the agent port and proves the
service answers.

This is the alternative to `deploy/setup-target.sh`, not an addition to it. A
resolver is reached over SSH or through an agent, never both, and the choice is
fixed in the panel once the server is added.

[INSTALL.md](INSTALL.md) covers the panel host. Do that first: the panel is what
generates the token this script asks for.

## Why an agent rather than SSH

The SSH path needs an account, `sudo` and seven exact sudoers rules on the
resolver, because the panel sends command text that a login shell runs.

The agent path needs none of them. The panel names no file and sends no command
text: it asks the agent to write, to check and to reload, and the agent runs the
commands its own configuration names, on the file its own configuration names.
An agent that took a path from a request would be a way to write any file on
that host, which is exactly what the design refuses.

What it costs is a listening port, and a certificate to pin.

## Before you start

- A server running Debian, Ubuntu, or a member of the RHEL family. The script
  refuses anything else rather than installing half of it.
- Root.
- Unbound. The script offers to install it if it is missing.
- Outbound HTTPS, to reach GitHub and the Go download.
- A port the panel can reach, `8443` by default.
- The agent token. Add the server in the panel first: the panel shows the token
  once, on the page that creates it, and nothing shows it a second time.

## Adding the server in the panel first

1. Sign in as an administrator and open **Servers**.
2. Add the server with the transport set to **agent**, its address and its port.
   An agent server takes nothing else: it reports its own records file, and the
   commands it runs stay on the resolver.
3. Open the key panel. It shows the token once. Copy it now.

The transport cannot be changed later. The secret behind it is a private key on
one path and a token on the other, and a record that switched would point at a
file of the wrong kind.

## Running the script

Copy it onto the resolver and run it as root:

```
scp deploy/bootstrap-agent.sh root@dns1:/root/
ssh root@dns1 sh /root/bootstrap-agent.sh
```

While the repository is public it can be fetched directly:

```
curl -fsSLO https://raw.githubusercontent.com/KilimcininKorOglu/jbound-web-ui/main/deploy/bootstrap-agent.sh
sudo sh bootstrap-agent.sh
```

## What it asks

| Question | Default | What it decides |
| --- | --- | --- |
| Repository to clone | the GitHub remote | where the source comes from |
| Branch or tag to build | `main` | which version, and what a re-run upgrades to |
| Is the repository private | no | whether it asks for a GitHub token |
| Agent token from the panel | none, required | the credential the panel authenticates with |
| Records file the agent owns | `/etc/unbound/local_records.conf` | the only file the agent writes |
| Main Unbound configuration | `/etc/unbound/unbound.conf` | what the configuration check reads, and where the include line goes |
| Address the agent listens on | `0.0.0.0:8443` | the port the panel connects to |
| Panel address | empty | opens the port to that address alone rather than to the network |
| Install Unbound | yes, when it is missing | |

The account the agent runs as is not a question. It gets its own, unless the
host cannot grant it what it needs, and then the script says so.

Both tokens are typed without being echoed. Neither becomes a command argument
or an environment variable, because `/proc` hands both of those to any account
on the host. The GitHub token lives in a `600` file inside a directory only root
can enter and is removed when the script ends however it ends. The agent token
is written to `/etc/jbound-agent/token` with mode `600` and nowhere else.

## Running it unattended

```
sudo sh bootstrap-agent.sh -y \
  -t "$AGENT_TOKEN" \
  -P 10.0.0.5 \
  -b v1.0.0
```

| Flag | Effect |
| --- | --- |
| `-t TOKEN` | the agent token from the panel |
| `-r URL` | repository to clone |
| `-b REF` | branch or tag to build |
| `-f PATH` | records file |
| `-c PATH` | main Unbound configuration |
| `-a ADDR` | address the agent listens on |
| `-P ADDR` | panel address, so the firewall opens the port to it alone |
| `-u` | install Unbound when it is missing |
| `-R` | run the agent as root rather than under its own account |
| `-n` | leave the firewall alone |
| `-y` | ask nothing |

Passing the token on the command line puts it in the process list and in your
shell history. It is the way to script this, and the reason the interactive run
asks for it instead.

## What it leaves on the host

| Path | Mode | What it is |
| --- | --- | --- |
| `/usr/local/bin/jbound-agent` | `0755 root:root` | the agent |
| `/etc/jbound-agent` | `0700 jbound-agent` | holds the token and the private key |
| `/etc/jbound-agent/token` | `0600 jbound-agent` | the credential the panel presents |
| `/etc/jbound-agent/agent.crt` | `0644 jbound-agent` | the self signed certificate the panel pins |
| `/etc/jbound-agent/agent.key` | `0600 jbound-agent` | its private half |
| `/etc/jbound-agent/jbound-agent.env` | `0600 jbound-agent` | the two paths and the five commands |
| `/etc/systemd/system/jbound-agent.service` | `0644 root:root` | the unit |
| `/etc/polkit-1/rules.d/50-jbound-agent.rules` | `0644 root:root` | the one grant the restart needs |
| `/usr/local/src/jbound` | | the checkout, kept so a re-run can update it |
| `/usr/local/go` | | only when the host had no Go 1.26 or newer |

No sudoers rule is installed and no login is created. The account it does create
is described below. The group of `/etc/unbound` and of three files in it changes
so that account can do its work; the modes of `/etc/unbound` itself are widened
to `775` for the same reason.

## Which account it runs as

Its own: `jbound-agent`, a system account created by `setup-agent.sh`. It has no
home directory, no shell and a locked password, so there is nowhere to put an
`authorized_keys`, nothing to run if a key were accepted anyway, and nothing to
guess. An account that can be logged into is a way back in after the process it
belongs to has been closed.

What that account is granted is exact:

| Grant | Why |
| --- | --- |
| read on `unbound_control.key`, `unbound_control.pem`, `unbound_server.pem` | `unbound-control` refuses without all three |
| read on the trust anchor, `/var/lib/unbound/root.key` by default | `unbound-checkconf` fails on a file it cannot open even when nothing is wrong |
| write on the directories the records file and the main configuration sit in | both are replaced by a rename, so the write is on the directory |
| a polkit rule for `restart` and `reload` on `unbound.service` | the only step that needs a privilege at all |

Everything else still asks for a password. Measured on the account this script
creates: `systemctl stop unbound`, `systemctl restart ssh`, `systemctl
daemon-reload` and `systemctl restart jbound-agent` are all refused, `/etc/ssh`
is not writable and `/etc/shadow` is not readable.

The unit keeps the rest of its hardening either way:

| Setting | What it gives up |
| --- | --- |
| `NoNewPrivileges=yes` | cannot gain a privilege it does not start with |
| `CapabilityBoundingSet=` | no capabilities at all |
| `ProtectSystem=strict` | the whole filesystem is read only |
| `ReadWritePaths=/etc/unbound` | the one directory it may write |
| `RestrictSUIDSGID=yes` | cannot create a setuid file |
| `MemoryDenyWriteExecute=yes` | cannot write executable memory |

### When it stays root

A host with no polkit cannot grant the restart to anybody but root, and one with
no systemd has no unit to grant it on. `setup-agent.sh` says so and leaves the
agent as root, recording it in a drop-in at
`/etc/systemd/system/jbound-agent.service.d/user.conf` so the state is on disk
rather than only in the output of a script somebody ran once.

`-R` forces root deliberately. Install polkit and re-run the script to narrow it
again.

### What this does not contain

The agent repairs the main configuration when the include line is missing, so
the account can write `unbound.conf`. Unbound reads that file as root before it
drops to its own user, and the Debian build carries the python module. Anyone
who gets code running **as the agent account** can therefore still reach root on
that host through the resolver.

What the account change contains is narrower and still worth having: the code
that runs before a caller is authenticated, the TLS handshake, the HTTP parsing
and the JSON decoding, no longer runs as root. A flaw there lands on an account
with four grants rather than on the whole host.

What contains the **token** is the write check: the agent refuses to write
anything but records, so a stolen token manages DNS records and nothing else.
That check is on by default and needs no account change at all.

If you give it a records file or a main configuration outside `/etc/unbound`,
the script writes a drop-in at
`/etc/systemd/system/jbound-agent.service.d/paths.conf` that allows those
directories, because the unit alone would leave the agent unable to write the
file it was told to manage. Moving the paths back under `/etc/unbound` removes
the drop-in again.

## The commands the agent runs

The agent runs what its environment file names, and nothing else. The setup
script resolves each one on the host it runs on, because the paths differ:

| Key | Debian and Ubuntu | RHEL family |
| --- | --- | --- |
| `CHECK_CONF_CMD` | `/usr/sbin/unbound-checkconf <config>` | the same |
| `RELOAD_CMD` | `/usr/sbin/unbound-control reload_keep_cache` | the same |
| `RELOAD_FALLBACK_CMD` | `/usr/sbin/service unbound reload` | `/usr/bin/systemctl reload unbound` |
| `RESTART_CMD` | `/usr/sbin/service unbound restart` | `/usr/bin/systemctl restart unbound` |
| `STATUS_CMD` | `/usr/bin/systemctl is-active unbound` | the same |

A key left empty is a resolver that does not have that step, and the panel skips
that rung rather than reporting a failure. The bootstrap prints what each one
resolved to and warns about any that name a command the host does not have.

Install a missing command and re-run the script to pick it up, or edit the file
and restart the service:

```
systemctl restart jbound-agent
```

## Firewall

The agent port is the way into this resolver, so the script opens it to the
panel alone whenever you name the panel's address.

| Found | What it does |
| --- | --- |
| ufw | `ufw allow from <panel> to any port <port> proto tcp`, or the port to anywhere when no panel address was given |
| firewalld | a rich rule for the panel address, or the port in the default zone |
| nftables, used directly | changes nothing and prints the rule to add, because guessing which chain to write into is how an operator is locked out |
| none | says so and moves on |

Nothing else is opened here. The agent replaces the SSH path rather than adding
to it, so a resolver managed this way needs no inbound SSH from the panel at
all.

## Approving the fingerprint

The certificate is self signed on purpose. The panel pins the fingerprint an
operator approves, the same way it pins an SSH host key, so a public issuer
would add a step and prove nothing the pin does not already prove.

The script prints the fingerprint when it finishes. In the panel:

1. Press **Test** on the server.
2. The panel reports the fingerprint it was offered. Compare it with the one the
   script printed.
3. Approve it. It is stored with the server record, and a host that later offers
   a different one is refused rather than trusted again.

**Test** walks the whole path rather than only the connection: it authenticates,
reads the file, writes the current content back over itself, runs the
configuration check and asks for the service status. A command the agent cannot
run therefore shows up while you are adding the server, not during a change.

If you replace the certificate, the pin no longer matches and every connection
stops until an operator approves the new one. That is the point of it. Re-running
the bootstrap keeps the existing certificate for exactly this reason.

## Upgrading

Re-run the script. It pulls the chosen ref again, rebuilds, reinstalls and
restarts, and keeps the certificate and the token:

```
sudo sh /usr/local/src/jbound/deploy/bootstrap-agent.sh -y -b v1.1.0
```

The panel and its agents speak one protocol, defined once in `internal/agentapi`
and imported by both ends. Upgrade the panel and its agents together when the
protocol changes; a 501 from an agent means it has no command configured for
that step, not that it is too old.

## Removing it

```
systemctl disable --now jbound-agent
rm -f /etc/systemd/system/jbound-agent.service
rm -f /usr/local/bin/jbound-agent
rm -f /etc/polkit-1/rules.d/50-jbound-agent.rules
rm -rf /etc/jbound-agent /usr/local/src/jbound
userdel jbound-agent
systemctl daemon-reload
```

Delete the server in the panel as well, or it keeps reporting an unreachable
host. The records the panel wrote stay in `local_records.conf` until somebody
removes them there, and Unbound goes on answering them.

## When something is wrong

**The agent does not answer.**

```
systemctl status jbound-agent
journalctl -u jbound-agent -n 50 --no-pager
```

An unauthenticated request is the quickest proof that it is up:

```
curl -sk -o /dev/null -w '%{http_code}\n' https://127.0.0.1:8443/v1/info
```

`401` means the agent is running and refusing a caller with no token, which is
both halves of what you want to know. Anything else means it is not listening.

**The panel says the fingerprint does not match.** The certificate changed. That
happens when `/etc/jbound-agent` was removed and recreated, or the host was
rebuilt. Compare what the panel reports against:

```
openssl x509 -in /etc/jbound-agent/agent.crt -outform der |
    openssl dgst -sha256 -binary | openssl base64 | tr -d '='
```

If they match, approve the new one in the panel. If they do not, something else
is answering on that address, and that is worth stopping to understand.

**The panel says it is unreachable.** The port is closed, or the firewall opened
it to an address the panel does not come from. Check from the panel host:

```
curl -sk -o /dev/null -w '%{http_code}\n' https://<resolver>:8443/v1/info
```

**A change reaches the agent but the resolver does not answer it.** The records
file was written and the reload did not happen, or the include line is missing
from the main configuration. The agent adds that line itself when it is missing,
and the panel writes an audit row when it does. Read what the resolver thinks:

```
unbound-checkconf /etc/unbound/unbound.conf
grep -n include /etc/unbound/unbound.conf
```
