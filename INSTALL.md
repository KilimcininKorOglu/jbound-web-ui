# Installing JBound on a bare server

`deploy/bootstrap.sh` takes a server that has nothing on it and leaves a running
panel. It installs the build dependencies, fetches the source from git, builds
both binaries, runs `deploy/install.sh`, writes your answers into the
environment file, sets the firewall and starts the service.

It does not install TLS. The panel speaks plain HTTP on the loopback address and
expects a reverse proxy in front of it. That step is yours, and
[Reverse proxy](#reverse-proxy) below carries a working configuration for nginx
and for Caddy.

Everything the script does can be done by hand. The README describes the same
install one step at a time; this file is the automated path and the decisions
that come with it.

## Before you start

- A server running Debian, Ubuntu, or a member of the RHEL family (Rocky, Alma,
  RHEL). The script refuses anything else rather than installing half of it.
- Root, or an account that can `sudo`.
- Outbound HTTPS, to reach GitHub and the Go download.
- One local account that will administer the panel. The panel has no user
  database: it authenticates against the local accounts of its own host.

The panel host does not run Unbound. It reaches the resolvers over SSH or
through an agent, and those are prepared separately.

## Getting the script onto the server

While the repository is public:

```
curl -fsSLO https://raw.githubusercontent.com/KilimcininKorOglu/jbound-web-ui/main/deploy/bootstrap.sh
sudo sh bootstrap.sh
```

While it is private, `raw.githubusercontent.com` will not serve it. Copy the
file from a checkout instead:

```
scp deploy/bootstrap.sh root@panel:/root/
ssh root@panel sh /root/bootstrap.sh
```

The script asks whether the repository is private and, if it is, reads a GitHub
token that has read access to it. The token is typed without being echoed, is
written to a file with mode `600` inside a directory only root can enter, is
used for that one clone, and is removed when the script ends however it ends.
It never becomes a command argument or an environment variable, because
`/proc` hands both of those to any account on the host.

## What it asks

Every question has a default in brackets. An empty line takes it.

| Question | Default | What it decides |
| --- | --- | --- |
| Repository to clone | the GitHub remote | where the source comes from |
| Branch or tag to build | `main` | which version you get, and what a re-run upgrades to |
| Is the repository private | no | whether it asks for a token |
| Local group whose members administer the panel | `sudo`, `wheel` on RHEL | who may manage servers, groups, settings and the SIEM page |
| Local group allowed to sign in at all | empty | empty means every local account at or above the uid below |
| Lowest uid allowed to sign in | `1000` | keeps the system accounts out |
| Address the panel listens on | `127.0.0.1:8080` | the address the reverse proxy will point at |
| Local account to add to the admin group | empty | skip it if the account is already a member |
| Will the panel be reached over plain HTTP | no | answering yes sets `COOKIE_SECURE=false` |
| Open 80 and 443 for a reverse proxy | yes | what the firewall step allows |
| Enable ufw now | no | only asked when ufw is installed and inactive |

Leaving the listen address on the loopback interface is the intended setup. The
script warns if you give it an address other hosts can reach, because the panel
would then be serving plain HTTP to the network.

## Running it unattended

Every answer has a flag, and `-y` takes the default for anything you did not
name:

```
sudo sh bootstrap.sh -y \
  -b v1.0.0 \
  -g dnsadmins \
  -a alice \
  -p
```

| Flag | Effect |
| --- | --- |
| `-r URL` | repository to clone |
| `-b REF` | branch or tag to build |
| `-g GROUP` | `ADMIN_GROUP` |
| `-G GROUP` | `ALLOWED_GROUP` |
| `-m UID` | `MIN_UID` |
| `-l ADDR` | `LISTEN_ADDR` |
| `-a USER` | local account to add to the admin group |
| `-p` | open 80 and 443 |
| `-k` | `COOKIE_SECURE=false` |
| `-n` | leave the firewall alone |
| `-y` | ask nothing |

`-y` cannot supply a token, so an unattended run needs the repository to be
readable without one.

## What it leaves on the host

| Path | Mode | What it is |
| --- | --- | --- |
| `/usr/local/bin/jbound` | `0755 root:root` | the panel |
| `/usr/local/libexec/jbound-authhelper` | `4750 root:jbound` | the setuid PAM helper, the only privileged part |
| `/etc/jbound/jbound.env` | `0640 root:jbound` | the environment file, never overwritten by a later run |
| `/etc/pam.d/jbound` | `0644 root:root` | the PAM service the helper calls |
| `/var/lib/jbound` | `0700 jbound:jbound` | the database, the SSH keys and the agent tokens |
| `/etc/systemd/system/jbound.service` | `0644 root:root` | the unit |
| `/usr/local/src/jbound` | | the checkout, kept so a re-run can update it |
| `/usr/local/go` | | only when the host had no Go 1.26 or newer |

`install.sh` reads the helper mode and the data directory mode back after
writing them, and refuses to finish if either is wrong. It also refuses to
finish while `/etc/sudoers.d/jbound` exists, because the panel account is meant
to hold no root command.

The setuid helper is the only privileged part. The panel sends its audit trail
to the collector over an ordinary socket, so it needs no syslog daemon on the
host, no file under `/etc/rsyslog.d` and no sudoers rule.

An upgrade from a release that forwarded through rsyslog removes
`/etc/sudoers.d/jbound`, `/etc/rsyslog.d/60-jbound.conf` and
`/usr/local/sbin/jbound-siem-apply`. The rules in
`/var/lib/jbound/siem-rules.conf` are left alone: the panel reads them once at
startup and carries the collector they name into its own settings, so the trail
keeps flowing across the upgrade. Delete that file afterwards if you want it
gone. `/var/log/jbound.log` stops filling and is left where it is.

## Reverse proxy

The panel listens on `127.0.0.1:8080` and speaks plain HTTP. Put one of these in
front of it.

Two settings matter more than the rest:

- **A read timeout above five minutes.** A change that reaches a whole group can
  legitimately take as long as `fleet_operation_timeout`, which defaults to five
  minutes and can be set to ten. nginx gives up after sixty seconds by default,
  and the operator loses the per-server report of a write that did happen.
- **`Host` passed through.** The panel compares the `Origin` header against the
  host it was reached on. A proxy that rewrites `Host` makes every form
  submission look like a cross-site request.

### nginx

```nginx
server {
    listen 443 ssl;
    server_name panel.example.net;

    ssl_certificate     /etc/letsencrypt/live/panel.example.net/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/panel.example.net/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;

        # A fleet write may run for minutes. The default of 60s turns a slow
        # but successful change into a 504 with no report.
        proxy_read_timeout 15m;
        proxy_send_timeout 15m;
    }
}

server {
    listen 80;
    server_name panel.example.net;
    return 301 https://$host$request_uri;
}
```

### Caddy

```caddy
panel.example.net {
    reverse_proxy 127.0.0.1:8080
}
```

That is the whole file. Caddy obtains and renews the certificate itself, its
`read_timeout` and `response_header_timeout` have no default, so a slow fleet
write is not cut off, and it passes the original `Host` through to a plain HTTP
upstream. The two settings nginx needs are already what Caddy does.

### What a proxy costs you

The panel reads the client address from the connection and ignores
`X-Forwarded-For` and every other forwarding header. A client supplied header
would let anyone reset the login rate limit and forge a session fingerprint, so
trusting one is worse than not having it.

Behind a proxy on the same host that means:

- Every audit row records the address of the proxy, `127.0.0.1`, rather than the
  operator's own address. The user name in the row is still the real one.
- The login rate limit counts every failure against one bucket, so it becomes a
  limit for the whole panel rather than one per source address.

If the address in the trail matters to you, take it from the proxy's own access
log, which does see it.

## Firewall

The script sets whichever firewall it finds running.

| Found | What it does |
| --- | --- |
| ufw | allows the SSH port first, then 80 and 443 if asked. Offers to enable ufw only if it is inactive, and never enables it without an answer |
| firewalld | adds the SSH port and the `http` and `https` services to the default zone, permanently, then reloads |
| nftables, used directly | changes nothing. It prints the rules to add and says why: guessing which chain to write into is how an operator is locked out of their own server |
| none | says so and moves on |

The SSH port is read from `sshd -T`, so a port set in a drop-in file is found.
It is allowed before anything else, because enabling a firewall that denies
inbound traffic would otherwise close the session running the script.

Nothing opens the panel port. It listens on the loopback interface, and the
reverse proxy is what the network reaches.

Outbound, the panel needs to reach every managed resolver: port 22 for a server
over SSH, and the agent port, 8443 by default, for a server with an agent. Hosts
with a restrictive egress policy have to allow those.

## First sign in

Open the panel through the proxy and sign in with a local account of the panel
host, using that account's own password. A member of `ADMIN_GROUP` gets the
administrative pages; anybody else may manage records only.

If nobody can sign in, the three values that decide it are in
`/etc/jbound/jbound.env`: `ADMIN_GROUP`, `ALLOWED_GROUP` and `MIN_UID`. They are
kept in the environment rather than in the database, because anybody who could
write the database could otherwise make themselves an administrator. Edit them
there and restart the service.

## Preparing the DNS servers

The panel is now running and manages nothing. Each resolver is prepared one way
or the other, never both:

```
# over SSH, on the resolver
sudo ./deploy/setup-target.sh -k "ssh-ed25519 AAAA... jbound"

# with the agent, on the resolver
sudo ./deploy/setup-agent.sh -t "<the token the panel showed once>"
```

The panel generates the key pair or the token when you add the server, and shows
you the half the setup script needs.

For the agent path there is a bootstrap of its own, which builds and installs the
agent on a bare resolver the way this one did the panel:
[INSTALL-AGENT.md](INSTALL-AGENT.md). The README covers both paths by hand.

## Upgrading

Re-run the script. It pulls the chosen ref again, rebuilds, reinstalls and
restarts, and leaves `/etc/jbound/jbound.env` exactly as you left it:

```
sudo sh /usr/local/src/jbound/deploy/bootstrap.sh -y -b v1.1.0
```

When the new binary has a database migration to apply, it copies the database
first, next to the original as `jbound.db.before-<migration>.sql`, and refuses to
start if it cannot write that copy. A migration can be one way, so that file is
the way back to the version that was running before.

Take a backup first anyway:

```
sudo -u jbound /usr/local/bin/jbound backup /var/backups/jbound/$(date +%F)
```

## Removing it

```
systemctl disable --now jbound
rm -f /etc/systemd/system/jbound.service /etc/pam.d/jbound
rm -f /usr/local/bin/jbound /usr/local/libexec/jbound-authhelper
rm -rf /usr/local/share/doc/jbound /usr/local/src/jbound
systemctl daemon-reload
```

`/var/lib/jbound` and `/etc/jbound` are left for you to remove deliberately. The
first holds the SSH private key of every managed server and the audit trail; the
second holds the decisions about who may sign in. Delete them when you are sure,
and remember that the managed resolvers keep the records the panel wrote until
somebody removes them there.

## When something is wrong

**The script stopped.** It stops at the first failure rather than continuing
past it. The message names the step. Nothing before that point is undone,
and re-running is safe.

**The panel does not answer its health check.**

```
systemctl status jbound
journalctl -u jbound -n 50 --no-pager
```

`GET /healthz` reaches the database rather than reporting that a process is
alive, so `503 unavailable` means the database, the disk or the data directory,
not the network.

**Every sign in fails.** The helper is what talks to PAM. Check that it is
`4750 root:jbound` and that `/etc/pam.d/jbound` includes a stack this
distribution has: `common-auth` on Debian and Ubuntu, `system-auth` on the RHEL
family. The panel answers one shared rejection for every failed sign in on
purpose, so the reason is in the log rather than on the page.

**SELinux is enforcing.** The script restores the file contexts it can and warns
you. This combination is not covered by the project's tests. Read what was
denied with:

```
ausearch -m avc -ts recent
```

**A fleet action times out in the browser but the change reached the servers.**
That is the proxy read timeout. Raise it as shown above.
