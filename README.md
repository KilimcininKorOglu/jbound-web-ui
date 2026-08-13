# Unbound DNS Panel

A web panel that manages the local DNS records of several Unbound resolvers at
once. One record is written to every server of a group in one action, the
servers are compared against each other, and every change is recorded in an
audit trail that can be mirrored to a SIEM.

The panel holds no DNS service of its own. It reaches each resolver over SSH,
writes one include file, and reloads the resolver.

## What it does

- Reads and writes `host_entries.conf` on every managed server over SSH.
- Adds, edits and deletes A, AAAA, CNAME, MX and TXT records on a single server
  or on a whole group.
- Compares the servers of a group and repairs a record that is missing or
  different on some of them.
- Reloads the resolvers, and asks each one what it answers for a name.
- Records every action with the user, the address and the result, and can mirror
  the trail to syslog in CEF.
- Signs users in against the local accounts of the panel host through PAM.
- Speaks English and Turkish, follows a light or dark theme or the one the
  operating system asks for.

## Requirements

Panel host:

- Linux with systemd, PAM and rsyslog.
- Go 1.26 and a C compiler to build.
- `dig` for the query page.
- A reverse proxy for TLS. The panel listens on the loopback address.

Managed DNS server:

- Unbound with an `include:` line for the host entries file.
- An SSH account, `sudo`, and three exact sudoers rules created by
  `deploy/setup-target.sh`.

## Install

Build and install:

```
make build build-helper
sudo make install
```

`deploy/install.sh` does the work and can be re-run at any time. It creates the
`unbound-web` system account, the state directory, both binaries, the PAM
service file, the environment file, the rsyslog file the panel owns, two sudoers
rules and the systemd unit. It never overwrites the environment file, and it
reads back the two modes the whole design rests on:

| Path | Mode | Why |
| --- | --- | --- |
| `/usr/local/libexec/unbound-web-authhelper` | `4750 root:unbound-web` | setuid root so PAM can read the shadow database, group-only so no other account can use it as a password oracle |
| `/var/lib/unbound-web` | `0700 unbound-web` | the SSH private keys live under it |

Then review `/etc/unbound-web/unbound-web.env` and start the service:

```
sudo systemctl enable --now unbound-web
```

### Who may sign in

The panel has no user database. It authenticates against the local accounts of
its own host, through a PAM service file installed as `/etc/pam.d/unbound-web`.

- `ADMIN_GROUP` (default `sudo`) decides who administers the panel: servers,
  groups, the SIEM configuration and the settings page.
- `ALLOWED_GROUP` limits who may sign in at all. Left empty, every local account
  with a uid at or above `MIN_UID` may sign in and manage records.
- `MIN_UID` (default `1000`) keeps the system accounts out.

These three live in the environment file rather than in the database, because
anybody who could write the database could otherwise make themselves an
administrator.

### Reverse proxy

The panel listens on `127.0.0.1:8080` and expects TLS to be terminated in front
of it. The session cookie carries the `Secure` flag by default, so a panel
reached over plain HTTP needs `COOKIE_SECURE=false` and a network you trust.

## Prepare a DNS server

Run the setup script as root on every resolver:

```
sudo ./deploy/setup-target.sh -k "ssh-ed25519 AAAA... unbound-web"
```

It creates the `dnsops` account, adds the public key the panel generated,
creates `/etc/unbound/host_entries.conf` with mode `644` and installs three
exact sudoers rules. The permissions of `/etc/unbound` are left alone: reading
needs no sudo, and writing goes through the three rules.

The script prints the values to enter in the panel, because the paths of `tee`,
`mv` and `service` differ between distributions and each sudoers rule has to
match the command the panel runs.

Re-run the script after changing the host entries path in the panel. The rules
are derived from that path.

## Add a server

1. Sign in as an administrator and open **Servers**.
2. Add the server with its address, the SSH account and the paths the setup
   script printed. The panel generates an SSH key pair for it and stores the
   private half under `<DATA_DIR>/keys` with mode `0600`.
3. Open the key panel and copy the public key onto the server, or hand it to
   `setup-target.sh -k`.
4. Press **Test**. The first connection reports the host key of the server and
   nothing is written until it is approved.
5. Approve the host key. It is stored with the server record, and a server that
   later offers a different key is refused rather than trusted again.

A server can be added to a group. A group is what a record action targets when
it should reach more than one machine.

## Audit trail and SIEM

Every action is written to the database with the user, the uid, the address, the
target and the result. The **Audit Logs** page filters it.

The **SIEM Config** page manages the rsyslog rules of the panel host and a
switch that turns the mirror on and off. With the switch off the panel keeps
writing its own trail and stops sending it, which is what an operator wants
while a receiver is being repaired. The rules stay where they are.

## Settings

The **Settings** page stores its values in the database and every change takes
effect on the next read, without a restart. It covers four groups: timings
(session, cache, SSH and DNS timeouts), limits (login attempts, fleet
concurrency, page size), the SIEM switch, and the interface defaults a browser
gets before anybody picks a language or a theme.

The language and the theme of one browser are its own choice and live in a
cookie. Nothing about a reader is stored server side.

## Backup

Back up `/var/lib/unbound-web`. It holds:

- `unbound.db`, the server records, the groups and the audit trail.
- `keys/`, the SSH private keys.

The backup gives access to every managed DNS server, so it has to be encrypted.

## Development

The development stack runs the panel and three Unbound targets in containers.
The panel container carries its own rsyslog, so the SIEM page works there as
well. No part of it touches the host.

```
make dev-up        # build and start the stack
make dev-verify    # check the acceptance criteria
make dev-logs      # follow the panel logs
make dev-down      # stop it and drop the volumes
```

The panel is served on `http://127.0.0.1:8330`. `make dev-env` creates
`.env.dev` from the example on the first run and refuses to start until every
`CHANGEME` value is replaced. The test accounts are created inside the container
by `docker/testusers.sh`.

### Checks

```
make check        # vet, staticcheck, modernize, govulncheck and the unit tests
make test         # unit tests only
make dev-itest    # integration tests against the containers
make cppcheck     # the setuid helper, on top of -Wall -Wextra -Werror
make shellcheck   # the install and setup scripts
make coverage     # coverage of every package
```

The analysers are pinned and run through `go run`, so a checkout needs nothing
installed beyond the Go toolchain.

## Layout

```
cmd/unbound-web      the service
authhelper           the setuid PAM helper, the only privileged component
internal/auth        sessions, CSRF, rate limiting, PAM
internal/server      server and group records, SSH keys
internal/transport   the SSH connection pool
internal/dnsfile     the host entries format
internal/fleet       actions that touch more than one server
internal/audit       the audit trail and the CEF mirror
internal/settings    the settings registry and their storage
internal/i18n        the language catalogues
internal/web         handlers, templates and static assets
deploy               install script, systemd unit, PAM file, target setup
docker               the development stack
```
