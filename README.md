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
- Keeps the file each server carried before the last change, and puts it back
  from the servers page when a change turns out to be wrong.
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

### Log level

`LOG_LEVEL` in the environment file takes `debug`, `info`, `warn` or `error`,
and defaults to `info`. A running panel switches to `debug` and back on
`SIGUSR1`:

```
sudo systemctl kill -s USR1 unbound-web
```

Raising the level this way keeps the SSH connections, the record cache and the
requests that are being diagnosed. A restart takes all three away, which is
usually the state an incident is about.

## Settings

The **Settings** page stores its values in the database and every change takes
effect on the next read, without a restart. It covers four groups: timings
(session, cache, SSH and DNS timeouts), limits (login attempts, fleet
concurrency, page size), the SIEM switch, and the interface defaults a browser
gets before anybody picks a language or a theme.

The language and the theme of one browser are its own choice and live in a
cookie. Nothing about a reader is stored server side.

## Backup and restore

Take the backup with the panel binary, as the service account:

```
sudo -u unbound-web unbound-web backup /var/backups/unbound-web/$(date +%F)
```

The target directory must not exist yet. The command writes:

- `unbound.db`, a consistent snapshot of the server records, the groups, the
  host key pins and the audit trail.
- `keys/`, the SSH private keys.

Do not copy `/var/lib/unbound-web` with `cp` or `tar` while the panel runs. The
database is open in WAL mode, so its state is spread across `unbound.db` and
`unbound.db-wal`, and a file level copy can catch the two at different moments.
The result is a database that is either short of committed transactions or
refused as corrupt, and you find out during the recovery. The command uses
`VACUUM INTO`, which reads under one transaction and writes a single self
contained file, then reopens that file and runs `PRAGMA integrity_check` before
it reports success.

The directory reaches every managed DNS server, so encrypt it before it leaves
the host.

### Restore

```
systemctl stop unbound-web
rm -rf /var/lib/unbound-web/unbound.db /var/lib/unbound-web/unbound.db-wal \
       /var/lib/unbound-web/unbound.db-shm /var/lib/unbound-web/keys
cp -a <backup>/unbound.db <backup>/keys /var/lib/unbound-web/
chown -R unbound-web:unbound-web /var/lib/unbound-web
chmod 700 /var/lib/unbound-web /var/lib/unbound-web/keys
chmod 600 /var/lib/unbound-web/unbound.db /var/lib/unbound-web/keys/*
systemctl start unbound-web
```

`/etc/unbound-web/unbound-web.env` is not part of the backup. It is installed
once and never rewritten, so keep it with your configuration management.

### What this gets you

- **Recovery point.** The moment the last backup ran. There is no continuous
  archiving, so everything after it is lost: records added through the panel
  are still on the resolvers, but audit rows, new servers and group changes
  from that window are not.
- **Recovery time.** The time to place the directory and start the service. No
  DNS server has to be touched, because the private keys and the approved host
  keys come back with the backup.

Exercise the restore on a spare host. A backup nobody has restored is a backup
nobody knows the state of, and the fleet is the thing that pays for the
difference.

### The copy an upgrade leaves behind

When a new binary has a migration to apply, it copies the database first and
writes it next to the original as `unbound.db.before-<migration>.sql`. A
migration can be one way: `0002` drops a column the previous binary reads, so
without that copy there is no going back to the version that was running
before. Roll back by stopping the service, putting the copy in place of
`unbound.db` and installing the older binary.

The panel refuses to start if it cannot write the copy, because the copy is
what protects against the step that follows it. Each file is written once; a
second attempt at the same upgrade keeps the first copy, which is the state you
actually want back. Delete them yourself once the upgrade has proven itself.

### Running it on a timer

The installer sets up no schedule, because where the backups go and how long
they are kept is your policy. A pair of units is enough:

```
# /etc/systemd/system/unbound-web-backup.service
[Service]
Type=oneshot
User=unbound-web
ExecStart=/bin/sh -c 'exec /usr/local/bin/unbound-web backup /var/backups/unbound-web/$(date +%%F-%%H%%M)'

# /etc/systemd/system/unbound-web-backup.timer
[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

Removing the old directories is your policy too, and so is moving them off the
host.

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
make check        # every check that needs no container
make test         # unit tests only
make dev-itest    # integration tests against the containers
make cppcheck     # the setuid helper, on top of -Wall -Wextra -Werror
make shellcheck   # the install and setup scripts
make coverage     # coverage of every package
```

`check` covers the Go analysers, the vulnerability scan and the unit tests, and
it covers the setuid helper and the scripts that run as root during install,
which are the two highest risk artefacts here. Those two need `cppcheck` and
`shellcheck` on the host, and say so rather than passing quietly when they are
missing. `make dev-cppcheck` runs the helper analyser inside the panel
container instead, for a workstation that has no `cppcheck`. The Go analysers are pinned and run through `go run`, so they need
nothing installed beyond the Go toolchain.

`.github/workflows/check.yml` runs the same checks on every push and pull
request, and the vulnerability scan again once a week, because an advisory
lands against source that did not change.

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
