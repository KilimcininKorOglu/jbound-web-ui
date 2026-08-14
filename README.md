# JBound

A web panel that manages the local DNS records of several Unbound resolvers at
once. One record is written to every server of a group in one action, the
servers are compared against each other, and every change is recorded in an
audit trail that can be mirrored to a SIEM.

The panel holds no DNS service of its own. It reaches each resolver, writes one
include file, and reloads the resolver. A server is reached over SSH or through
an agent that runs on it, and the choice is made per server.

## What it does

- Reads and writes `local_records.conf` on every managed server.
- Adds, edits and deletes A, AAAA, CNAME, MX and TXT records on a single server
  or on a whole group, one record at a time or several in one pass.
- Compares the servers of a group and repairs a record that is missing or
  different on some of them.
- Keeps the file each server carried before the last change, and puts it back
  from the servers page when a change turns out to be wrong.
- Checks the configuration of a resolver before a change goes live, and puts the
  previous file back when the resolver refuses it.
- Reloads the resolvers without losing their cache where it can, restarts them
  where it must, and proves each one is running afterwards.
- Asks each resolver what it answers for a name.
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

Managed DNS server, over SSH:

- Unbound with an `include:` line for the records file. The setup script adds
  the line when it is missing.
- An SSH account, `sudo`, and seven exact sudoers rules created by
  `deploy/setup-target.sh`.
- `unbound-control` for the reload that keeps the cache. A resolver without it
  still works: the panel falls back to a plain reload, and to a restart.

Managed DNS server, through the agent:

- Unbound, and the `jbound-agent` binary installed by `deploy/setup-agent.sh`.
- A port the panel can reach, `8443` by default.
- No account, no `sudo` and no sudoers rule. The panel sends no command text and
  names no file, so there is nothing for a login shell to run.

## Install

Build and install:

```
make build build-helper
sudo make install
```

`deploy/install.sh` does the work and can be re-run at any time. It creates the
`jbound` system account, the state directory, both binaries, the PAM
service file, the environment file, the rsyslog file the panel owns, two sudoers
rules, the third-party licences and the systemd unit. It never overwrites the
environment file, and it reads back the two modes the whole design rests on:

| Path | Mode | Why |
| --- | --- | --- |
| `/usr/local/libexec/jbound-authhelper` | `4750 root:jbound` | setuid root so PAM can read the shadow database, group-only so no other account can use it as a password oracle |
| `/var/lib/jbound` | `0700 jbound` | the SSH private keys and the agent tokens live under it |

Then review `/etc/jbound/jbound.env` and start the service:

```
sudo systemctl enable --now jbound
```

### Who may sign in

The panel has no user database. It authenticates against the local accounts of
its own host, through a PAM service file installed as `/etc/pam.d/jbound`.

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

`GET /healthz` needs no session and answers `200 ok` only when the database
still answers a query. A panel whose database has become unreadable, whose disk
is full or whose data directory has been unmounted returns `503 unavailable`,
so a monitor built on it reports the outage rather than the process. The reason
goes to the log, because the route is open to anybody who can reach the port.

## Prepare a DNS server

A resolver is prepared one way or the other, never both. The panel does the same
work either way, and the difference is what has to exist on the resolver for it.

### Over SSH

Run the setup script as root on every resolver:

```
sudo ./deploy/setup-target.sh -k "ssh-ed25519 AAAA... jbound"
```

It creates the `dnsops` account, adds the public key the panel generated,
creates `/etc/unbound/local_records.conf` with mode `644` and installs seven exact
sudoers rules. The permissions of `/etc/unbound` are left alone: reading needs
no sudo, and everything else goes through the rules.

| Rule | What the panel does with it |
| --- | --- |
| `tee` | writes the new file to a fixed temporary path |
| `mv` | moves it over the records file in one step |
| `unbound-checkconf` | asks the resolver whether it will load the result |
| `unbound-control reload_keep_cache` | reloads without discarding the cache |
| `service unbound reload` | reloads when the control socket is not there |
| `service unbound restart` | restarts when neither reload works |
| `jbound-ensure-include` | makes the main configuration read the records file |

The paths of these commands differ between distributions and each rule has to
match the command the panel runs exactly, so the script resolves them with
`command -v` and prints the values to enter in the panel.

`-c` names the main configuration file, which defaults to
`/etc/unbound/unbound.conf`. `unbound-checkconf` reads it, so a resolver that
keeps its configuration elsewhere needs the real path here.

Re-run the script after changing the records path in the panel. The rules
are derived from that path.

**Re-run it on every server you prepared with an earlier version.** The last
five rules are newer than the first two. Without them **Test** reports the
configuration check as failed, and a record written to that server is rolled
back rather than applied.

### Through the agent

The agent is the alternative to the account and the seven rules. The panel asks
it to write, to check and to reload, and the agent runs the commands its own
configuration names. No command text crosses the network, so there is nothing
for a login shell to run and nothing for `sudo` to allow.

Build it, copy it onto the resolver and run the setup script as root:

```
make build-agent
scp dist/jbound-agent root@dns1:/usr/local/bin/jbound-agent
scp deploy/jbound-agent.service root@dns1:/etc/systemd/system/
sudo ./deploy/setup-agent.sh -t "<the token the panel showed>"
```

It writes `/etc/jbound-agent/token` with mode `600`, generates a self signed
certificate, writes the environment file naming the two files and the five
commands, and starts the service. It creates no account and installs no sudoers
rule.

The certificate is self signed on purpose. The panel pins the fingerprint an
operator approves, the same way it pins an SSH host key, so a public issuer
would add a step and prove nothing the pin does not already prove. The script
prints the fingerprint to approve and the port to enter.

`-f` and `-c` name the records file and the main configuration, and both go into
the environment file rather than into the panel. The panel asks the agent which
file holds the records and is never in a position to name one, because an agent
that took a path from a request would be a way to write any file on that host.

### What the panel does to a resolver

A change is one confirmation, one write, one check and one reload.

The confirmation comes first. It puts the clause header at the top of the
records file and appends the include line to the main configuration when it is
missing. Without it a resolver takes every write, accepts every configuration
check, reloads without complaint and answers none of the records, and nothing
anywhere reports a problem. An SSH server does it with
`jbound-ensure-include`, which takes no arguments because both paths were
written into it when the target was prepared; an agent server does it in the
process, from the two paths its environment file names. Either way the panel
never names a file a managed server then writes, and an include the panel had to
add reaches the audit trail.

The write goes to a temporary file in the same directory and is moved over the
records file, so the resolver never reads a half written file. The panel
compares the digest of the temporary file against what it sent before it moves
anything.

Then `unbound-checkconf` runs. If it refuses the result, the panel writes the
previous content back and reports the failure with what the checker said. The
same happens when the sudoers rule for it is missing, or when the agent has no
command configured for it, because a check that cannot run proves nothing.

The reload is a ladder of three rungs, and the panel stops at the first one that
leaves the resolver running:

1. `unbound-control reload_keep_cache`, which keeps the answers already cached.
2. `service unbound reload`, for a resolver with no control socket.
3. `service unbound restart`, which empties the cache. The panel then polls the
   service until it answers, because a restart is not instant.

The result and the audit row name the rung that worked, so a restart is never
mistaken for a cheap reload. If all three fail the change is left marked as
unapplied, because nothing reached the resolver.

Adding the first record of a domain also writes a `local-zone` line for the
parent, since Unbound answers nothing for a name whose zone is not local.
Deleting the last record of a zone leaves that line alone, because the zone may
still hold records the panel did not write.

## Add a server

1. Sign in as an administrator and open **Servers**.
2. Choose how the panel reaches it. The form shows the fields that transport
   uses and hides the rest. The choice is fixed once the server is added,
   because the secret behind it is a private key on one path and a token on the
   other, and a record that switched would point at a file of the wrong kind.
3. Add the server with its address and, over SSH, the account and the paths the
   setup script printed. An agent server takes a port and nothing else: it
   reports its own records file, and its commands stay on the resolver.
4. Open the key panel. Over SSH it shows the public key to copy onto the server,
   or to hand to `setup-target.sh -k`, and the private half stays under
   `<DATA_DIR>/keys` with mode `0600`. On an agent server it shows the token
   once, to hand to `setup-agent.sh -t`. Nothing shows it a second time, and it
   appears in no listing.
5. Press **Test**. The first connection reports the host key of the server, or
   the certificate fingerprint of its agent, and nothing is written until it is
   approved.
6. Approve it. It is stored with the server record, and a server that later
   offers a different one is refused rather than trusted again.

**Test** walks the whole path rather than only the connection: it signs in,
reads the file, writes the current content back over itself, runs the
configuration check and asks for the service status. A missing sudoers rule
therefore shows up while you are adding the server, not during a change.

A server can be added to a group. A group is what a record action targets when
it should reach more than one machine.

## Records

**Add record** takes as many rows as you need. Every row is validated first, and
one bad row refuses the whole batch rather than writing the good half. The rows
that pass reach each server as a single write followed by a single reload, and
leave one audit row per server saying how many records went.

A record is written to every server of the target at once, so the record list
folds the servers together: one line per record, with a badge saying how many of
the targeted servers hold it. A badge below the target count links to **Record
Diff**, where the servers are compared side by side and a missing or different
record can be repaired.

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
sudo systemctl kill -s USR1 jbound
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

### Bringing an older trail with you

If this panel replaces a single-server installation that kept its own audit
table, its history can be carried over. Export the table as CSV with a header
row, from any client:

```
SELECT id, user_id, username, action, details, ip_address, created_at
  FROM audit_logs ORDER BY id
```

Then, as the service account:

```
sudo -u jbound jbound import-audit /path/to/audit_logs.csv
```

The header names the columns, so their order does not matter and a column the
panel has no use for can stay in the file. `username`, `action` and `created_at`
are required. A row that cannot be read stops the whole import and names its
line, because a trail that stops halfway with nothing to say so is worse than
one that was never imported.

Two things about the rows it writes:

- They carry uid `-1`. The panel identifies a user by the uid the operating
  system gave them, and the number in the export belongs to a user table that no
  longer exists. Writing it into a column that means "uid" would put a wrong
  number in the trail and forward it to the SIEM as `suid`.
- They name no server. The installation they come from managed one resolver, and
  which of this panel's records that became is not something the import can know.

A timestamp without a zone is read as UTC, which is what the panel stores. Export
it as RFC 3339 with an offset if the old host did not run on UTC.

The import leaves one row about itself, so a trail that suddenly reaches further
back than the panel has existed says where that came from.

## Backup and restore

Take the backup with the panel binary, as the service account:

```
sudo -u jbound jbound backup /var/backups/jbound/$(date +%F)
```

The target directory must not exist yet. The command writes:

- `jbound.db`, a consistent snapshot of the server records, the groups, the
  host key pins and the audit trail.
- `keys/`, the SSH private keys and the agent tokens.

Do not copy `/var/lib/jbound` with `cp` or `tar` while the panel runs. The
database is open in WAL mode, so its state is spread across `jbound.db` and
`jbound.db-wal`, and a file level copy can catch the two at different moments.
The result is a database that is either short of committed transactions or
refused as corrupt, and you find out during the recovery. The command uses
`VACUUM INTO`, which reads under one transaction and writes a single self
contained file, then reopens that file and runs `PRAGMA integrity_check` before
it reports success.

The directory reaches every managed DNS server, so encrypt it before it leaves
the host.

### Restore

```
systemctl stop jbound
rm -rf /var/lib/jbound/jbound.db /var/lib/jbound/jbound.db-wal \
       /var/lib/jbound/jbound.db-shm /var/lib/jbound/keys
cp -a <backup>/jbound.db <backup>/keys /var/lib/jbound/
chown -R jbound:jbound /var/lib/jbound
chmod 700 /var/lib/jbound /var/lib/jbound/keys
chmod 600 /var/lib/jbound/jbound.db /var/lib/jbound/keys/*
systemctl start jbound
```

`/etc/jbound/jbound.env` is not part of the backup. It is installed
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
writes it next to the original as `jbound.db.before-<migration>.sql`. A
migration can be one way: `0002` drops a column the previous binary reads, so
without that copy there is no going back to the version that was running
before. Roll back by stopping the service, putting the copy in place of
`jbound.db` and installing the older binary.

The panel refuses to start if it cannot write the copy, because the copy is
what protects against the step that follows it. Each file is written once; a
second attempt at the same upgrade keeps the first copy, which is the state you
actually want back. Delete them yourself once the upgrade has proven itself.

### Running it on a timer

The installer sets up no schedule, because where the backups go and how long
they are kept is your policy. A pair of units is enough:

```
# /etc/systemd/system/jbound-backup.service
[Service]
Type=oneshot
User=jbound
ExecStart=/bin/sh -c 'exec /usr/local/bin/jbound backup /var/backups/jbound/$(date +%%F-%%H%%M)'

# /etc/systemd/system/jbound-backup.timer
[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

Removing the old directories is your policy too, and so is moving them off the
host.

## Development

The development stack runs the panel and six Unbound targets in containers.
Three are reached over SSH and three through the agent, so one record written to
the group proves both transports rather than proving each on its own. The panel
container carries its own rsyslog, so the SIEM page works there as well. No part
of it touches the host.

```
make dev-up        # build and start the stack
make dev-verify    # check the acceptance criteria
make dev-logs      # follow the panel logs
make dev-stop      # stop it and keep the data
make dev-start     # start it again
make dev-down      # remove it and drop every volume
```

`dev-stop` leaves the panel database, the approved host keys and the files
the targets hold where they are, so the servers you added are still there
tomorrow. `dev-down` removes them: the next start has an empty panel and the
targets are seeded again from `docker/seed`.

The panel is served on `http://127.0.0.1:8330`. `make dev-env` creates
`.env.dev` from the example on the first run and refuses to start until every
`CHANGEME` value is replaced. The test accounts are created inside the container
by `docker/testusers.sh`.

The first start also fills the panel: the six targets, their approved host keys
and agent fingerprints, and a group named `resolvers` over all of them, written
by `docker/devseed`. It goes through the same service an operator goes through,
and it leaves a panel that already holds a server alone, so anything you change
afterwards stays changed.

The group carries a seventh member, `dns-down`, pointed at the unrouted
`192.0.2.1`. Every fleet action therefore reaches six servers and times out on
one, which is the partial result an operator has to be able to read: HTTP 207, a
row per server, and a toast that does not claim success. Disable it on the
servers page when you want a clean run.

The agent targets carry no sshd, no `sudo`, no account and no sudoers file, so
the absence the transport is built on stays true rather than merely described.
One of them, `dns5`, starts with the include line taken out of its resolver
configuration: the failure is invisible everywhere else, and reproducing it on
every start is what keeps the repair proven. They answer DNS on `8360`, `8361`
and `8362`, next to `8331`, `8332` and `8333` for the SSH three.

### Checks

```
make check        # every check that needs no container
make test         # unit tests only
make dev-itest    # integration tests against the containers
make cppcheck     # the setuid helper, on top of -Wall -Wextra -Werror
make shellcheck   # the install and setup scripts
make coverage     # coverage without the integration tests
make dev-coverage # coverage of both tag sets, inside the container
```

`coverage` leaves the integration tests out and therefore understates the
packages that speak to a real server. `internal/transport` reads as two thirds
covered there and is near ninety with `dev-coverage`, because a fake SSH server
only proves the panel agrees with itself and what that code is for is what a
real sshd does with it. `dev-coverage` is the number to judge by.

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
cmd/jbound           the service
cmd/jbound-agent     the agent a managed resolver runs
authhelper           the setuid PAM helper, the only privileged component
internal/auth        sessions, CSRF, rate limiting, PAM
internal/server      server and group records, SSH keys and agent tokens
internal/transport   the connection pool, over SSH and through an agent
internal/agentapi    the protocol both ends of the agent speak
internal/dnsfile     the records format
internal/fleet       actions that touch more than one server
internal/audit       the audit trail and the CEF mirror
internal/settings    the settings registry and their storage
internal/i18n        the language catalogues
internal/web         handlers, templates and static assets
deploy               install script, systemd units, PAM file, target setup
deploy/licenses      the licences of the assets the binary serves
docker               the development stack
```

## Licence of the assets it serves

The panel embeds its stylesheets, scripts, icons and fonts, so it redistributes
them. `deploy/licenses/` carries the licence of each one and `install.sh` places
the directory under `/usr/local/share/doc/jbound/licenses`. Everything there is
MIT, 0BSD or the SIL Open Font License, and all three ask only that the notice
travels with the copies.
