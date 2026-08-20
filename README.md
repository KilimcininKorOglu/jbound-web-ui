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
- Blocks a name, so every resolver of the target answers NXDOMAIN or REFUSED for
  it and for everything under it.
- Compares the servers of a group and repairs a record that is missing or
  different on some of them, one row at a time or the whole comparison at once,
  or makes them all match one chosen server.
- Keeps the file each server carried before the last change, and puts it back
  from the servers page when a change turns out to be wrong.
- Checks the configuration of a resolver before a change goes live, and puts the
  previous file back when the resolver refuses it.
- Reloads the resolvers without losing their cache where it can, restarts them
  where it must, and proves each one is running afterwards.
- Asks each resolver what it answers for a name.
- Records every action with the user, the address and the result, and sends the
  trail to a SIEM collector in CEF, in order, holding it in the database while
  the collector is down.
- Writes a consistent backup of its own database and keys with one command.
- Signs users in against the local accounts of the panel host through PAM.
- Speaks English and Turkish, follows a light or dark theme or the one the
  operating system asks for.

## Requirements

Panel host:

- Linux with systemd and PAM.
- Go to build the panel, and a C compiler with the PAM development headers
  (`libpam0g-dev` on Debian) to build the helper. `go.mod` carries a `toolchain`
  line at a patched release, so a host with an older 1.26 fetches that one
  instead of building with an unpatched compiler.
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
- A port the panel can reach, `0.0.0.0:8443` by default.
- No login account, no `sudo` and no sudoers rule. The agent runs under a locked
  `jbound-agent` system account with no shell. The panel sends no command text
  and names no file, so there is nothing for a login shell to run.

## Install

On a server with nothing on it, `deploy/bootstrap.sh` does all of this in one
run: dependencies, source, build, install, environment file, firewall and
service. [INSTALL.md](INSTALL.md) covers it, along with the reverse proxy it
deliberately leaves to you. The rest of this section is the same install one
step at a time.

Build and install:

```
make build build-helper
sudo make install
```

`deploy/install.sh` does the work and can be re-run at any time. It creates the
`jbound` system account, the state directory, the panel binary and the setuid
helper, the PAM service file, the environment file, the third-party licences and
the systemd unit. It creates no sudoers rule: the setuid helper is the only
privileged part. It never overwrites the environment file, and it reads back the
two modes the whole design rests on:

| Path | Mode | Why |
| --- | --- | --- |
| `/usr/local/libexec/jbound-authhelper` | `4750 root:jbound` | setuid root so PAM can read the shadow database, group-only so no other account can use it as a password oracle |
| `/var/lib/jbound` | `0700 jbound` | the SSH private keys and the agent tokens live under it |

Then review `/etc/jbound/jbound.env` and start the service:

```
sudo systemctl enable --now jbound
```

`install.sh -n` leaves out the systemd unit. That is the way in for a host that
has no systemd, and nothing else in the panel depends on it.

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

On a resolver with nothing on it, `deploy/bootstrap-agent.sh` does all of the
below in one run: dependencies, source, build, binary, unit, configuration and
firewall. [INSTALL-AGENT.md](INSTALL-AGENT.md) covers it. The steps below are
the same install by hand.

Build it, copy it onto the resolver and run the setup script as root:

```
make build-agent
scp dist/jbound-agent root@dns1:/usr/local/bin/jbound-agent
scp deploy/jbound-agent.service root@dns1:/etc/systemd/system/
sudo ./deploy/setup-agent.sh -t "<the token the panel showed>"
```

It writes `/etc/jbound-agent/token` with mode `600`, generates a self signed
certificate, writes the environment file naming the two files and the five
commands, and starts the service. It installs no sudoers rule.

The one account it creates is `jbound-agent`, the system account the agent runs
under. It has no home directory, no shell and a locked password, so nobody signs
in as it: the agent is a service on that host, not a way onto it. Nothing on the
resolver accepts a login from the panel.

That account gets exactly what the work needs: read on the control credentials,
write in the two directories the records file and the main configuration live
in, and one polkit rule that lets it reload and restart `unbound.service` and
nothing else. A host with no polkit, or with no systemd, cannot grant the
restart to anything but root, and the agent runs as root there instead. The
script says which of the two it hit while it runs, and on a systemd host it
records the fallback in a `User=root` unit drop-in, so the state is on disk
rather than in somebody's memory. Install polkit and re-run the script to narrow
it; the script removes the drop-in again once it can.

The certificate is self signed on purpose. The panel pins the fingerprint an
operator approves, the same way it pins an SSH host key, so a public issuer
would add a step and prove nothing the pin does not already prove. The script
prints the fingerprint to approve and the port to enter.

`-f` and `-c` name the records file and the main configuration, and both go into
the environment file rather than into the panel. The panel asks the agent which
file holds the records and is never in a position to name one, because an agent
that took a path from a request would be a way to write any file on that host.

### What the panel does to a resolver

A change is one confirmation, one write and one check. The reload comes
afterwards, on its own.

The reload is its own action. Adding, editing or deleting a record writes the
file and leaves the server marked unapplied, and **Apply Rules** on the records
page is what walks the reload ladder and clears the marker. A record therefore
sits in the file until it is applied, which is what lets several changes reach a
fleet on one reload.

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

### Blocking a name

NXDOMAIN and REFUSED are in the same type list as A and MX, and they are chosen
the same way. Neither is a value a record can hold: in Unbound a name that
answers either is a zone with a behaviour rather than a name with data, so the
panel writes `local-zone: "<name>." always_nxdomain` or `always_refuse` instead
of a `local-data:` line. The value and the preference disappear from the form
with the choice, because a blocked name answers on its own.

A block covers that name **and every name under it**. `ads.example.net` blocked
this way takes `www.ads.example.net` with it.

That is also why the panel refuses the two ways of contradicting it. A record
under a blocked name would reach the file, pass the configuration check, survive
the reload and answer nothing, while the panel went on listing it; and a block
over a name that already has records would do the same to those. Either
submission is refused with both sides named, and the way out is to remove
whichever of the two is no longer wanted.

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

Every server belongs to one group, or to none. The group is chosen on the
server form, and it is what a record action targets when it should reach more
than one machine. A server in no group can still be written to on its own, and
it appears in no group listing and in no comparison.

A group names one of its own servers as its source, which is the reference a
comparison marks and a synchronisation copies from. The source has to be an
enabled member of that group, and it is cleared when that server leaves the
group, is disabled or is deleted.

## Records

**Add record** takes as many rows as you need. Every row is validated first, and
one bad row refuses the whole batch rather than writing the good half. The rows
that pass reach each server as a single write followed by a single reload, and
leave one audit row per server saying how many records went.

A name carries one address. Adding a record to a name the target already
answers for stops the write and asks: replace the value that is there, or
leave the record alone. The answer covers the whole target at once, so the
servers holding the old value have it replaced and the ones that never knew
the name have it written. A record every server already holds is said so
rather than sent out to be refused; one that only some of them hold is written
to the others, and the servers that were already right are reported as
skipped.

The rule covers A, AAAA and CNAME. It does not reach MX or TXT, because a name
carries several mail exchangers, which is what a preference is for, and several
pieces of text. It also does not reach a file edited by hand on the target: a
name given two addresses there goes on being listed, edited and deleted, and a
synchronisation copies it as it stands.

A record is written to every server of the target at once, so the record list
folds the servers together: one line per record, with a badge saying how many of
the targeted servers hold it. A badge below the target count links to **Record
Diff**, where the servers are compared side by side and a missing or different
record can be repaired.

The comparison closes in three ways. Each row carries a button that writes that
one record to the servers that lack it, replacing the value on a server that
answers for the name with something else. Above the table, **Repair every
difference** writes what each server lacks in a single pass: every server ends
up holding every record any of them held, and nothing is deleted, so a server
whose extra record was the one worth keeping keeps it. A name two servers
answer differently for is left alone there, because that button has no source
to say which of the two values is the right one, and the report says how many
records it left. Beside it,
**Synchronise** copies the source server over the others, which does delete: the
target ends up holding exactly what the source holds. The first needs no source
and is open to anyone who may write a record. The second copies from the source
of the group being compared and is admin only, because it removes records
nobody named.

A comparison is between the servers of one group. There is no view of every
server at once: two groups holding different records is the ordinary state of a
panel that manages more than one of them, so such a view would report drift
that is not drift, and no write may target it. A page opened with no target
lands on the first group by name. **Synchronise** is offered only once that
group names a source.

## The interface

A button is named after what pressing it does, and the colour says the same
thing on every page:

| Colour | What the button does |
| --- | --- |
| Green | Adds something, or saves a form |
| Amber | Changes something that is already there |
| Red | Takes something away |
| Blue | Probes something and reports back, changing nothing |
| Grey | Shows something, changing nothing |
| Violet | Applies the rules, the one action that reaches the running resolvers |
| No colour | Cancels or closes, and does nothing else |

The confirmation a destructive button raises answers in the same red, so the
dialog cannot look like a different action from the one that was pressed.

The panel speaks English and Turkish, and follows a light theme, a dark one, or
whichever the operating system asks for. Both choices live in a cookie on the
reader's own browser and nowhere else, so nothing about a reader is stored on
the panel. The **Settings** page decides what a browser gets before anybody has
chosen.

Every page is reachable by keyboard, starting with a skip link that jumps past
the navigation, and both palettes are measured rather than chosen by eye: text
reads at 4.5:1 or better and every control edge and focus ring at 3:1 or better,
which is what WCAG 2.2 AA asks for.

## Audit trail and SIEM

Every action is written to the database with the user, the uid, the address, the
target and the result. The **Audit Logs** page filters it.

The **SIEM Config** page names the collector, the protocol (UDP, TCP or TLS)
and the port, and carries a switch that turns the mirror on and off. With the
switch off the panel keeps writing its own trail and stops sending it, which is
what an operator wants while a collector is being repaired. The collector stays
where it is, and the entry that turned the mirror off is sent anyway, because a
receiver that was never told cannot tell a silenced panel from a quiet one.

The panel reaches the collector itself. There is no syslog daemon on the panel
host in between, no file for it to read and no privilege for any of it. Every
event is durable in the database before it is sent, and a cursor records how far
the collector has been caught up, so a collector that is down builds a backlog
rather than losing events: the page shows how many rows are waiting, and they go
out in order once it answers. A newly named collector is given what happens from
then on rather than the whole history.

What arrives is one line per event: the RFC 5424 envelope, facility `local6`,
tag `jbound`, and a CEF payload with vendor `JBound` and product
`JBoundDNSPanel`. That is what a collector filters on. The severity of the line
follows the action, so a failed login and a deleted record arrive as warnings
and an added one as a notice. The timestamp is the moment the action happened
rather than the moment it was sent, so a backlog that goes out after an outage
does not arrive stamped with the recovery.

A change across a group arrives as one line per server: `dhost` names the
resolver the action was aimed at and `dvchost` names the panel.

Plain syslog over a stream carries no acknowledgement. A collector that
disappears without closing the connection can lose what was in flight, which is
the same limit rsyslog has when it forwards with `@@`.

TLS uses the trust store of the panel host. Add a private CA there rather than
to the panel.

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
(session, cache, SSH, DNS and fleet operation timeouts), limits (login attempts,
fleet concurrency, page size), the SIEM switch and its collector, and the
interface defaults a browser gets before anybody picks a language or a theme.

The interface defaults are what a browser gets before anybody chooses; a reader
who picks a language or a theme keeps that choice in a cookie of their own, as
[The interface](#the-interface) describes.

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
writes it next to the original, named after the migration file that is about to
run: `jbound.db.before-0002_transfer_tools.sql`. A migration can be one way:
`0002` drops a column the previous binary reads, so without that copy there is
no going back to the version that was running before. Roll back by stopping the
service, putting the copy in place of `jbound.db` and installing the older
binary.

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
the group proves both transports rather than proving each on its own. A seventh
container stands in for the SIEM collector: point the SIEM page at `tcp`
`siem-sink` port `514`. No part of it touches the host.

```
make dev-up        # build and start the stack
make dev-verify    # check the acceptance criteria
make dev-logs      # follow the panel logs
make dev-shell     # open a shell in the panel container
make dev-stop      # stop it and keep the data
make dev-start     # start it again
make dev-down      # remove it and drop every volume
make dev-restart   # rebuild from scratch, dropping every volume as well
```

`dev-stop` leaves the panel database, the approved host keys and the files
the targets hold where they are, so the servers you added are still there
tomorrow. `dev-down` and `dev-restart` remove them: the next start has an empty
panel and the targets are seeded again from `docker/seed`.

The panel is served on `http://127.0.0.1:8330`. `make dev-env` creates
`.env.dev` from the example on the first run and refuses to start until every
`CHANGEME` value is replaced. The test accounts are created inside the container
by `docker/testusers.sh`.

A `docker compose` command typed by hand needs that file named, because the
agent targets refuse to start without the token in it:

```
docker compose -f docker-compose.dev.yml --env-file .env.dev ps
```

The first start also fills the panel: the six targets, their approved host keys
and agent fingerprints, and a group named `resolvers` that holds all of them and
names `dns1` as its source, written by `docker/devseed`. It goes through the
same service an operator goes through, and it leaves a panel that already holds
a server alone, so anything you change afterwards stays changed.

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

`air` rebuilds the panel when a file changes. On macOS the event does not always
cross the Docker mount, and the container then keeps serving the previous build,
which is a confusing way to lose an hour. Watch `make dev-logs` for a
`building...` line after editing a template or a stylesheet, and restart the
container when there is none:

```
docker compose -f docker-compose.dev.yml --env-file .env.dev restart app
```

### Checks

```
make check        # every check that needs no container
make test         # unit tests only
make lint         # go vet, staticcheck and modernize over both tag sets
make vuln         # the vulnerability scan
make dev-test     # unit tests inside the panel container
make dev-itest    # integration tests against the containers
make cppcheck     # the setuid helper, on top of -Wall -Wextra -Werror
make shellcheck   # the install and setup scripts
make coverage     # coverage without the integration tests
make dev-coverage # coverage of both tag sets, inside the container
```

Every test target passes `-count=1`, so a run never reports a cached result, and
every one but the coverage pair also passes `-race`. One test on its own is the
usual Go command:

```
go test ./internal/fleet/ -run TestRepairAllDeletesNothing -count=1
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
container instead, for a workstation that has no `cppcheck`. The Go analysers
are pinned and run through `go run`, so they need nothing installed beyond the
Go toolchain.

`.github/workflows/check.yml` runs the same checks on every push and pull
request, and the vulnerability scan again once a week, because an advisory
lands against source that did not change. It takes its Go version from
`go-version-file: go.mod`, so CI cannot drift from the toolchain line.

The Go analysers are pinned in the Makefile: `staticcheck@2025.1.1`,
`govulncheck@v1.1.4` and `modernize@v0.20.0`. Run them at those versions rather
than at `@latest`, or a local result and CI disagree about what is a finding.
`govulncheck` reports one advisory it cannot clear, `GO-2026-5932` against
`golang.org/x/crypto/openpgp`, which has no fixed version and which no part of
the panel calls; everything else is expected at zero.

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
internal/dnsquery    the query page, which runs dig on the panel host
internal/audit       the audit trail
internal/siem        the CEF rendering, the sender and the delivery queue
internal/settings    the settings registry and their storage
internal/store       the SQL statements, with no business rules of their own
internal/database    the connection, the pragmas and the migrations
internal/config      the environment file, read once at startup
internal/preflight   the startup checks that must pass before it serves
internal/i18n        the language catalogues
internal/web         handlers, templates and static assets
deploy               install script, systemd units, PAM file, target setup
deploy/licenses      the licences of the assets the binary serves
docker               the development stack
scripts              the verification scripts the make targets run
```

## Licence of the assets it serves

The panel embeds its stylesheets, scripts and icons, so it redistributes them.
`deploy/licenses/` carries the licence of each one and `install.sh` places the
directory under `/usr/local/share/doc/jbound/licenses`. Three assets are
somebody else's, all MIT or 0BSD: htmx, SweetAlert2 and Boxicons. Both licences
ask only that the notice travels with the copies.

Everything else on the page is the panel's own. There is no vendor template and
no framework: `panel.css` is the whole appearance and `app.js` is the whole
behaviour that htmx does not cover. The text is set in the fonts the reader's
system already has, so no font is shipped and no page reaches a font host.
