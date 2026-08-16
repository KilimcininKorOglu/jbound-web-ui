#!/bin/bash
# Starts a development Unbound target: sshd plus Unbound.
#
# The container exits when either service dies. A half running target would
# make test failures point at the wrong layer.

set -euo pipefail

SSH_USER=${SSH_USER:-dnsops}
RECORDS_PATH=${RECORDS_PATH:-/etc/unbound/local_records.conf}
SEED_FILE=${SEED_FILE:-}
PUBLIC_KEY_FILE=${PUBLIC_KEY_FILE:-/keys/dev_ed25519.pub}
SHELL_POLLUTION=${SHELL_POLLUTION:-0}

# REMOTE_CONTROL=0 takes the control section out of the resolver configuration,
# so the first rung of the panel's reload has nothing to talk to and the fall
# through to the second rung is exercised on every run.
REMOTE_CONTROL=${REMOTE_CONTROL:-1}

log() { printf '[entrypoint-dns] %s\n' "$*"; }

# --- SSH host keys -----------------------------------------------------------
# Generated once per target, then kept on a volume so a recreated container
# offers the same identity. The panel pins what it saw on first connection and
# refuses a host that later offers something else, which is the whole point of
# the pin and is exactly what a rebuilt container used to trip.
#
# The keys are restored into /etc/ssh rather than mounted there, because a
# volume over /etc/ssh would freeze the sshd configuration this image writes at
# build time.
IDENTITY_DIR=${IDENTITY_DIR:-/var/lib/target-identity}
install -d -m 700 "$IDENTITY_DIR"

if ls "$IDENTITY_DIR"/ssh_host_*_key > /dev/null 2>&1; then
    cp -a "$IDENTITY_DIR"/ssh_host_* /etc/ssh/
    log "restored the host keys from $IDENTITY_DIR"
fi

# Fills in only what is missing, so a restored key is never replaced.
ssh-keygen -A
cp -a /etc/ssh/ssh_host_* "$IDENTITY_DIR"/

# --- Seed records ------------------------------------------------------------
# Only on first start. Later runs keep whatever the panel wrote.
#
# This runs before the target preparation, because that step creates the file
# when it is missing. Seeding afterwards would find a file that already exists
# and leave every target empty.
if [ -n "$SEED_FILE" ] && [ ! -s "$RECORDS_PATH" ]; then
    if [ -r "$SEED_FILE" ]; then
        cp "$SEED_FILE" "$RECORDS_PATH"
        chmod 644 "$RECORDS_PATH"
        log "seeded $RECORDS_PATH from $SEED_FILE"
    else
        log "seed file not readable: $SEED_FILE"
        exit 1
    fi
fi

# --- Target preparation ------------------------------------------------------
# The same script that ships to production runs here. That keeps the dev
# sudoers rules identical to the documented ones. It also puts the clause
# header in the seeded file and confirms the main configuration includes it.
if [ -r "$PUBLIC_KEY_FILE" ]; then
    /usr/local/sbin/setup-target.sh \
        -u "$SSH_USER" \
        -f "$RECORDS_PATH" \
        -k "$(cat "$PUBLIC_KEY_FILE")"
else
    log "public key not found at $PUBLIC_KEY_FILE"
    log "run 'make dev-keys' on the host before starting the stack"
    exit 1
fi

# --- Optional shell pollution fixture ----------------------------------------
# Verifies that the panel detects a login shell that writes to stdout. Off by
# default, because a permanently polluted target would fail every other test.
#
# The line must go to the TOP of .bashrc. The Debian default starts with an
# interactive-shell guard that returns immediately for ssh command execution,
# so anything appended after it never runs. Real world pollution has the same
# shape: it only reaches stdout when it sits before that guard.
SSH_HOME=$(getent passwd "$SSH_USER" | cut -d: -f6)
POLLUTION_LINE='echo "jbound shell pollution fixture"'
BASHRC="$SSH_HOME/.bashrc"

touch "$BASHRC"
grep -vFx "$POLLUTION_LINE" "$BASHRC" > "$BASHRC.clean" || true
mv "$BASHRC.clean" "$BASHRC"

if [ "$SHELL_POLLUTION" = "1" ]; then
    printf '%s\n' "$POLLUTION_LINE" | cat - "$BASHRC" > "$BASHRC.new"
    mv "$BASHRC.new" "$BASHRC"
    log "shell pollution fixture enabled for $SSH_USER"
fi
chown "$SSH_USER":"$SSH_USER" "$BASHRC"

# --- Remote control fixture --------------------------------------------------
if [ "$REMOTE_CONTROL" = "1" ]; then
    unbound-control-setup >/dev/null
    log "remote control enabled"
else
    sed -i '/^remote-control:/,$d' /etc/unbound/unbound.conf
    log "remote control disabled, the panel falls through to the reload command"
fi

# --- Unbound sanity check ----------------------------------------------------
unbound-checkconf /etc/unbound/unbound.conf

# --- Run both services -------------------------------------------------------
/usr/sbin/sshd -D -e &
SSHD_PID=$!
log "sshd started (pid $SSHD_PID)"

# Unbound runs under the init script rather than as a child of this shell,
# because that is what the panel's reload and restart commands drive. A
# restart replaces the process, and a container that waited on the first pid
# would take the restart as a dead service and stop.
service unbound start
log "unbound started through the init script"

terminate() {
    log "shutting down"
    service unbound stop || true
    kill "$SSHD_PID" 2>/dev/null || true
    wait || true
    exit 0
}
trap terminate TERM INT

# Supervise both, so a dead service is never silent. Unbound is asked the way
# the panel asks, which also proves the status command the panel is configured
# with answers on this image.
while true; do
    if ! kill -0 "$SSHD_PID" 2>/dev/null; then
        log "sshd exited, stopping the container"
        exit 1
    fi
    if ! service unbound status >/dev/null 2>&1; then
        log "unbound is not running, stopping the container"
        exit 1
    fi
    sleep 2
done
