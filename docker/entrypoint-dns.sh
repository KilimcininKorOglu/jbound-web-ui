#!/bin/bash
# Starts a development Unbound target: sshd plus Unbound.
#
# The container exits when either service dies. A half running target would
# make test failures point at the wrong layer.

set -euo pipefail

SSH_USER=${SSH_USER:-dnsops}
HOST_ENTRIES_PATH=${HOST_ENTRIES_PATH:-/etc/unbound/host_entries.conf}
SEED_FILE=${SEED_FILE:-}
PUBLIC_KEY_FILE=${PUBLIC_KEY_FILE:-/keys/dev_ed25519.pub}
SHELL_POLLUTION=${SHELL_POLLUTION:-0}

log() { printf '[entrypoint-dns] %s\n' "$*"; }

# --- SSH host keys -----------------------------------------------------------
# Generated on first start so every container gets a distinct host key. The
# panel pins whatever it sees on first connection.
ssh-keygen -A

# --- Target preparation ------------------------------------------------------
# The same script that ships to production runs here. That keeps the dev
# sudoers rules identical to the documented ones.
if [ -r "$PUBLIC_KEY_FILE" ]; then
    /usr/local/sbin/setup-target.sh \
        -u "$SSH_USER" \
        -f "$HOST_ENTRIES_PATH" \
        -k "$(cat "$PUBLIC_KEY_FILE")"
else
    log "public key not found at $PUBLIC_KEY_FILE"
    log "run 'make dev-keys' on the host before starting the stack"
    exit 1
fi

# --- Seed records ------------------------------------------------------------
# Only on first start. Later runs keep whatever the panel wrote.
if [ -n "$SEED_FILE" ] && [ ! -s "$HOST_ENTRIES_PATH" ]; then
    if [ -r "$SEED_FILE" ]; then
        cp "$SEED_FILE" "$HOST_ENTRIES_PATH"
        chmod 644 "$HOST_ENTRIES_PATH"
        log "seeded $HOST_ENTRIES_PATH from $SEED_FILE"
    else
        log "seed file not readable: $SEED_FILE"
        exit 1
    fi
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

# --- Unbound sanity check ----------------------------------------------------
unbound-checkconf /etc/unbound/unbound.conf

# --- Run both services -------------------------------------------------------
/usr/sbin/sshd -D -e &
SSHD_PID=$!
log "sshd started (pid $SSHD_PID)"

/usr/sbin/unbound -d -c /etc/unbound/unbound.conf &
UNBOUND_PID=$!
log "unbound started (pid $UNBOUND_PID)"

terminate() {
    log "shutting down"
    kill "$SSHD_PID" "$UNBOUND_PID" 2>/dev/null || true
    wait || true
    exit 0
}
trap terminate TERM INT

# Exit as soon as either child stops, so a dead service is never silent.
wait -n "$SSHD_PID" "$UNBOUND_PID"
STATUS=$?
log "a service exited with status $STATUS, stopping the container"
kill "$SSHD_PID" "$UNBOUND_PID" 2>/dev/null || true
exit "$STATUS"
