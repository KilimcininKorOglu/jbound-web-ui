#!/bin/bash
# Starts the development panel container.
#
# Order matters: accounts, helper, rsyslog, then the panel itself. Every step
# fails loudly, because a container that comes up half configured makes later
# test failures point at the wrong layer.

set -euo pipefail

SRC_DIR=${SRC_DIR:-/src}
DATA_DIR=${DATA_DIR:-/var/lib/unbound-web}
AUTH_HELPER_PATH=${AUTH_HELPER_PATH:-/usr/local/libexec/unbound-web-authhelper}
RSYSLOG_CONF_PATH=${RSYSLOG_CONF_PATH:-/etc/rsyslog.d/60-unbound-dns-panel.conf}
SYSLOG_LOG_PATH=${SYSLOG_LOG_PATH:-/var/log/unbound-dns-panel.log}
KEY_DIR=${KEY_DIR:-/keys}

log() { printf '[entrypoint-app] %s\n' "$*"; }

# --- Test accounts -----------------------------------------------------------
/usr/local/bin/testusers.sh

# --- Setuid PAM helper -------------------------------------------------------
# Built from the bind mounted source so it tracks edits. Absent until Faz 3
# lands, and the container still starts without it so Faz 0 is verifiable on
# its own.
if [ -f "$SRC_DIR/authhelper/authhelper.c" ]; then
    log "building the PAM helper"
    make -C "$SRC_DIR/authhelper" install
    if [ ! -u "$AUTH_HELPER_PATH" ]; then
        log "error: $AUTH_HELPER_PATH is missing the setuid bit"
        exit 1
    fi
    log "helper installed: $(stat -c '%a %U:%G' "$AUTH_HELPER_PATH") $AUTH_HELPER_PATH"
else
    log "authhelper source not present yet, skipping the helper build"
fi

# --- Data directory ----------------------------------------------------------
mkdir -p "$DATA_DIR" "$DATA_DIR/keys"
chown -R unbound-web:unbound-web "$DATA_DIR"
chmod 0700 "$DATA_DIR" "$DATA_DIR/keys"

# The dev SSH key pair is generated on the host and mounted read only. Copy it
# where the panel expects per-server keys, owned by the service account.
if [ -r "$KEY_DIR/dev_ed25519" ]; then
    install -m 0600 -o unbound-web -g unbound-web \
        "$KEY_DIR/dev_ed25519" "$DATA_DIR/keys/dev_ed25519"
    log "dev SSH key installed for the panel"
else
    log "error: $KEY_DIR/dev_ed25519 not found"
    log "run 'make dev-keys' on the host before starting the stack"
    exit 1
fi

# --- rsyslog -----------------------------------------------------------------
# The panel rewrites this file, so it exists up front with group write for the
# service account. This mirrors the production install step.
touch "$RSYSLOG_CONF_PATH"
chown root:unbound-web "$RSYSLOG_CONF_PATH"
chmod 0664 "$RSYSLOG_CONF_PATH"

touch "$SYSLOG_LOG_PATH"
chmod 0644 "$SYSLOG_LOG_PATH"

/usr/sbin/rsyslogd -i /run/rsyslogd.pid
log "rsyslogd started"

# --- Known hosts -------------------------------------------------------------
# Host key pinning lives in the database. This file only keeps the ssh client
# quiet when a developer opens a shell inside the container.
install -d -m 0700 -o unbound-web -g unbound-web /home/unbound-web/.ssh

# --- Panel -------------------------------------------------------------------
cd "$SRC_DIR"

if [ ! -f "$SRC_DIR/go.mod" ]; then
    log "go.mod not present yet, the panel binary starts in Faz 1"
    log "container stays up so the rest of the stack can be verified"
    exec sleep infinity
fi

# runuser rather than setpriv. setpriv performs the exec itself, which lets it
# start a binary the target account has no execute permission on. That makes it
# a poor tool for reasoning about the 4750 helper, and the same confusion would
# apply to anything else it launches.
log "starting the panel through air"
exec runuser -u unbound-web -- air -c .air.toml
