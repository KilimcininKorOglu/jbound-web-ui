#!/bin/bash
# Starts the development panel container.
#
# Order matters: accounts, helper, rsyslog, then the panel itself. Every step
# fails loudly, because a container that comes up half configured makes later
# test failures point at the wrong layer.

set -euo pipefail

SRC_DIR=${SRC_DIR:-/src}
DATA_DIR=${DATA_DIR:-/var/lib/jbound}
AUTH_HELPER_PATH=${AUTH_HELPER_PATH:-/usr/local/libexec/jbound-authhelper}
RSYSLOG_CONF_PATH=${RSYSLOG_CONF_PATH:-/etc/rsyslog.d/60-jbound.conf}
SYSLOG_LOG_PATH=${SYSLOG_LOG_PATH:-/var/log/jbound.log}
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
chown -R jbound:jbound "$DATA_DIR"
chmod 0700 "$DATA_DIR" "$DATA_DIR/keys"

# The dev SSH key pair is generated on the host and mounted read only. Copy it
# where the panel expects per-server keys, owned by the service account.
if [ -r "$KEY_DIR/dev_ed25519" ]; then
    install -m 0600 -o jbound -g jbound \
        "$KEY_DIR/dev_ed25519" "$DATA_DIR/keys/dev_ed25519"
    log "dev SSH key installed for the panel"
else
    log "error: $KEY_DIR/dev_ed25519 not found"
    log "run 'make dev-keys' on the host before starting the stack"
    exit 1
fi

# --- rsyslog -----------------------------------------------------------------
# The panel never writes this file. jbound-siem-apply does, as root, from the
# rules the panel wrote into its own data directory. The mode mirrors the
# production install step, and a group writable one here would hide the whole
# point of that split.
touch "$RSYSLOG_CONF_PATH"
chown root:root "$RSYSLOG_CONF_PATH"
chmod 0644 "$RSYSLOG_CONF_PATH"

# Removed rather than created, so rsyslog creates it through the action
# jbound-siem-apply writes, with the group that action names.
rm -f "$SYSLOG_LOG_PATH"

# The same first run the production install does, so the panel has a log file
# before anybody opens the SIEM page.
/usr/local/sbin/jbound-siem-apply
log "rendered $RSYSLOG_CONF_PATH"

/usr/sbin/rsyslogd -i /run/rsyslogd.pid
log "rsyslogd started"

# --- Known hosts -------------------------------------------------------------
# Host key pinning lives in the database. This file only keeps the ssh client
# quiet when a developer opens a shell inside the container.
install -d -m 0700 -o jbound -g jbound /home/jbound/.ssh

# --- Panel -------------------------------------------------------------------
cd "$SRC_DIR"

if [ ! -f "$SRC_DIR/go.mod" ]; then
    log "go.mod not present yet, the panel binary starts in Faz 1"
    log "container stays up so the rest of the stack can be verified"
    exec sleep infinity
fi

# The fixture passwords were needed to create the test accounts and have no
# further use. Dropping them here keeps them out of the environment of the long
# running panel process, where any local account could read them from /proc.
unset DEV_PASSWORD_ROOT DEV_PASSWORD_DNSADMIN DEV_PASSWORD_DNSUSER \
      DEV_PASSWORD_SVCACCT DEV_PASSWORD_LOWUID DEV_PASSWORD_LOCKEDUSER \
      DEV_PASSWORD_EXPIREDUSER

# --- Seed the panel ----------------------------------------------------------
# The three targets, their approved host keys and one group over them, so a
# developer opens a working panel instead of typing the same setup after every
# start. It runs as the service account, because the database and the keys
# belong to it, and it leaves a panel that already holds servers alone.
if [ -d "$SRC_DIR/docker/devseed" ]; then
    log "seeding the development panel"
    runuser -u jbound -- go run ./docker/devseed
fi

# runuser rather than setpriv. setpriv performs the exec itself, which lets it
# start a binary the target account has no execute permission on. That makes it
# a poor tool for reasoning about the 4750 helper, and the same confusion would
# apply to anything else it launches.
log "starting the panel through air"
exec runuser -u jbound -- air -c .air.toml
