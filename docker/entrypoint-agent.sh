#!/bin/bash
# Starts a development agent target: Unbound plus the jbound agent.
#
# The container exits when either dies. A half running target would make test
# failures point at the wrong layer.

set -euo pipefail

RECORDS_PATH=${RECORDS_PATH:-/etc/unbound/local_records.conf}
MAIN_CONFIG_PATH=${MAIN_CONFIG_PATH:-/etc/unbound/unbound.conf}
LISTEN_ADDR=${LISTEN_ADDR:-0.0.0.0:8443}
SEED_FILE=${SEED_FILE:-}
CONF_DIR=/etc/jbound-agent

# AGENT_TOKEN is what the devseed writes into the panel database, so the two
# sides agree without anybody copying a value by hand.
AGENT_TOKEN=${AGENT_TOKEN:-}

# MAIN_INCLUDE=0 takes the include line out of the resolver configuration, so
# the agent has to put it back. That failure is invisible everywhere else, and
# a target that reproduces it on every run is the only way the repair stays
# proven rather than merely written.
MAIN_INCLUDE=${MAIN_INCLUDE:-1}

log() { printf '[entrypoint-agent] %s\n' "$*"; }

if [ -z "$AGENT_TOKEN" ]; then
    log "AGENT_TOKEN is not set, the panel would never be able to connect"
    exit 1
fi

# --- Seed records ------------------------------------------------------------
# Only on first start. Later runs keep whatever the panel wrote.
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

# --- Missing include fixture -------------------------------------------------
if [ "$MAIN_INCLUDE" = "0" ]; then
    grep -v "^[[:space:]]*include:.*$(basename "$RECORDS_PATH")" \
        "$MAIN_CONFIG_PATH" > "$MAIN_CONFIG_PATH.stripped"
    mv "$MAIN_CONFIG_PATH.stripped" "$MAIN_CONFIG_PATH"
    log "removed the include line, the agent has to put it back"
fi

# --- Agent configuration -----------------------------------------------------
# The same layout setup-agent.sh writes on a real host, so the dev stack
# exercises the shipped file rather than a shape of its own.
install -d -m 700 -o root -g root "$CONF_DIR"

umask 077
printf '%s\n' "$AGENT_TOKEN" > "$CONF_DIR/token"
chmod 600 "$CONF_DIR/token"

if [ ! -e "$CONF_DIR/agent.crt" ]; then
    # Generated per container, so each target has its own identity and the
    # panel pins three different fingerprints, the way it would in production.
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -keyout "$CONF_DIR/agent.key" \
        -out "$CONF_DIR/agent.crt" \
        -subj "/CN=$(hostname)" \
        -addext "subjectAltName=DNS:$(hostname),IP:127.0.0.1" >/dev/null 2>&1

    chmod 600 "$CONF_DIR/agent.key"
    chmod 644 "$CONF_DIR/agent.crt"
    log "generated $CONF_DIR/agent.crt for $(hostname)"
fi

# The devseed reads this to pin the certificate without an operator approving
# one by hand on every stack start.
openssl x509 -in "$CONF_DIR/agent.crt" -outform der |
    openssl dgst -sha256 -binary | openssl base64 | tr -d '=\n' \
    > "$CONF_DIR/fingerprint"
log "certificate fingerprint SHA256:$(cat "$CONF_DIR/fingerprint")"

# --- Unbound -----------------------------------------------------------------
# unbound-control is what the first rung of the reload ladder speaks.
unbound-control-setup >/dev/null

# The check runs before the agent starts, so a broken image fails here rather
# than on the first change the panel makes.
unbound-checkconf "$MAIN_CONFIG_PATH"

service unbound start
log "unbound started through the init script"

# --- Agent -------------------------------------------------------------------
# Exported rather than set on the command line, because the agent reads its
# whole configuration from the environment the way a systemd unit gives it one.
export LISTEN_ADDR
export TLS_CERT="$CONF_DIR/agent.crt"
export TLS_KEY="$CONF_DIR/agent.key"
export TOKEN_FILE="$CONF_DIR/token"
export RECORDS_PATH
export MAIN_CONFIG_PATH
export CHECK_CONF_CMD="/usr/sbin/unbound-checkconf $MAIN_CONFIG_PATH"
export RELOAD_CMD="/usr/sbin/unbound-control reload_keep_cache"
export RELOAD_FALLBACK_CMD="/usr/sbin/service unbound reload"
export RESTART_CMD="/usr/sbin/service unbound restart"
export STATUS_CMD="/usr/sbin/service unbound status"

/usr/local/bin/jbound-agent &
AGENT_PID=$!
log "agent started (pid $AGENT_PID)"

terminate() {
    log "shutting down"
    service unbound stop || true
    kill "$AGENT_PID" 2>/dev/null || true
    wait || true
    exit 0
}
trap terminate TERM INT

# Supervise both, so a dead service is never silent.
while true; do
    if ! kill -0 "$AGENT_PID" 2>/dev/null; then
        log "the agent exited, stopping the container"
        exit 1
    fi
    if ! service unbound status >/dev/null 2>&1; then
        log "unbound is not running, stopping the container"
        exit 1
    fi
    sleep 2
done
