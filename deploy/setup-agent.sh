#!/bin/sh
# Prepares an Unbound server so the JBound panel can manage it through an agent.
#
# Run this as root on every managed DNS server that will speak the agent
# protocol. It is the alternative to setup-target.sh, not an addition to it: a
# host runs one or the other.
#
# Usage:
#   setup-agent.sh -t TOKEN [-f RECORDS_PATH] [-c MAIN_CONFIG] [-a LISTEN_ADDR]
#
#   -t  Token the panel showed when the server was added. Required.
#   -f  Path of the Unbound records file.     Default: /etc/unbound/local_records.conf
#   -c  Path of the main Unbound configuration. Default: /etc/unbound/unbound.conf
#   -a  Address the agent listens on.         Default: 0.0.0.0:8443
#
# It creates no account and installs no sudoers rule. That is the whole point:
# the panel sends no command text and names no file, so there is nothing here
# for a login shell to run and nothing for sudo to allow.
#
# The certificate it generates is self signed. The panel pins the fingerprint
# the operator approves, so a public issuer would add a step and prove nothing
# the pin does not already prove.

set -eu

RECORDS_PATH=/etc/unbound/local_records.conf
MAIN_CONFIG_PATH=/etc/unbound/unbound.conf
LISTEN_ADDR=0.0.0.0:8443
TOKEN=
CONF_DIR=/etc/jbound-agent
BINARY=/usr/local/bin/jbound-agent

while getopts 't:f:c:a:h' opt; do
    case "$opt" in
        t) TOKEN=$OPTARG ;;
        f) RECORDS_PATH=$OPTARG ;;
        c) MAIN_CONFIG_PATH=$OPTARG ;;
        a) LISTEN_ADDR=$OPTARG ;;
        h) sed -n '2,22p' "$0"; exit 0 ;;
        *) echo "run with -h for usage" >&2; exit 2 ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "error: run this script as root" >&2
    exit 1
fi

if [ -z "$TOKEN" ]; then
    echo "error: -t is required, and holds the token the panel showed once" >&2
    exit 1
fi

for path in "$RECORDS_PATH" "$MAIN_CONFIG_PATH"; do
    case "$path" in
        /*) ;;
        *) echo "error: path must be absolute: $path" >&2; exit 1 ;;
    esac
done

if [ ! -x "$BINARY" ]; then
    echo "error: $BINARY is not there, copy the built agent first" >&2
    exit 1
fi

# --- Configuration directory -------------------------------------------------
# 0700, because it holds the token and the private key of the certificate.
install -d -m 700 -o root -g root "$CONF_DIR"

# --- Token -------------------------------------------------------------------
# The panel shows it once, when the server is added. It is written here and
# never anywhere else on this host.
umask 077
printf '%s\n' "$TOKEN" > "$CONF_DIR/token"
chmod 600 "$CONF_DIR/token"
echo "wrote $CONF_DIR/token"

# --- Certificate -------------------------------------------------------------
# Regenerated only when it is missing. Replacing it would change the
# fingerprint the panel has pinned, and every connection would stop until an
# operator approved the new one.
if [ ! -e "$CONF_DIR/agent.crt" ]; then
    HOSTNAME_FQDN=$(hostname -f 2>/dev/null || hostname)

    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -keyout "$CONF_DIR/agent.key" \
        -out "$CONF_DIR/agent.crt" \
        -subj "/CN=$HOSTNAME_FQDN" \
        -addext "subjectAltName=DNS:$HOSTNAME_FQDN" >/dev/null 2>&1

    chmod 600 "$CONF_DIR/agent.key"
    chmod 644 "$CONF_DIR/agent.crt"
    echo "generated $CONF_DIR/agent.crt for $HOSTNAME_FQDN"
else
    echo "keeping the existing $CONF_DIR/agent.crt"
fi

FINGERPRINT=$(openssl x509 -in "$CONF_DIR/agent.crt" -outform der |
    openssl dgst -sha256 -binary | openssl base64 | tr -d '=')

# --- Environment file --------------------------------------------------------
cat > "$CONF_DIR/jbound-agent.env" <<EOF
# Managed by jbound setup-agent.sh. Re-run the script after changing a path.
LISTEN_ADDR=$LISTEN_ADDR
TLS_CERT=$CONF_DIR/agent.crt
TLS_KEY=$CONF_DIR/agent.key
TOKEN_FILE=$CONF_DIR/token

# The two files the agent owns. The panel asks which one holds the records and
# never says; an agent that took the path from a request would be a way to
# write any file on this host.
RECORDS_PATH=$RECORDS_PATH
MAIN_CONFIG_PATH=$MAIN_CONFIG_PATH

# Each step may be left empty, which is a resolver that does not have it. The
# panel skips that rung rather than reporting a failure.
CHECK_CONF_CMD=/usr/sbin/unbound-checkconf $MAIN_CONFIG_PATH
RELOAD_CMD=/usr/sbin/unbound-control reload_keep_cache
RELOAD_FALLBACK_CMD=/usr/sbin/service unbound reload
RESTART_CMD=/usr/sbin/service unbound restart
STATUS_CMD=systemctl is-active unbound
EOF
chmod 600 "$CONF_DIR/jbound-agent.env"
echo "wrote $CONF_DIR/jbound-agent.env"

# --- Service -----------------------------------------------------------------
if [ -e /etc/systemd/system/jbound-agent.service ]; then
    systemctl daemon-reload
    systemctl enable --now jbound-agent
    systemctl restart jbound-agent
    echo "started jbound-agent"
else
    echo "note: install deploy/jbound-agent.service to /etc/systemd/system first"
fi

# --- Report ------------------------------------------------------------------
cat <<EOF

Enter these values in the panel server record:

  transport           agent
  host                $(hostname -f 2>/dev/null || hostname)
  agent_port          ${LISTEN_ADDR##*:}

Approve this fingerprint when the panel asks:

  SHA256:$FINGERPRINT

The agent reports the records file itself, so there is nothing to enter for it.

EOF
