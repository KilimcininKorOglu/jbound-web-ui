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
#   -R  Run the agent as root, the way it used to. Without this the script
#       creates a system account for it and grants that account exactly what
#       the five steps need.
#
# It installs no sudoers rule and creates no login. That is the whole point:
# the panel sends no command text and names no file, so there is nothing here
# for a login shell to run and nothing for sudo to allow. The account it does
# create has no shell and holds only what the five steps need.
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

# The account the agent runs as. Root is what it used to be and what -R keeps.
SERVICE_USER=jbound-agent
RUN_AS_ROOT=no
POLKIT_RULE=/etc/polkit-1/rules.d/50-jbound-agent.rules
UNIT_DROPIN=/etc/systemd/system/jbound-agent.service.d

while getopts 't:f:c:a:Rh' opt; do
    case "$opt" in
        t) TOKEN=$OPTARG ;;
        f) RECORDS_PATH=$OPTARG ;;
        c) MAIN_CONFIG_PATH=$OPTARG ;;
        a) LISTEN_ADDR=$OPTARG ;;
        R) RUN_AS_ROOT=yes ;;
        h) sed -n '2,25p' "$0"; exit 0 ;;
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

# --- The account the agent runs as -------------------------------------------
# Root writes the records file, repairs the main configuration and reloads the
# resolver without asking anybody. A dedicated account does all three too, and
# what it takes is exact: read on the control credentials, write in the
# directories those two files live in, and one polkit rule for the restart.
#
# The fallback is announced rather than silent. A host that cannot grant the
# restart to anybody but root gets an agent that runs as root, because an agent
# that cannot restart a resolver it just reconfigured is worse than one that
# runs with more than it needs.

HAVE_SYSTEMD=no
if command -v systemctl > /dev/null 2>&1 && [ -d /run/systemd/system ]; then
    HAVE_SYSTEMD=yes
fi

if [ "$RUN_AS_ROOT" = no ] && [ "$HAVE_SYSTEMD" = no ]; then
    echo "note: no systemd here, so the agent runs as root"
    RUN_AS_ROOT=yes
fi
if [ "$RUN_AS_ROOT" = no ] && [ ! -d /etc/polkit-1/rules.d ]; then
    echo "note: this host has no polkit, so the agent runs as root"
    echo "      install polkit and re-run this script to narrow it"
    RUN_AS_ROOT=yes
fi

AGENT_USER=root
if [ "$RUN_AS_ROOT" = no ]; then
    AGENT_USER=$SERVICE_USER

    if ! getent group "$SERVICE_USER" > /dev/null 2>&1; then
        groupadd --system "$SERVICE_USER"
    fi
    if ! id "$SERVICE_USER" > /dev/null 2>&1; then
        # No home directory, no shell and no password. The account exists to
        # own a process and three files, so there is nowhere to put an
        # authorized_keys, nothing to run if a key were accepted anyway, and
        # nothing to guess. An account that can be logged into is a way back
        # in after the process it belongs to has been closed.
        useradd --system --gid "$SERVICE_USER" \
            --home-dir /nonexistent --no-create-home \
            --shell /usr/sbin/nologin --comment "JBound agent" "$SERVICE_USER"
    fi

    # Locked rather than merely empty, on every run. An empty password field is
    # a password that some PAM stacks accept.
    passwd --lock "$SERVICE_USER" > /dev/null 2>&1 ||
        usermod --lock "$SERVICE_USER" > /dev/null 2>&1 || true
    usermod --shell /usr/sbin/nologin --home /nonexistent "$SERVICE_USER" > /dev/null 2>&1 || true

    # Its own directory. It holds the token and the private key of the
    # certificate, so nobody else reads it either.
    chown -R "$SERVICE_USER:$SERVICE_USER" "$CONF_DIR"
    chmod 700 "$CONF_DIR"

    # unbound-control reads all three of these and refuses without any one.
    for control_file in unbound_control.key unbound_control.pem unbound_server.pem; do
        [ -f "/etc/unbound/$control_file" ] || continue
        chgrp "$SERVICE_USER" "/etc/unbound/$control_file"
        chmod 640 "/etc/unbound/$control_file"
    done

    # Both files are replaced by a rename, so the write is on the directory
    # they sit in rather than on the files themselves.
    for config_dir in "$(dirname "$RECORDS_PATH")" "$(dirname "$MAIN_CONFIG_PATH")"; do
        chgrp "$SERVICE_USER" "$config_dir"
        chmod 775 "$config_dir"
    done
    for config_file in "$RECORDS_PATH" "$MAIN_CONFIG_PATH"; do
        [ -f "$config_file" ] || continue
        chgrp "$SERVICE_USER" "$config_file"
        chmod 664 "$config_file"
    done

    # unbound-checkconf reads the trust anchor the configuration names, and
    # fails on a file it cannot open even when nothing is wrong.
    ANCHOR=$(grep -rh 'auto-trust-anchor-file:' /etc/unbound 2>/dev/null |
        head -n1 | sed 's/.*auto-trust-anchor-file:[[:space:]]*//; s/"//g' || true)
    [ -n "$ANCHOR" ] || ANCHOR=/var/lib/unbound/root.key
    if [ -f "$ANCHOR" ]; then
        chgrp "$SERVICE_USER" "$(dirname "$ANCHOR")" "$ANCHOR"
        chmod 750 "$(dirname "$ANCHOR")"
        chmod 640 "$ANCHOR"
    fi

    # One unit, two verbs, one account. Everything else still asks for a
    # password, including stopping the resolver and reloading the manager.
    install -d -m 755 /etc/polkit-1/rules.d
    cat > "$POLKIT_RULE" <<POLKIT
// Managed by jbound setup-agent.sh.
polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.systemd1.manage-units" &&
        action.lookup("unit") == "unbound.service" &&
        (action.lookup("verb") == "restart" || action.lookup("verb") == "reload") &&
        subject.user == "$SERVICE_USER") {
        return polkit.Result.YES;
    }
});
POLKIT
    chmod 644 "$POLKIT_RULE"
    echo "wrote $POLKIT_RULE"
fi

# The unit ships with the narrow account. A host that fell back to root records
# that here, so the state is on disk rather than only in this output.
if [ "$HAVE_SYSTEMD" = yes ]; then
    if [ "$AGENT_USER" = root ]; then
        install -d -m 755 "$UNIT_DROPIN"
        printf '# Written by jbound setup-agent.sh.\n[Service]\nUser=root\nGroup=root\n' \
            > "$UNIT_DROPIN/user.conf"
        chmod 644 "$UNIT_DROPIN/user.conf"
    else
        rm -f "$UNIT_DROPIN/user.conf"
        rmdir "$UNIT_DROPIN" 2> /dev/null || true
    fi
fi

# --- The commands this host has ----------------------------------------------
# The paths differ between distributions, and a rung that names a command the
# host does not have is a rung that fails at the moment it is needed. The RHEL
# family carries no /usr/sbin/service at all, so both fallbacks there are
# systemctl.
resolve() {
    command -v "$1" 2>/dev/null || true
}

CHECKCONF=$(resolve unbound-checkconf)
CONTROL=$(resolve unbound-control)
SERVICE=$(resolve service)
SYSTEMCTL=$(resolve systemctl)

CHECK_CONF_CMD=
if [ -n "$CHECKCONF" ]; then
    CHECK_CONF_CMD="$CHECKCONF $MAIN_CONFIG_PATH"
fi

RELOAD_CMD=
if [ -n "$CONTROL" ]; then
    RELOAD_CMD="$CONTROL reload_keep_cache"
fi

RELOAD_FALLBACK_CMD=
RESTART_CMD=
if [ "$AGENT_USER" != root ] && [ -n "$SYSTEMCTL" ]; then
    # systemctl rather than service, because the polkit rule is written
    # against the unit and the verb, and going through another front end is a
    # layer that can only get in the way.
    RELOAD_FALLBACK_CMD="$SYSTEMCTL reload unbound"
    RESTART_CMD="$SYSTEMCTL restart unbound"
elif [ -n "$SERVICE" ]; then
    RELOAD_FALLBACK_CMD="$SERVICE unbound reload"
    RESTART_CMD="$SERVICE unbound restart"
elif [ -n "$SYSTEMCTL" ]; then
    RELOAD_FALLBACK_CMD="$SYSTEMCTL reload unbound"
    RESTART_CMD="$SYSTEMCTL restart unbound"
fi

# systemctl answers the status with one word the panel can read, so it is
# preferred even on a host that also carries service.
STATUS_CMD=
if [ -n "$SYSTEMCTL" ]; then
    STATUS_CMD="$SYSTEMCTL is-active unbound"
elif [ -n "$SERVICE" ]; then
    STATUS_CMD="$SERVICE unbound status"
fi

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
# panel skips that rung rather than reporting a failure. These were resolved on
# this host, so re-run the script after installing a command that was missing.
CHECK_CONF_CMD=$CHECK_CONF_CMD
RELOAD_CMD=$RELOAD_CMD
RELOAD_FALLBACK_CMD=$RELOAD_FALLBACK_CMD
RESTART_CMD=$RESTART_CMD
STATUS_CMD=$STATUS_CMD
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

The agent runs as $AGENT_USER.

Enter these values in the panel server record:

  transport           agent
  host                $(hostname -f 2>/dev/null || hostname)
  agent_port          ${LISTEN_ADDR##*:}

Approve this fingerprint when the panel asks:

  SHA256:$FINGERPRINT

The agent reports the records file itself, so there is nothing to enter for it.

EOF
