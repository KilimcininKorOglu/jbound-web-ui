#!/bin/sh
# Prepares an Unbound server so the JBound panel can manage it over SSH.
#
# Run this as root on every managed DNS server.
#
# Usage:
#   setup-target.sh [-u USER] [-f RECORDS_PATH] [-c MAIN_CONFIG] [-k KEY]
#
#   -u  SSH account the panel connects as.       Default: dnsops
#   -f  Path of the Unbound records file.     Default: /etc/unbound/local_records.conf
#   -c  Path of the main Unbound configuration.  Default: /etc/unbound/unbound.conf
#   -k  Public key the panel generated. When omitted the key step is skipped.
#
# The script does NOT change the permissions of the Unbound configuration
# directory. Writing happens through six exact sudoers rules instead.
#
# Re-run this script whenever the records path changes in the panel,
# because the sudoers rules are derived from that path.

set -eu

SSH_USER=dnsops
RECORDS_PATH=/etc/unbound/local_records.conf
MAIN_CONFIG_PATH=/etc/unbound/unbound.conf
AUTHORIZED_KEY=
SUDOERS_FILE=/etc/sudoers.d/jbound-target

while getopts 'u:f:c:k:h' opt; do
    case "$opt" in
        u) SSH_USER=$OPTARG ;;
        f) RECORDS_PATH=$OPTARG ;;
        c) MAIN_CONFIG_PATH=$OPTARG ;;
        k) AUTHORIZED_KEY=$OPTARG ;;
        h) sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "run with -h for usage" >&2; exit 2 ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "error: run this script as root" >&2
    exit 1
fi

case "$RECORDS_PATH" in
    /*) ;;
    *) echo "error: records path must be absolute: $RECORDS_PATH" >&2; exit 1 ;;
esac

case "$MAIN_CONFIG_PATH" in
    /*) ;;
    *) echo "error: main config path must be absolute: $MAIN_CONFIG_PATH" >&2; exit 1 ;;
esac

RECORDS_DIR=$(dirname "$RECORDS_PATH")
RECORDS_FILE=$(basename "$RECORDS_PATH")
TMP_PATH="$RECORDS_DIR/.$RECORDS_FILE.tmp"

# --- Resolve absolute command paths -----------------------------------------
# Distributions disagree on these locations, and sudoers rules must match the
# exact path the panel invokes.
resolve() {
    _found=$(command -v "$1" 2>/dev/null || true)
    if [ -z "$_found" ]; then
        echo "error: required command not found: $1" >&2
        exit 1
    fi
    printf '%s\n' "$_found"
}

TEE_PATH=$(resolve tee)
MV_PATH=$(resolve mv)
BASE64_PATH=$(resolve base64)
SHA256_PATH=$(resolve sha256sum)
SERVICE_PATH=$(resolve service)
CHECKCONF_PATH=$(resolve unbound-checkconf)
CONTROL_PATH=$(resolve unbound-control)

# --- SSH account -------------------------------------------------------------
if ! id -u "$SSH_USER" >/dev/null 2>&1; then
    useradd --system --create-home --shell /bin/bash "$SSH_USER"
    echo "created account: $SSH_USER"
else
    echo "account already exists: $SSH_USER"
fi

SSH_HOME=$(getent passwd "$SSH_USER" | cut -d: -f6)
if [ -z "$SSH_HOME" ]; then
    echo "error: cannot resolve home directory of $SSH_USER" >&2
    exit 1
fi

if [ -n "$AUTHORIZED_KEY" ]; then
    mkdir -p "$SSH_HOME/.ssh"
    if ! grep -qsFx "$AUTHORIZED_KEY" "$SSH_HOME/.ssh/authorized_keys"; then
        printf '%s\n' "$AUTHORIZED_KEY" >> "$SSH_HOME/.ssh/authorized_keys"
        echo "added public key to $SSH_HOME/.ssh/authorized_keys"
    else
        echo "public key already present"
    fi
    chmod 700 "$SSH_HOME/.ssh"
    chmod 600 "$SSH_HOME/.ssh/authorized_keys"
    chown -R "$SSH_USER":"$SSH_USER" "$SSH_HOME/.ssh"
else
    echo "no public key given, skipping authorized_keys step"
fi

# --- Records file ------------------------------------------------------------
# Mode 644 lets the panel read without sudo. Writing goes through sudo, so the
# directory permissions stay untouched.
if [ ! -e "$RECORDS_PATH" ]; then
    mkdir -p "$RECORDS_DIR"
    : > "$RECORDS_PATH"
    echo "created $RECORDS_PATH"
fi
chmod 644 "$RECORDS_PATH"

# --- Sudoers rules -----------------------------------------------------------
# Six exact rules, no wildcards. The temp path is fixed so the mv rule can be
# an exact match.
#
# The first three write the file. The last three are what a change runs after
# it: the configuration check, the cache preserving reload, and the restart the
# panel falls back to when a reload leaves the resolver stopped.
TMP_SUDOERS=$(mktemp)
trap 'rm -f "$TMP_SUDOERS"' EXIT

cat > "$TMP_SUDOERS" <<EOF
# Managed by jbound setup-target.sh. Do not edit by hand.
# Re-run the script after changing the records path in the panel.
$SSH_USER ALL=(ALL) NOPASSWD: $TEE_PATH $TMP_PATH
$SSH_USER ALL=(ALL) NOPASSWD: $MV_PATH $TMP_PATH $RECORDS_PATH
$SSH_USER ALL=(ALL) NOPASSWD: $SERVICE_PATH unbound reload
$SSH_USER ALL=(ALL) NOPASSWD: $CHECKCONF_PATH $MAIN_CONFIG_PATH
$SSH_USER ALL=(ALL) NOPASSWD: $CONTROL_PATH reload_keep_cache
$SSH_USER ALL=(ALL) NOPASSWD: $SERVICE_PATH unbound restart
EOF

chmod 440 "$TMP_SUDOERS"

# Validate before installing. A broken sudoers file can lock out the server.
if ! visudo -c -f "$TMP_SUDOERS" >/dev/null; then
    echo "error: generated sudoers file failed validation, nothing installed" >&2
    exit 1
fi

install -m 440 -o root -g root "$TMP_SUDOERS" "$SUDOERS_FILE"
echo "installed $SUDOERS_FILE"

# --- Report ------------------------------------------------------------------
cat <<EOF

Enter these values in the panel server record:

  ssh_user            $SSH_USER
  records_path        $RECORDS_PATH
  base64_path         $BASE64_PATH
  tee_path            $TEE_PATH
  mv_path             $MV_PATH
  sha256_path         $SHA256_PATH
  reload_cmd          sudo $CONTROL_PATH reload_keep_cache
  reload_fallback_cmd sudo $SERVICE_PATH unbound reload
  restart_cmd         sudo $SERVICE_PATH unbound restart
  check_conf_cmd      sudo $CHECKCONF_PATH $MAIN_CONFIG_PATH
  status_cmd          systemctl is-active unbound

EOF
