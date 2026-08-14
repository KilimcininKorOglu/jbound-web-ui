#!/bin/sh
# Prepares an Unbound server so the JBound panel can manage it over SSH.
#
# Run this as root on every managed DNS server.
#
# Usage:
#   setup-target.sh [-u USER] [-f HOST_ENTRIES_PATH] [-k AUTHORIZED_KEY]
#
#   -u  SSH account the panel connects as.       Default: dnsops
#   -f  Path of the Unbound host entries file.   Default: /etc/unbound/host_entries.conf
#   -k  Public key the panel generated. When omitted the key step is skipped.
#
# The script does NOT change the permissions of the Unbound configuration
# directory. Writing happens through three exact sudoers rules instead.
#
# Re-run this script whenever the host entries path changes in the panel,
# because the sudoers rules are derived from that path.

set -eu

SSH_USER=dnsops
HOST_ENTRIES_PATH=/etc/unbound/host_entries.conf
AUTHORIZED_KEY=
SUDOERS_FILE=/etc/sudoers.d/jbound-target

while getopts 'u:f:k:h' opt; do
    case "$opt" in
        u) SSH_USER=$OPTARG ;;
        f) HOST_ENTRIES_PATH=$OPTARG ;;
        k) AUTHORIZED_KEY=$OPTARG ;;
        h) sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "run with -h for usage" >&2; exit 2 ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "error: run this script as root" >&2
    exit 1
fi

case "$HOST_ENTRIES_PATH" in
    /*) ;;
    *) echo "error: host entries path must be absolute: $HOST_ENTRIES_PATH" >&2; exit 1 ;;
esac

ENTRIES_DIR=$(dirname "$HOST_ENTRIES_PATH")
ENTRIES_FILE=$(basename "$HOST_ENTRIES_PATH")
TMP_PATH="$ENTRIES_DIR/.$ENTRIES_FILE.tmp"

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

# --- Host entries file -------------------------------------------------------
# Mode 644 lets the panel read without sudo. Writing goes through sudo, so the
# directory permissions stay untouched.
if [ ! -e "$HOST_ENTRIES_PATH" ]; then
    mkdir -p "$ENTRIES_DIR"
    : > "$HOST_ENTRIES_PATH"
    echo "created $HOST_ENTRIES_PATH"
fi
chmod 644 "$HOST_ENTRIES_PATH"

# --- Sudoers rules -----------------------------------------------------------
# Three exact rules, no wildcards. The temp path is fixed so the mv rule can be
# an exact match.
TMP_SUDOERS=$(mktemp)
trap 'rm -f "$TMP_SUDOERS"' EXIT

cat > "$TMP_SUDOERS" <<EOF
# Managed by jbound setup-target.sh. Do not edit by hand.
# Re-run the script after changing the host entries path in the panel.
$SSH_USER ALL=(ALL) NOPASSWD: $TEE_PATH $TMP_PATH
$SSH_USER ALL=(ALL) NOPASSWD: $MV_PATH $TMP_PATH $HOST_ENTRIES_PATH
$SSH_USER ALL=(ALL) NOPASSWD: $SERVICE_PATH unbound reload
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

  ssh_user           $SSH_USER
  host_entries_path  $HOST_ENTRIES_PATH
  base64_path        $BASE64_PATH
  tee_path           $TEE_PATH
  mv_path            $MV_PATH
  sha256_path        $SHA256_PATH
  reload_cmd         sudo $SERVICE_PATH unbound reload
  status_cmd         systemctl is-active unbound

EOF
