#!/bin/sh
# Installs the JBound panel on the host that runs it.
#
# Run this as root on the panel server. It is safe to re-run: every step is
# skipped when it is already done, and no file an operator edited is
# overwritten.
#
# Usage:
#   install.sh [-b PANEL_BINARY] [-a HELPER_BINARY] [-p PREFIX] [-n]
#
#   -b  Panel binary to install.    Default: dist/jbound
#   -a  Helper binary to install.   Default: authhelper/jbound-authhelper
#   -p  Install prefix.             Default: /usr/local
#   -n  No systemd on this host. Skips the unit and the two sudoers rules,
#       because both of them drive rsyslog through systemctl. For a container
#       or an image build.
#
# Build both binaries first:
#   make build build-helper

set -eu

SERVICE_USER=jbound
SERVICE_GROUP=jbound
DATA_DIR=/var/lib/jbound
CONF_DIR=/etc/jbound
ENV_FILE="$CONF_DIR/jbound.env"
RSYSLOG_CONF=/etc/rsyslog.d/60-jbound.conf
SUDOERS_FILE=/etc/sudoers.d/jbound
UNIT_FILE=/etc/systemd/system/jbound.service

PANEL_BINARY=dist/jbound
HELPER_BINARY=authhelper/jbound-authhelper
PREFIX=/usr/local
USE_SYSTEMD=yes

unset CDPATH
SOURCE_DIR=$(cd -- "$(dirname -- "$0")" && pwd)

while getopts 'b:a:p:nh' opt; do
    case "$opt" in
        b) PANEL_BINARY=$OPTARG ;;
        a) HELPER_BINARY=$OPTARG ;;
        p) PREFIX=$OPTARG ;;
        n) USE_SYSTEMD=no ;;
        h) sed -n '2,19p' "$0"; exit 0 ;;
        *) echo "run with -h for usage" >&2; exit 2 ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "error: run this script as root" >&2
    exit 1
fi

for binary in "$PANEL_BINARY" "$HELPER_BINARY"; do
    if [ ! -f "$binary" ]; then
        echo "error: $binary is missing, run: make build build-helper" >&2
        exit 1
    fi
done

# --- Service account ---------------------------------------------------------
# A system account with no shell. The panel never logs in, and the group is what
# gates execution of the setuid helper.
if ! getent group "$SERVICE_GROUP" >/dev/null; then
    groupadd --system "$SERVICE_GROUP"
    echo "created group: $SERVICE_GROUP"
fi

if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --gid "$SERVICE_GROUP" --home-dir "$DATA_DIR" \
        --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
    echo "created account: $SERVICE_USER"
fi

# The panel reads the syslog file back for the SIEM page. On a Debian family
# host that file belongs to the adm group.
if getent group adm >/dev/null && ! id -nG "$SERVICE_USER" | grep -qw adm; then
    usermod -aG adm "$SERVICE_USER"
    echo "added $SERVICE_USER to the adm group so it can read the syslog file"
fi

# --- State directory ---------------------------------------------------------
# 0700 because the SSH private keys live under it. Nothing but the panel and
# root ever reads this tree.
install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$DATA_DIR"
install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$DATA_DIR/keys"

# --- Binaries ----------------------------------------------------------------
install -d -m 0755 "$PREFIX/bin" "$PREFIX/libexec"
install -m 0755 -o root -g root "$PANEL_BINARY" "$PREFIX/bin/jbound"
echo "installed $PREFIX/bin/jbound"

# Mode 4750 is the whole design of the helper: setuid root so PAM can read the
# shadow database, and group-only execution so no other local account can use it
# as a password oracle.
install -m 4750 -o root -g "$SERVICE_GROUP" "$HELPER_BINARY" \
    "$PREFIX/libexec/jbound-authhelper"
echo "installed $PREFIX/libexec/jbound-authhelper"

# --- PAM service -------------------------------------------------------------
install -m 0644 -o root -g root "$SOURCE_DIR/pam.d-jbound" \
    /etc/pam.d/jbound
echo "installed /etc/pam.d/jbound"

# --- Environment file --------------------------------------------------------
# Never overwritten. It carries the decisions of the operator, and an upgrade
# that resets ADMIN_GROUP would hand the panel to the wrong people.
install -d -m 0750 -o root -g "$SERVICE_GROUP" "$CONF_DIR"
if [ ! -f "$ENV_FILE" ]; then
    install -m 0640 -o root -g "$SERVICE_GROUP" \
        "$SOURCE_DIR/jbound.env.example" "$ENV_FILE"
    echo "installed $ENV_FILE, review it before starting the service"
else
    echo "kept the existing $ENV_FILE"
fi

# --- rsyslog file the panel owns ---------------------------------------------
# The panel runs unprivileged, so the file exists before it does and is group
# writable. The directory permissions are left alone.
if [ ! -e "$RSYSLOG_CONF" ]; then
    install -m 0664 -o root -g "$SERVICE_GROUP" /dev/null "$RSYSLOG_CONF"
    echo "created $RSYSLOG_CONF"
else
    chown root:"$SERVICE_GROUP" "$RSYSLOG_CONF"
    chmod 0664 "$RSYSLOG_CONF"
fi

# --- Sudoers rules and the systemd unit --------------------------------------
# Two exact rules, no wildcards. The panel restarts rsyslog after writing the
# file above and validates the configuration before it does. Both rules drive
# systemctl, so a host without systemd gets neither.
resolve() {
    _found=$(command -v "$1" 2>/dev/null || true)
    if [ -z "$_found" ]; then
        echo "error: required command not found: $1" >&2
        exit 1
    fi
    printf '%s\n' "$_found"
}

if [ "$USE_SYSTEMD" = yes ]; then
    SYSTEMCTL_PATH=$(resolve systemctl)
    RSYSLOGD_PATH=$(resolve rsyslogd)

    TMP_SUDOERS=$(mktemp)
    trap 'rm -f "$TMP_SUDOERS"' EXIT

    cat > "$TMP_SUDOERS" <<EOF
# Managed by jbound install.sh. Do not edit by hand.
$SERVICE_USER ALL=(ALL) NOPASSWD: $SYSTEMCTL_PATH restart rsyslog
$SERVICE_USER ALL=(ALL) NOPASSWD: $RSYSLOGD_PATH -N1
EOF

    chmod 440 "$TMP_SUDOERS"

    # Validate before installing. A broken sudoers file can lock out the host.
    if ! visudo -c -f "$TMP_SUDOERS" >/dev/null; then
        echo "error: generated sudoers file failed validation, nothing installed" >&2
        exit 1
    fi

    install -m 440 -o root -g root "$TMP_SUDOERS" "$SUDOERS_FILE"
    echo "installed $SUDOERS_FILE"

    install -m 0644 -o root -g root "$SOURCE_DIR/jbound.service" "$UNIT_FILE"
    systemctl daemon-reload
    echo "installed $UNIT_FILE"
else
    echo "skipped the systemd unit and the sudoers rules, both need systemctl"
fi

# --- Verify ------------------------------------------------------------------
# The hardening is worth nothing unspoken. These are the two modes that carry
# it, so they are read back rather than assumed.
HELPER_MODE=$(stat -c '%a %U %G' "$PREFIX/libexec/jbound-authhelper")
if [ "$HELPER_MODE" != "4750 root $SERVICE_GROUP" ]; then
    echo "error: the helper is $HELPER_MODE, want 4750 root $SERVICE_GROUP" >&2
    exit 1
fi

DATA_MODE=$(stat -c '%a %U' "$DATA_DIR")
if [ "$DATA_MODE" != "700 $SERVICE_USER" ]; then
    echo "error: $DATA_DIR is $DATA_MODE, want 700 $SERVICE_USER" >&2
    exit 1
fi

cat <<EOF

Installed. What is left:

  1. Review $ENV_FILE. ADMIN_GROUP decides who administers the panel.
  2. Start the service:
       systemctl enable --now jbound
  3. Put a reverse proxy in front of $(grep -s '^LISTEN_ADDR=' "$ENV_FILE" | cut -d= -f2-) and terminate TLS there.
  4. Prepare every DNS server with deploy/setup-target.sh and add it in the
     panel. The panel generates the key pair; the setup script takes the public
     half.

Back up with "sudo -u $SERVICE_USER $PREFIX/bin/jbound backup <dir>". Do not copy
$DATA_DIR while the panel runs; the database is open and a file copy of it
cannot be trusted. The backup holds the SSH private keys of every managed
server, so it has to be encrypted. See the README for the restore steps.

EOF
