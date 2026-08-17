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
#   -n  No systemd on this host. Skips the unit. For a container or an image
#       build.
#
# Build both binaries first:
#   make build build-helper

set -eu

SERVICE_USER=jbound
SERVICE_GROUP=jbound
DATA_DIR=/var/lib/jbound
CONF_DIR=/etc/jbound
ENV_FILE="$CONF_DIR/jbound.env"
UNIT_FILE=/etc/systemd/system/jbound.service

# What an earlier release installed to forward through rsyslog. The panel
# reaches its receiver itself now, so these are removed rather than updated.
OLD_RSYSLOG_CONF=/etc/rsyslog.d/60-jbound.conf
OLD_SUDOERS_FILE=/etc/sudoers.d/jbound
DOC_DIR=/usr/local/share/doc/jbound/licenses

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
        h) sed -n '2,18p' "$0"; exit 0 ;;
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

# The panel reads nothing under /var/log. An earlier install joined the adm
# group so the SIEM page could read the panel's own log file back, which handed
# over every other service's records with it.
if id -nG "$SERVICE_USER" 2>/dev/null | grep -qw adm; then
    gpasswd -d "$SERVICE_USER" adm > /dev/null
    echo "removed $SERVICE_USER from the adm group, the panel reads no host logs"
fi

# --- State directory ---------------------------------------------------------
# 0700 because the SSH private keys live under it. Nothing but the panel and
# root ever reads this tree.
install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$DATA_DIR"
install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$DATA_DIR/keys"

# --- Binaries ----------------------------------------------------------------
install -d -m 0755 "$PREFIX/bin" "$PREFIX/sbin" "$PREFIX/libexec"
install -m 0755 -o root -g root "$PANEL_BINARY" "$PREFIX/bin/jbound"
echo "installed $PREFIX/bin/jbound"

# Mode 4750 is the whole design of the helper: setuid root so PAM can read the
# shadow database, and group-only execution so no other local account can use it
# as a password oracle.
install -m 4750 -o root -g "$SERVICE_GROUP" "$HELPER_BINARY" \
    "$PREFIX/libexec/jbound-authhelper"
echo "installed $PREFIX/libexec/jbound-authhelper"

# --- Third-party licences ----------------------------------------------------
# The binary serves its stylesheets, scripts, icons and fonts from inside
# itself, so it redistributes them. Every one of those licences asks for its
# notice to travel with the copies.
install -d -m 0755 "$DOC_DIR"
for licence in "$SOURCE_DIR/licenses/"*; do
    install -m 0644 -o root -g root "$licence" "$DOC_DIR/$(basename "$licence")"
done
echo "installed $DOC_DIR"

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

# --- What the rsyslog path left behind ---------------------------------------
# The panel sends its trail to the receiver itself, over an ordinary socket. It
# needs no sudoers rule, no daemon on this host and no file under /etc/rsyslog.d,
# so an upgrade takes all three away. Leaving the sudoers rule in place would
# leave the panel account able to run a root script it no longer calls.
for stale in "$OLD_SUDOERS_FILE" "$OLD_RSYSLOG_CONF" "$PREFIX/sbin/jbound-siem-apply"; do
    if [ -e "$stale" ]; then
        rm -f "$stale"
        echo "removed $stale, the panel forwards without rsyslog"
    fi
done

# No rsyslog restart is needed. The panel writes to no local syslog socket any
# more, so the rule that was removed had nothing left to match.
#
# The rules the panel used to write stay where they are. The panel reads them
# once at startup to carry the collector they name into its own settings, and an
# operator who wants them gone can delete the file afterwards.

# --- The systemd unit --------------------------------------------------------
if [ "$USE_SYSTEMD" = yes ]; then
    install -m 0644 -o root -g root "$SOURCE_DIR/jbound.service" "$UNIT_FILE"
    systemctl daemon-reload
    echo "installed $UNIT_FILE"
else
    echo "skipped the systemd unit, it needs systemctl"
fi

# --- Verify ------------------------------------------------------------------
# The hardening is worth nothing unspoken. These are the three modes that carry
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

# Nothing may grant the panel account a root command. The setuid helper is the
# one privileged piece left, and it is checked above.
if [ -e "$OLD_SUDOERS_FILE" ]; then
    echo "error: $OLD_SUDOERS_FILE still grants the panel account a root command" >&2
    exit 1
fi

cat <<EOF

Installed. What is left:

  1. Review $ENV_FILE. ADMIN_GROUP decides who administers the panel.
  2. Start the service:
       systemctl enable --now jbound
  3. Put a reverse proxy in front of $(grep -s '^LISTEN_ADDR=' "$ENV_FILE" | cut -d= -f2-) and terminate TLS there.
  4. Name a receiver on the SIEM page if the trail is to reach a collector. The
     panel sends to it directly, so nothing else on this host is involved.
  5. Prepare every DNS server with deploy/setup-target.sh and add it in the
     panel. The panel generates the key pair; the setup script takes the public
     half.

Back up with "sudo -u $SERVICE_USER $PREFIX/bin/jbound backup <dir>". Do not copy
$DATA_DIR while the panel runs; the database is open and a file copy of it
cannot be trusted. The backup holds the SSH private keys of every managed
server, so it has to be encrypted. See the README for the restore steps.

EOF
