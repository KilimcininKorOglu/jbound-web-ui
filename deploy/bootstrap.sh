#!/bin/sh
# Brings JBound up on a bare server, from nothing to a running service.
#
# It installs the build dependencies, fetches the source from git, builds both
# binaries, hands them to install.sh, writes the answers it collected into the
# environment file, opens what the firewall has to open and starts the service.
#
# It is safe to re-run. A second run pulls the chosen ref again, rebuilds,
# reinstalls and restarts, which is how an upgrade is done. Nothing an operator
# edited is overwritten: install.sh keeps the environment file, and this script
# only sets the keys it was given an answer for.
#
# What it does NOT do: TLS. The panel listens on the loopback address and a
# reverse proxy has to terminate TLS in front of it. INSTALL.md says how, and
# -p opens the ports that proxy will need.
#
# Usage:
#   bootstrap.sh [options]
#
#   -r URL    Repository to clone.        Default: the public GitHub remote
#   -b REF    Branch or tag to build.     Default: main
#   -g GROUP  ADMIN_GROUP.                Default: sudo, or wheel on RHEL
#   -G GROUP  ALLOWED_GROUP.              Default: empty, every local account
#   -m UID    MIN_UID.                    Default: 1000
#   -l ADDR   LISTEN_ADDR.                Default: 127.0.0.1:8080
#   -a USER   Local account to add to the admin group.
#   -p        Open 80 and 443 for the reverse proxy you will add.
#   -k        COOKIE_SECURE=false, for a panel reached over plain HTTP.
#   -n        Leave the firewall alone.
#   -y        Take every default and ask nothing. For an unattended run.
#   -h        This text.

set -eu

REPO=https://github.com/KilimcininKorOglu/jbound-web-ui.git
REF=main
SRC_DIR=/usr/local/src/jbound

# The toolchain line in go.mod states the lowest patch level the panel may be
# built with. A distribution will not carry it for years, so the script fetches
# the official tarball when the host has nothing new enough.
GO_VERSION=1.26.6
GO_MIN_MINOR=26

ADMIN_GROUP=
ALLOWED_GROUP=
MIN_UID=1000
LISTEN_ADDR=127.0.0.1:8080
COOKIE_SECURE=true
ADMIN_USER=
OPEN_PROXY_PORTS=no
TOUCH_FIREWALL=yes
ASSUME_YES=no

WORK_DIR=
cleanup() {
    # The credential file lives in here. It goes whatever way the script ends.
    [ -n "$WORK_DIR" ] && [ -d "$WORK_DIR" ] && rm -rf "$WORK_DIR"
    return 0
}
trap cleanup EXIT INT TERM

die() { printf 'error: %s\n' "$1" >&2; exit 1; }
say() { printf '%s\n' "$1"; }
step() { printf '\n== %s\n' "$1"; }
warn() { printf 'warning: %s\n' "$1" >&2; }

# ask prints its prompt on stderr and the answer on stdout, so a caller can
# read it through a command substitution.
ask() {
    ask_default=$2
    if [ "$ASSUME_YES" = yes ]; then
        printf '%s' "$ask_default"
        return 0
    fi
    printf '%s [%s]: ' "$1" "$ask_default" >&2
    IFS= read -r ask_answer < /dev/tty || ask_answer=
    [ -n "$ask_answer" ] || ask_answer=$ask_default
    printf '%s' "$ask_answer"
}

# ask_yes_no returns success for yes. The default is what an empty line means.
ask_yes_no() {
    if [ "$ASSUME_YES" = yes ]; then
        [ "$2" = y ]
        return $?
    fi
    if [ "$2" = y ]; then
        printf '%s [Y/n]: ' "$1" >&2
    else
        printf '%s [y/N]: ' "$1" >&2
    fi
    IFS= read -r yn_answer < /dev/tty || yn_answer=
    [ -n "$yn_answer" ] || yn_answer=$2
    case "$yn_answer" in
        y | Y | yes | YES) return 0 ;;
        *) return 1 ;;
    esac
}

# read_secret reads one line without echoing it. The value reaches no argument
# list and no environment variable, because /proc exposes both.
read_secret() {
    printf '%s: ' "$1" >&2
    stty -echo < /dev/tty
    IFS= read -r secret_answer < /dev/tty || secret_answer=
    stty echo < /dev/tty
    printf '\n' >&2
    printf '%s' "$secret_answer"
}

while getopts 'r:b:g:G:m:l:a:pknyh' opt; do
    case "$opt" in
        r) REPO=$OPTARG ;;
        b) REF=$OPTARG ;;
        g) ADMIN_GROUP=$OPTARG ;;
        G) ALLOWED_GROUP=$OPTARG ;;
        m) MIN_UID=$OPTARG ;;
        l) LISTEN_ADDR=$OPTARG ;;
        a) ADMIN_USER=$OPTARG ;;
        p) OPEN_PROXY_PORTS=yes ;;
        k) COOKIE_SECURE=false ;;
        n) TOUCH_FIREWALL=no ;;
        y) ASSUME_YES=yes ;;
        h) sed -n '2,35p' "$0"; exit 0 ;;
        *) echo "run with -h for usage" >&2; exit 2 ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "run this script as root"

if [ "$ASSUME_YES" = no ] && [ ! -e /dev/tty ]; then
    die "no terminal to ask questions on, re-run with -y and the options you want"
fi

# --- The distribution --------------------------------------------------------
# The panel is developed and tested on Debian. The RHEL family differs in the
# package names, in the PAM stack it includes and in carrying SELinux, and all
# three are handled below. Anything else is refused rather than half installed.

[ -r /etc/os-release ] || die "/etc/os-release is missing, cannot tell what this is"
# shellcheck disable=SC1091
. /etc/os-release

FAMILY=
case " ${ID:-} ${ID_LIKE:-} " in
    *" debian "* | *" ubuntu "*) FAMILY=debian ;;
    *" rhel "* | *" fedora "* | *" centos "*) FAMILY=rhel ;;
esac
[ -n "$FAMILY" ] || die "${PRETTY_NAME:-this system} is not supported, Debian, Ubuntu and the RHEL family are"

if [ -z "$ADMIN_GROUP" ]; then
    if [ "$FAMILY" = rhel ]; then ADMIN_GROUP=wheel; else ADMIN_GROUP=sudo; fi
fi

say "JBound bootstrap on ${PRETTY_NAME:-$ID} (${FAMILY} family)"

# --- The questions -----------------------------------------------------------

step "What this panel will be"

REPO=$(ask "Repository to clone" "$REPO")
REF=$(ask "Branch or tag to build" "$REF")

GIT_TOKEN=
if ask_yes_no "Is the repository private" n; then
    GIT_TOKEN=$(read_secret "GitHub token with read access to the repository")
    [ -n "$GIT_TOKEN" ] || die "no token given, and a private repository needs one"
fi

ADMIN_GROUP=$(ask "Local group whose members administer the panel" "$ADMIN_GROUP")
ALLOWED_GROUP=$(ask "Local group allowed to sign in at all, empty for every account" "$ALLOWED_GROUP")
MIN_UID=$(ask "Lowest uid allowed to sign in" "$MIN_UID")
LISTEN_ADDR=$(ask "Address the panel listens on" "$LISTEN_ADDR")

if [ -z "$ADMIN_USER" ] && [ "$ASSUME_YES" = no ]; then
    ADMIN_USER=$(ask "Local account to add to $ADMIN_GROUP, empty to skip" "")
fi

case "$LISTEN_ADDR" in
    127.0.0.1:* | localhost:* | "[::1]":*) ;;
    *) warn "$LISTEN_ADDR is reachable from outside this host, and the panel speaks plain HTTP" ;;
esac

if [ "$COOKIE_SECURE" = true ] && [ "$ASSUME_YES" = no ]; then
    if ask_yes_no "Will the panel be reached over plain HTTP, with no TLS in front" n; then
        COOKIE_SECURE=false
    fi
fi

if [ "$TOUCH_FIREWALL" = yes ] && [ "$OPEN_PROXY_PORTS" = no ] && [ "$ASSUME_YES" = no ]; then
    if ask_yes_no "Open 80 and 443 for a reverse proxy you will add" y; then
        OPEN_PROXY_PORTS=yes
    fi
fi

# --- Packages ----------------------------------------------------------------

step "Installing the build and runtime dependencies"

# A tool that is already there is left alone. On the RHEL family that is not a
# nicety: the stock image carries curl-minimal, and asking for curl on top of
# it is a package conflict rather than an upgrade.
EXTRA=
command -v git > /dev/null 2>&1 || EXTRA="$EXTRA git"
command -v curl > /dev/null 2>&1 || EXTRA="$EXTRA curl"

if [ "$FAMILY" = debian ]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    # shellcheck disable=SC2086
    apt-get install -y --no-install-recommends \
        ca-certificates make gcc libc6-dev libpam0g-dev rsyslog $EXTRA
    if ! command -v dig > /dev/null 2>&1; then
        # The name of the dig package changed. Either one provides the binary.
        apt-get install -y --no-install-recommends bind9-dnsutils \
            || apt-get install -y --no-install-recommends dnsutils
    fi
else
    PKG=dnf
    command -v dnf > /dev/null 2>&1 || PKG=yum
    # shellcheck disable=SC2086
    "$PKG" install -y ca-certificates make gcc glibc-devel pam-devel \
        rsyslog bind-utils $EXTRA
fi

command -v dig > /dev/null 2>&1 || die "dig is still missing, the query page needs it"

# --- The Go toolchain --------------------------------------------------------

step "Checking the Go toolchain"

go_is_new_enough() {
    command -v go > /dev/null 2>&1 || return 1
    go_version=$(go version 2>/dev/null | awk '{print $3}' | sed 's/^go//')
    go_major=${go_version%%.*}
    go_rest=${go_version#*.}
    go_minor=${go_rest%%.*}
    case "$go_major$go_minor" in
        *[!0-9]*) return 1 ;;
    esac
    [ "$go_major" -gt 1 ] && return 0
    [ "$go_major" -eq 1 ] && [ "$go_minor" -ge "$GO_MIN_MINOR" ]
}

if go_is_new_enough; then
    say "using $(go version)"
else
    case "$(uname -m)" in
        x86_64) GO_ARCH=amd64 ;;
        aarch64 | arm64) GO_ARCH=arm64 ;;
        *) die "no Go build published for $(uname -m), install Go $GO_VERSION yourself and re-run" ;;
    esac

    GO_TAR=go${GO_VERSION}.linux-${GO_ARCH}.tar.gz
    GO_TMP=$(mktemp -d)
    say "fetching $GO_TAR"
    # dl.google.com rather than go.dev, because go.dev answers the .sha256
    # path with an HTML redirect page and the check would compare a digest
    # against a web page.
    curl -fsSL -o "$GO_TMP/$GO_TAR" "https://dl.google.com/go/$GO_TAR"

    # Against the digest the same site publishes. It proves the download
    # arrived whole, which is the failure that actually happens; it is not a
    # second opinion about what the file should be.
    GO_WANT=$(curl -fsSL "https://dl.google.com/go/$GO_TAR.sha256")
    GO_GOT=$(sha256sum "$GO_TMP/$GO_TAR" | awk '{print $1}')
    [ "$GO_WANT" = "$GO_GOT" ] || die "the Go tarball does not match the published digest"

    rm -rf /usr/local/go
    tar -C /usr/local -xzf "$GO_TMP/$GO_TAR"
    rm -rf "$GO_TMP"
    PATH=/usr/local/go/bin:$PATH
    export PATH
    say "installed $(go version) into /usr/local/go"
fi

# --- The source --------------------------------------------------------------

step "Fetching the source"

WORK_DIR=$(mktemp -d)
chmod 700 "$WORK_DIR"

GIT_OPTS=
if [ -n "$GIT_TOKEN" ]; then
    # A credential file in a 0700 directory, removed by the exit trap. The
    # token is never an argument and never an environment variable, because
    # /proc hands both to any account on the host.
    CRED_FILE=$WORK_DIR/git-credentials
    umask 077
    printf 'https://x-access-token:%s@github.com\n' "$GIT_TOKEN" > "$CRED_FILE"
    GIT_TOKEN=
    GIT_OPTS="-c credential.helper=store --file=$CRED_FILE"
fi

if [ -d "$SRC_DIR/.git" ]; then
    say "updating $SRC_DIR"
    # shellcheck disable=SC2086
    git $GIT_OPTS -C "$SRC_DIR" fetch --tags origin
    git -C "$SRC_DIR" checkout --quiet "$REF"
    git -C "$SRC_DIR" reset --hard --quiet "origin/$REF" 2>/dev/null \
        || git -C "$SRC_DIR" reset --hard --quiet "$REF"
else
    install -d -m 0755 "$(dirname "$SRC_DIR")"
    # shellcheck disable=SC2086
    git $GIT_OPTS clone --branch "$REF" "$REPO" "$SRC_DIR"
fi

say "building $(git -C "$SRC_DIR" rev-parse --short HEAD)"

# --- Build and install -------------------------------------------------------

step "Building the panel and the helper"

cd "$SRC_DIR"
make build build-helper

step "Installing"

# A container or an image build has no systemd. install.sh carries the flag for
# it, and the service cannot be started here either, so both are skipped
# together rather than failing halfway through.
HAVE_SYSTEMD=no
if command -v systemctl > /dev/null 2>&1 && [ -d /run/systemd/system ]; then
    HAVE_SYSTEMD=yes
fi

if [ "$HAVE_SYSTEMD" = yes ]; then
    ./deploy/install.sh
else
    say "no systemd on this host, installing without the unit and the sudoers rules"
    ./deploy/install.sh -n
fi

# --- The environment file ----------------------------------------------------
# install.sh writes it once from the example and never again, so the answers
# are applied here rather than there.

step "Writing the answers into /etc/jbound/jbound.env"

ENV_FILE=/etc/jbound/jbound.env
[ -f "$ENV_FILE" ] || die "$ENV_FILE is missing, install.sh should have created it"

set_env() {
    if grep -q "^$1=" "$ENV_FILE"; then
        sed -i "s|^$1=.*|$1=$2|" "$ENV_FILE"
    else
        printf '%s=%s\n' "$1" "$2" >> "$ENV_FILE"
    fi
    say "  $1=$2"
}

set_env ADMIN_GROUP "$ADMIN_GROUP"
set_env ALLOWED_GROUP "$ALLOWED_GROUP"
set_env MIN_UID "$MIN_UID"
set_env LISTEN_ADDR "$LISTEN_ADDR"
set_env COOKIE_SECURE "$COOKIE_SECURE"
set_env DIG_PATH "$(command -v dig)"

# --- PAM ---------------------------------------------------------------------
# install.sh ships the Debian stack. The RHEL family includes one file for both
# stacks, and a service that includes a file it does not have refuses every
# sign in with nothing useful to say.

if [ "$FAMILY" = rhel ]; then
    step "Pointing /etc/pam.d/jbound at the RHEL stack"
    cat > /etc/pam.d/jbound <<'EOF'
# PAM service definition for the JBound panel, RHEL family.
# Written by deploy/bootstrap.sh. Only the auth and account stacks are used.

auth     include  system-auth
account  include  system-auth
EOF
    chmod 0644 /etc/pam.d/jbound
    say "  auth and account now include system-auth"
fi

# --- SELinux -----------------------------------------------------------------

if command -v getenforce > /dev/null 2>&1 && [ "$(getenforce)" = Enforcing ]; then
    step "SELinux is enforcing"
    restorecon -R /usr/local/bin/jbound /usr/local/libexec/jbound-authhelper \
        /var/lib/jbound /etc/jbound 2>/dev/null || true
    warn "SELinux is enforcing and this combination is not covered by the project's tests"
    warn "if a sign in fails, check: ausearch -m avc -ts recent"
fi

# --- The admin account -------------------------------------------------------

if [ -n "$ADMIN_USER" ]; then
    step "Adding $ADMIN_USER to $ADMIN_GROUP"
    id "$ADMIN_USER" > /dev/null 2>&1 || die "no local account named $ADMIN_USER"
    getent group "$ADMIN_GROUP" > /dev/null 2>&1 || groupadd "$ADMIN_GROUP"
    usermod -aG "$ADMIN_GROUP" "$ADMIN_USER"
    say "  $ADMIN_USER may now administer the panel"
elif ! getent group "$ADMIN_GROUP" > /dev/null 2>&1; then
    warn "the group $ADMIN_GROUP does not exist, so nobody can administer the panel yet"
fi

# --- Firewall ----------------------------------------------------------------
# The panel itself needs nothing opened while it listens on the loopback
# address. What needs opening is the reverse proxy in front of it, and the SSH
# port this session is running over, which a firewall enabled for the first
# time would otherwise close behind us.

if [ "$TOUCH_FIREWALL" = yes ]; then
    step "Firewall"

    # Asking sshd itself is the only answer that accounts for a drop-in file.
    # Both readings are allowed to fail: a host with no sshd at all still has
    # a firewall worth setting, and 22 is the answer that locks nobody out.
    SSH_PORT=$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}' || true)
    if [ -z "$SSH_PORT" ]; then
        SSH_PORT=$(awk '/^[Pp]ort /{print $2; exit}' /etc/ssh/sshd_config 2>/dev/null || true)
    fi
    [ -n "$SSH_PORT" ] || SSH_PORT=22

    # A firewall that will not answer is reported and stepped over. The panel
    # is installed by this point, and leaving it uninstalled over a rule that
    # could not be written helps nobody.
    if command -v ufw > /dev/null 2>&1; then
        UFW_STATE=$(ufw status 2>/dev/null | head -n1 || true)
        say "  ufw: ${UFW_STATE:-unreadable}"
        if ufw allow "$SSH_PORT/tcp" > /dev/null; then
            say "  allowed $SSH_PORT/tcp, so this session survives"
        else
            warn "ufw would not allow $SSH_PORT/tcp, check it before enabling"
        fi
        if [ "$OPEN_PROXY_PORTS" = yes ]; then
            if ufw allow 80/tcp > /dev/null && ufw allow 443/tcp > /dev/null; then
                say "  allowed 80/tcp and 443/tcp"
            else
                warn "ufw would not allow 80 and 443"
            fi
        fi
        case "$UFW_STATE" in
            *inactive*)
                if ask_yes_no "  ufw is inactive, enable it now" n; then
                    ufw --force enable
                    say "  ufw enabled"
                else
                    say "  left ufw inactive, the rules are stored"
                fi
                ;;
        esac
    elif command -v firewall-cmd > /dev/null 2>&1 && firewall-cmd --state > /dev/null 2>&1; then
        say "  firewalld is running"
        if firewall-cmd --permanent --add-port="$SSH_PORT/tcp" > /dev/null; then
            say "  allowed $SSH_PORT/tcp, so this session survives"
        else
            warn "firewalld would not allow $SSH_PORT/tcp"
        fi
        if [ "$OPEN_PROXY_PORTS" = yes ]; then
            if firewall-cmd --permanent --add-service=http > /dev/null \
                && firewall-cmd --permanent --add-service=https > /dev/null; then
                say "  allowed http and https"
            else
                warn "firewalld would not allow http and https"
            fi
        fi
        firewall-cmd --reload > /dev/null || warn "firewalld would not reload"
    elif command -v nft > /dev/null 2>&1 && nft list ruleset 2>/dev/null | grep -q .; then
        # An nftables ruleset written by hand is not something to edit from a
        # script. Guessing the chain to add to is how an operator is locked out.
        warn "this host uses nftables directly, so nothing was changed"
        say "  add yourself, in the chain that accepts inbound traffic:"
        say "    tcp dport $SSH_PORT accept"
        if [ "$OPEN_PROXY_PORTS" = yes ]; then
            say "    tcp dport { 80, 443 } accept"
        fi
    else
        say "  no active firewall found, nothing to change"
    fi
else
    say "skipped the firewall, as asked"
fi

# --- Start -------------------------------------------------------------------

HEALTH_PORT=${LISTEN_ADDR##*:}

if [ "$HAVE_SYSTEMD" = yes ]; then
    step "Starting the service"

    systemctl daemon-reload
    systemctl enable --now jbound

    HEALTH_OK=no
    i=0
    while [ "$i" -lt 20 ]; do
        if curl -fsS "http://127.0.0.1:$HEALTH_PORT/healthz" > /dev/null 2>&1; then
            HEALTH_OK=yes
            break
        fi
        i=$((i + 1))
        sleep 1
    done

    if [ "$HEALTH_OK" = yes ]; then
        say "  the panel answers on http://127.0.0.1:$HEALTH_PORT/healthz"
    else
        warn "the panel did not answer its health check in 20 seconds"
        warn "read the reason with: journalctl -u jbound -n 50 --no-pager"
    fi
else
    step "Not starting anything"
    say "  this host has no systemd, so the unit was not installed"
    say "  run the panel yourself with: /usr/local/bin/jbound"
fi

# --- What is left ------------------------------------------------------------

cat <<EOF

Installed. What is left:

  1. Put a reverse proxy in front of $LISTEN_ADDR and terminate TLS there.
     The panel speaks plain HTTP and expects to be reached through one.
     INSTALL.md carries a working nginx and Caddy example.

  2. Sign in as a member of $ADMIN_GROUP with that account's own password.
     The panel has no user database of its own.

  3. Prepare every DNS server, one way or the other:
       over SSH:      sudo ./deploy/setup-target.sh -k "<the key the panel shows>"
       with an agent: sudo ./deploy/setup-agent.sh -t "<the token the panel shows>"

  4. Add each server in the panel, approve its host key or certificate
     fingerprint, and press Test before you rely on it.

Upgrade later by re-running this script. It pulls $REF again, rebuilds,
reinstalls and restarts, and leaves $ENV_FILE alone.

Back up with: sudo -u jbound /usr/local/bin/jbound backup /var/backups/jbound/\$(date +%F)
EOF
