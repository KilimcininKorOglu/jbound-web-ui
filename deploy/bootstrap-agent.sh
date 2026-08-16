#!/bin/sh
# Brings a JBound agent up on a bare resolver, from nothing to a running service.
#
# It installs the dependencies, fetches the source from git, builds the agent,
# installs the binary and the unit, hands the rest to setup-agent.sh, opens the
# agent port and proves the service answers.
#
# This is the alternative to deploy/setup-target.sh, not an addition to it. A
# resolver is reached over SSH or through an agent, never both. The agent path
# installs no sudoers rule and needs no sshd: the panel sends no command text
# and names no file, so there is nothing here for a login shell to run. The
# account it creates has no home, no shell and a locked password.
#
# It is safe to re-run. A second run pulls the chosen ref again, rebuilds and
# restarts, which is how an upgrade is done. The certificate is kept, because
# replacing it would change the fingerprint the panel has pinned and every
# connection would stop until an operator approved the new one.
#
# Usage:
#   bootstrap-agent.sh [options]
#
#   -t TOKEN  The token the panel showed once when the server was added.
#   -r URL    Repository to clone.        Default: the public GitHub remote
#   -b REF    Branch or tag to build.     Default: main
#   -f PATH   Records file.               Default: /etc/unbound/local_records.conf
#   -c PATH   Main Unbound configuration. Default: /etc/unbound/unbound.conf
#   -a ADDR   Address the agent listens on. Default: 0.0.0.0:8443
#   -P ADDR   Panel address, so the firewall opens the port to it alone.
#   -u        Install Unbound when it is missing.
#   -R        Run the agent as root, rather than under its own account.
#   -n        Leave the firewall alone.
#   -y        Take every default and ask nothing. For an unattended run.
#   -h        This text.

set -eu

REPO=https://github.com/KilimcininKorOglu/jbound-web-ui.git
REF=main
SRC_DIR=/usr/local/src/jbound

GO_VERSION=1.26.6
GO_MIN_MINOR=26

TOKEN=
RECORDS_PATH=/etc/unbound/local_records.conf
MAIN_CONFIG_PATH=/etc/unbound/unbound.conf
LISTEN_ADDR=0.0.0.0:8443
PANEL_ADDR=
INSTALL_UNBOUND=no
AGENT_AS_ROOT=
TOUCH_FIREWALL=yes
ASSUME_YES=no

WORK_DIR=
cleanup() {
    if [ -n "$WORK_DIR" ] && [ -d "$WORK_DIR" ]; then
        rm -rf "$WORK_DIR"
    fi
    return 0
}
trap cleanup EXIT INT TERM

die() { printf 'error: %s\n' "$1" >&2; exit 1; }
say() { printf '%s\n' "$1"; }
step() { printf '\n== %s\n' "$1"; }
warn() { printf 'warning: %s\n' "$1" >&2; }

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

while getopts 't:r:b:f:c:a:P:uRnyh' opt; do
    case "$opt" in
        t) TOKEN=$OPTARG ;;
        r) REPO=$OPTARG ;;
        b) REF=$OPTARG ;;
        f) RECORDS_PATH=$OPTARG ;;
        c) MAIN_CONFIG_PATH=$OPTARG ;;
        a) LISTEN_ADDR=$OPTARG ;;
        P) PANEL_ADDR=$OPTARG ;;
        u) INSTALL_UNBOUND=yes ;;
        R) AGENT_AS_ROOT=-R ;;
        n) TOUCH_FIREWALL=no ;;
        y) ASSUME_YES=yes ;;
        h) sed -n '2,33p' "$0"; exit 0 ;;
        *) echo "run with -h for usage" >&2; exit 2 ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "run this script as root"

if [ "$ASSUME_YES" = no ] && [ ! -e /dev/tty ]; then
    die "no terminal to ask questions on, re-run with -y and the options you want"
fi

[ -r /etc/os-release ] || die "/etc/os-release is missing, cannot tell what this is"
# shellcheck disable=SC1091
. /etc/os-release

FAMILY=
case " ${ID:-} ${ID_LIKE:-} " in
    *" debian "* | *" ubuntu "*) FAMILY=debian ;;
    *" rhel "* | *" fedora "* | *" centos "*) FAMILY=rhel ;;
esac
[ -n "$FAMILY" ] || die "${PRETTY_NAME:-this system} is not supported, Debian, Ubuntu and the RHEL family are"

say "JBound agent bootstrap on ${PRETTY_NAME:-$ID} (${FAMILY} family)"

# --- The questions -----------------------------------------------------------

step "What this agent will be"

REPO=$(ask "Repository to clone" "$REPO")
REF=$(ask "Branch or tag to build" "$REF")

GIT_TOKEN=
if ask_yes_no "Is the repository private" n; then
    GIT_TOKEN=$(read_secret "GitHub token with read access to the repository")
    [ -n "$GIT_TOKEN" ] || die "no token given, and a private repository needs one"
fi

if [ -z "$TOKEN" ]; then
    say ""
    say "The panel shows the agent token once, on the page that adds the server."
    say "It is the credential the panel authenticates with, and nothing shows it twice."
    TOKEN=$(read_secret "Agent token from the panel")
fi
[ -n "$TOKEN" ] || die "no agent token, and the panel cannot authenticate without one"

RECORDS_PATH=$(ask "Records file the agent owns" "$RECORDS_PATH")
MAIN_CONFIG_PATH=$(ask "Main Unbound configuration" "$MAIN_CONFIG_PATH")
LISTEN_ADDR=$(ask "Address the agent listens on" "$LISTEN_ADDR")

if [ -z "$PANEL_ADDR" ] && [ "$TOUCH_FIREWALL" = yes ] && [ "$ASSUME_YES" = no ]; then
    say ""
    say "The agent port is the way into this resolver. Naming the panel here"
    say "opens it to that address alone rather than to the whole network."
    PANEL_ADDR=$(ask "Panel address, empty to open the port to anywhere" "")
fi

AGENT_PORT=${LISTEN_ADDR##*:}
case "$AGENT_PORT" in
    "" | *[!0-9]*) die "cannot read a port out of $LISTEN_ADDR" ;;
esac

# --- Unbound -----------------------------------------------------------------

step "Checking Unbound"

if command -v unbound > /dev/null 2>&1; then
    say "  unbound is installed"
elif [ "$INSTALL_UNBOUND" = yes ] || ask_yes_no "  unbound is missing, install it" y; then
    INSTALL_UNBOUND=yes
    say "  will install unbound with the rest"
else
    warn "this host has no unbound, and the agent manages the records of one"
fi

# --- Packages ----------------------------------------------------------------
# The agent is built with CGO_ENABLED=0, so no C compiler and no PAM headers
# are needed here. That is the panel host's list, not this one's.

step "Installing the dependencies"

EXTRA=
command -v git > /dev/null 2>&1 || EXTRA="$EXTRA git"
command -v curl > /dev/null 2>&1 || EXTRA="$EXTRA curl"
command -v openssl > /dev/null 2>&1 || EXTRA="$EXTRA openssl"
if [ "$INSTALL_UNBOUND" = yes ]; then
    EXTRA="$EXTRA unbound"
fi

if [ "$FAMILY" = debian ]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    # shellcheck disable=SC2086
    apt-get install -y --no-install-recommends ca-certificates make $EXTRA
else
    PKG=dnf
    command -v dnf > /dev/null 2>&1 || PKG=yum
    # shellcheck disable=SC2086
    "$PKG" install -y ca-certificates make $EXTRA
fi

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
    # path with an HTML redirect page.
    curl -fsSL -o "$GO_TMP/$GO_TAR" "https://dl.google.com/go/$GO_TAR"

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

step "Building the agent"

cd "$SRC_DIR"
make build-agent

step "Installing the binary and the unit"

install -m 0755 -o root -g root dist/jbound-agent /usr/local/bin/jbound-agent
say "  installed /usr/local/bin/jbound-agent"

HAVE_SYSTEMD=no
if command -v systemctl > /dev/null 2>&1 && [ -d /run/systemd/system ]; then
    HAVE_SYSTEMD=yes
    install -m 0644 -o root -g root deploy/jbound-agent.service \
        /etc/systemd/system/jbound-agent.service
    say "  installed /etc/systemd/system/jbound-agent.service"

    # The unit runs with ProtectSystem=strict and names /etc/unbound as the one
    # writable path. A resolver that keeps its files somewhere else would fail
    # at the first write with a read only filesystem, long after the operator
    # chose the path here, so the directories are added now.
    DROPIN_DIR=/etc/systemd/system/jbound-agent.service.d
    EXTRA_PATHS=
    for path in "$RECORDS_PATH" "$MAIN_CONFIG_PATH"; do
        dir=$(dirname "$path")
        case "$dir" in
            /etc/unbound | /etc/unbound/*) continue ;;
        esac
        case " $EXTRA_PATHS " in
            *" $dir "*) continue ;;
        esac
        EXTRA_PATHS="$EXTRA_PATHS $dir"
    done

    if [ -n "$EXTRA_PATHS" ]; then
        install -d -m 0755 "$DROPIN_DIR"
        {
            echo "# Written by deploy/bootstrap-agent.sh."
            echo "# The unit allows /etc/unbound only, and this agent was given"
            echo "# paths outside it."
            echo "[Service]"
            for dir in $EXTRA_PATHS; do
                echo "ReadWritePaths=$dir"
            done
        } > "$DROPIN_DIR/paths.conf"
        chmod 0644 "$DROPIN_DIR/paths.conf"
        say "  allowed the agent to write:$EXTRA_PATHS"
    elif [ -f "$DROPIN_DIR/paths.conf" ]; then
        # The paths moved back under /etc/unbound. Leaving the old drop in
        # would keep a directory writable that nothing writes to.
        rm -f "$DROPIN_DIR/paths.conf"
        rmdir "$DROPIN_DIR" 2>/dev/null || true
        say "  removed an old writable path override"
    fi

    systemctl daemon-reload
else
    say "  no systemd on this host, so the unit was not installed"
fi

# --- Configuration -----------------------------------------------------------
# setup-agent.sh owns this half: the token, the certificate and the environment
# file. It is the same script an operator runs by hand, so there is one
# description of what a prepared agent host looks like.

step "Configuring the agent"

# shellcheck disable=SC2086
./deploy/setup-agent.sh $AGENT_AS_ROOT -t "$TOKEN" -f "$RECORDS_PATH" \
    -c "$MAIN_CONFIG_PATH" -a "$LISTEN_ADDR"
TOKEN=

# --- The commands the agent will run -----------------------------------------
# Each step may be empty, and the panel then skips that rung rather than
# reporting a failure. A missing checker is worth knowing about now rather than
# during the first change.

step "Checking the commands the agent was given"

ENV_FILE=/etc/jbound-agent/jbound-agent.env
for key in CHECK_CONF_CMD RELOAD_CMD RELOAD_FALLBACK_CMD RESTART_CMD STATUS_CMD; do
    cmd=$(grep "^$key=" "$ENV_FILE" | cut -d= -f2- | awk '{print $1}')
    if [ -z "$cmd" ]; then
        say "  $key is empty, the panel will skip that step"
    elif [ -x "$cmd" ] || command -v "$cmd" > /dev/null 2>&1; then
        say "  $key -> $cmd"
    else
        warn "$key names $cmd, which is not on this host"
        warn "edit $ENV_FILE and restart jbound-agent"
    fi
done

# --- Firewall ----------------------------------------------------------------
# The agent port is the way into this resolver, so it is opened to the panel
# alone whenever the panel's address is known.

if [ "$TOUCH_FIREWALL" = yes ]; then
    step "Firewall"

    if command -v ufw > /dev/null 2>&1; then
        UFW_STATE=$(ufw status 2>/dev/null | head -n1 || true)
        say "  ufw: ${UFW_STATE:-unreadable}"
        if [ -n "$PANEL_ADDR" ]; then
            if ufw allow from "$PANEL_ADDR" to any port "$AGENT_PORT" proto tcp > /dev/null; then
                say "  allowed $AGENT_PORT/tcp from $PANEL_ADDR alone"
            else
                warn "ufw would not allow $AGENT_PORT/tcp from $PANEL_ADDR"
            fi
        elif ufw allow "$AGENT_PORT/tcp" > /dev/null; then
            say "  allowed $AGENT_PORT/tcp from anywhere"
        else
            warn "ufw would not allow $AGENT_PORT/tcp"
        fi
    elif command -v firewall-cmd > /dev/null 2>&1 && firewall-cmd --state > /dev/null 2>&1; then
        say "  firewalld is running"
        if [ -n "$PANEL_ADDR" ]; then
            RULE="rule family=ipv4 source address=$PANEL_ADDR port port=$AGENT_PORT protocol=tcp accept"
            if firewall-cmd --permanent --add-rich-rule="$RULE" > /dev/null; then
                say "  allowed $AGENT_PORT/tcp from $PANEL_ADDR alone"
            else
                warn "firewalld would not add the rich rule for $PANEL_ADDR"
            fi
        elif firewall-cmd --permanent --add-port="$AGENT_PORT/tcp" > /dev/null; then
            say "  allowed $AGENT_PORT/tcp from anywhere"
        else
            warn "firewalld would not allow $AGENT_PORT/tcp"
        fi
        firewall-cmd --reload > /dev/null || warn "firewalld would not reload"
    elif command -v nft > /dev/null 2>&1 && nft list ruleset 2>/dev/null | grep -q .; then
        warn "this host uses nftables directly, so nothing was changed"
        say "  add yourself, in the chain that accepts inbound traffic:"
        if [ -n "$PANEL_ADDR" ]; then
            say "    ip saddr $PANEL_ADDR tcp dport $AGENT_PORT accept"
        else
            say "    tcp dport $AGENT_PORT accept"
        fi
    else
        say "  no active firewall found, nothing to change"
    fi
else
    say "skipped the firewall, as asked"
fi

# --- Proof -------------------------------------------------------------------
# An unauthenticated 401 proves both halves at once: the agent is up, and it
# refuses a caller that brings no token.

step "Proving the agent answers"

if [ "$HAVE_SYSTEMD" = yes ]; then
    AGENT_OK=no
    i=0
    while [ "$i" -lt 15 ]; do
        CODE=$(curl -sk -o /dev/null -w '%{http_code}' \
            "https://127.0.0.1:$AGENT_PORT/v1/info" 2>/dev/null || true)
        if [ "$CODE" = "401" ]; then
            AGENT_OK=yes
            break
        fi
        i=$((i + 1))
        sleep 1
    done

    if [ "$AGENT_OK" = yes ]; then
        say "  the agent answers on port $AGENT_PORT and refuses a caller with no token"
    else
        warn "the agent did not answer 401 on port $AGENT_PORT in 15 seconds, it said ${CODE:-nothing}"
        warn "read the reason with: journalctl -u jbound-agent -n 50 --no-pager"
    fi
else
    say "  no systemd here, so nothing was started"
    say "  run it yourself with: /usr/local/bin/jbound-agent"
fi

# --- What is left ------------------------------------------------------------

FINGERPRINT=$(openssl x509 -in /etc/jbound-agent/agent.crt -outform der |
    openssl dgst -sha256 -binary | openssl base64 | tr -d '=')

cat <<EOF

Installed. What is left, in the panel:

  1. Open the server record and check it reads:
       transport    agent
       host         $(hostname -f 2>/dev/null || hostname)
       agent port   $AGENT_PORT

  2. Press Test. The panel reports this fingerprint the first time:

       SHA256:$FINGERPRINT

     Approve it. It is stored with the server record, and a host that later
     offers a different one is refused rather than trusted again.

  3. Nothing else. The agent reports the records file itself, and the commands
     it runs stay here, in $ENV_FILE.

Upgrade later by re-running this script. It pulls $REF again, rebuilds and
restarts, and keeps the certificate, so the fingerprint the panel pinned stays
the one this host offers.
EOF
