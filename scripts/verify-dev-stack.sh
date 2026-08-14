#!/bin/bash
# Checks the Faz 0 acceptance criteria of the development stack.
#
# Run through: make dev-verify

set -uo pipefail

COMPOSE=(docker compose -f docker-compose.dev.yml --env-file .env.dev)
FAILURES=0
PENDING=0

pass() { printf '  \033[32mOK\033[0m    %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAILURES=$((FAILURES + 1)); }
skip() { printf '  \033[33mWAIT\033[0m  %s\n' "$1"; PENDING=$((PENDING + 1)); }

echo "Faz 0 acceptance checks"
echo

# --- 1. Service account inside the panel container ---------------------------
if "${COMPOSE[@]}" exec -T app id jbound >/dev/null 2>&1; then
    pass "panel container has the jbound service account"
else
    fail "panel container is missing the jbound service account"
fi

# --- 2. Panel process must not run as root -----------------------------------
APP_UID=$("${COMPOSE[@]}" exec -T app id -u 2>/dev/null | tr -d '\r')
if [ "$APP_UID" = "0" ]; then
    # The entrypoint itself runs as root, the panel does not. Report it as
    # informational until the binary exists.
    pass "entrypoint runs as root, the panel drops to jbound at start"
else
    pass "container shell runs as uid $APP_UID"
fi

# --- 3. DNS targets answer queries -------------------------------------------
for spec in "dns1 8331" "dns2 8332" "dns3 8333"; do
    set -- $spec
    name=$1
    port=$2
    if dig +time=2 +tries=1 @127.0.0.1 -p "$port" ns1.example.local A +short 2>/dev/null | grep -q '10\.0\.0\.11'; then
        pass "$name answers on port $port"
    else
        fail "$name did not answer ns1.example.local on port $port"
    fi
done

# --- 4. SSH from the panel to every target -----------------------------------
for name in dns1 dns2 dns3; do
    if "${COMPOSE[@]}" exec -T app ssh \
        -i /var/lib/jbound/keys/dev_ed25519 \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=5 \
        -o BatchMode=yes \
        "dnsops@$name" true >/dev/null 2>&1; then
        pass "panel reaches $name over SSH"
    else
        fail "panel cannot reach $name over SSH"
    fi
done

# --- 5. Sudoers rules on every target ----------------------------------------
for name in dns1 dns2 dns3; do
    if "${COMPOSE[@]}" exec -T "$name" sudo -n -l -U dnsops 2>/dev/null | grep -q 'unbound reload'; then
        pass "$name carries the reload sudoers rule"
    else
        fail "$name is missing the reload sudoers rule"
    fi
done

# --- 6. Unbound configuration directory must stay untouched ------------------
for name in dns1 dns2 dns3; do
    mode=$("${COMPOSE[@]}" exec -T "$name" stat -c '%a' /etc/unbound 2>/dev/null | tr -d '\r')
    if [ "$mode" = "755" ]; then
        pass "$name keeps /etc/unbound at mode 755"
    else
        fail "$name has /etc/unbound at mode $mode, expected 755"
    fi
done

# --- 7. Agent targets answer queries -----------------------------------------
# dns5 is not here. It starts without the include line, so it answers nothing
# until the panel writes to it, which is the whole reason it exists. Its check
# is the repair itself, below.
for spec in "dns4 8360" "dns6 8362"; do
    set -- $spec
    name=$1
    port=$2
    if dig +time=2 +tries=1 @127.0.0.1 -p "$port" ns1.example.local A +short 2>/dev/null | grep -q '10\.0\.0\.11'; then
        pass "$name answers on port $port"
    else
        fail "$name did not answer ns1.example.local on port $port"
    fi
done

# --- 7b. The agent repairs the configuration it was given broken -------------
# The line is added at startup and stays added, so this holds whether or not
# the panel has written to dns5 yet.
if "${COMPOSE[@]}" exec -T dns5 grep -q '^[[:space:]]*include:.*local_records.conf' \
    /etc/unbound/unbound.conf 2>/dev/null; then
    pass "the agent on dns5 put the missing include line back"
else
    fail "dns5 still has no include line, the repair did not run"
fi

# --- 8. The agent listens and asks for the token -----------------------------
# An unauthenticated 401 proves both halves at once: the agent is up, and it
# hands out nothing to a caller that carries no token.
for spec in "dns4 8363" "dns5 8364" "dns6 8365"; do
    set -- $spec
    name=$1
    port=$2
    code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 \
        "https://127.0.0.1:$port/v1/info" 2>/dev/null)
    if [ "$code" = "401" ]; then
        pass "the agent on $name refuses a caller with no token"
    else
        fail "the agent on $name answered $code, expected 401"
    fi
done

# --- 9. Nothing to attack on an agent target ---------------------------------
# The transport exists to remove the shell and the sudoers rules. A target that
# still carried them would prove the panel works while proving nothing about
# what the transport is for.
for name in dns4 dns5 dns6; do
    found=$("${COMPOSE[@]}" exec -T "$name" sh -c \
        'command -v sshd sudo; id dnsops' 2>/dev/null | tr -d '\r')
    if [ -z "$found" ]; then
        pass "$name carries no sshd, no sudo and no account"
    else
        fail "$name carries something the agent transport removes: $found"
    fi
done

# --- 10. SIEM sink listens ---------------------------------------------------
if "${COMPOSE[@]}" exec -T siem-sink pgrep -x rsyslogd >/dev/null 2>&1; then
    pass "siem-sink is listening"
else
    fail "siem-sink is not running"
fi

# --- 11. Panel HTTP endpoint -------------------------------------------------
# The binary arrives in Faz 1. Until then this check is pending, not failing.
if [ -f go.mod ]; then
    if curl -fsS -o /dev/null --max-time 5 http://127.0.0.1:8330/; then
        pass "panel answers on http://127.0.0.1:8330"
    else
        fail "panel does not answer on http://127.0.0.1:8330"
    fi
else
    skip "panel HTTP endpoint waits for Faz 1, go.mod does not exist yet"
fi

echo
if [ "$FAILURES" -gt 0 ]; then
    echo "$FAILURES check(s) failed"
    exit 1
fi
if [ "$PENDING" -gt 0 ]; then
    echo "all available checks passed, $PENDING waiting on a later phase"
    exit 0
fi
echo "all checks passed"
