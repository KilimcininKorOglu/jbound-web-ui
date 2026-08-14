#!/bin/bash
# Exercises the SSH file transfer protocol from plan.md section 0.6 by hand.
#
# This runs the exact commands the transport layer will run, so a protocol
# problem surfaces before any Go code depends on it.
#
# Run through: make dev-protocol

set -uo pipefail

COMPOSE=(docker compose -f docker-compose.dev.yml --env-file .env.dev)
TARGET=${1:-dns1}
ENTRIES=/etc/unbound/local_records.conf
TMP=/etc/unbound/.local_records.conf.tmp

FAILURES=0
pass() { printf '  \033[32mOK\033[0m    %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAILURES=$((FAILURES + 1)); }

remote() {
    "${COMPOSE[@]}" exec -T app ssh \
        -i /var/lib/jbound/keys/dev_ed25519 \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o BatchMode=yes \
        -o LogLevel=ERROR \
        "dnsops@$TARGET" "$@"
}

echo "SSH transfer protocol checks against $TARGET"
echo

# --- Read --------------------------------------------------------------------
# base64 opens the file itself. A pipeline from cat would report the status of
# base64 alone, so a file it could not open would come back as an empty one.
ENCODED=$(remote "/usr/bin/base64 -w0 $ENTRIES")
if [ -z "$ENCODED" ]; then
    fail "read produced no output"
    exit 1
fi

# Two conditions, both required. base64 -w0 never wraps, so a second line is
# always shell pollution. Checking only the alphabet would let it through,
# because grep matches line by line and the base64 line passes on its own.
ENCODED_LINES=$(printf '%s\n' "$ENCODED" | wc -l | tr -d ' ')
ENCODED_BAD=$(printf '%s\n' "$ENCODED" | grep -cve '^[A-Za-z0-9+/=]*$' || true)
if [ "$ENCODED_LINES" -eq 1 ] && [ "$ENCODED_BAD" -eq 0 ]; then
    pass "read output is a single line of strict base64"
else
    fail "read output is $ENCODED_LINES line(s) with $ENCODED_BAD outside the alphabet"
fi

# Decoded bytes go to a file, never to a shell variable. Command substitution
# strips trailing newlines, which would silently change the file content.
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT
ORIGINAL="$WORK_DIR/original"
printf '%s' "$ENCODED" | base64 -d > "$ORIGINAL"

if grep -q 'local-data:' "$ORIGINAL"; then
    pass "decoded content carries local-data lines"
else
    fail "decoded content has no local-data lines"
fi

# --- Hash agreement ----------------------------------------------------------
REMOTE_HASH=$(remote "sha256sum $ENTRIES" | awk '{print $1}')
LOCAL_HASH=$(printf '%s' "$ENCODED" | base64 -d | shasum -a 256 | awk '{print $1}')
if [ "$REMOTE_HASH" = "$LOCAL_HASH" ]; then
    pass "remote and locally computed SHA-256 agree ($REMOTE_HASH)"
else
    fail "hash mismatch, remote $REMOTE_HASH local $LOCAL_HASH"
fi

# --- Write -------------------------------------------------------------------
# Appends a record, then removes it again, so the target ends where it started.
MARKER='local-data: "protocol-check.example.local. A 10.0.0.250"'
MODIFIED="$WORK_DIR/modified"
cp "$ORIGINAL" "$MODIFIED"
printf '%s\n' "$MARKER" >> "$MODIFIED"
NEW_B64=$(base64 < "$MODIFIED" | tr -d '\n')

# The digest of the temporary file decides whether it is moved into place.
# Joining tee and mv with && would gate the move on the status of tee, and tee
# writes a stream that was cut short just as happily as a whole one.
WRITE_SUM=$(printf '%s' "$NEW_B64" | remote "/usr/bin/base64 -d | sudo /usr/bin/tee $TMP > /dev/null; /usr/bin/sha256sum $TMP" | awk '{print $1}')
EXPECT_SUM=$(shasum -a 256 < "$MODIFIED" | awk '{print $1}')

if [ "$WRITE_SUM" = "$EXPECT_SUM" ]; then
    pass "temporary file matches what was sent ($WRITE_SUM)"
else
    fail "temporary file hashes $WRITE_SUM, expected $EXPECT_SUM"
fi

if [ "$WRITE_SUM" = "$EXPECT_SUM" ] && remote "sudo /usr/bin/mv $TMP $ENTRIES"; then
    pass "write through tee and mv succeeded"
else
    fail "write through tee and mv failed"
fi

if remote "/usr/bin/base64 -w0 $ENTRIES" | base64 -d | grep -q 'protocol-check'; then
    pass "written record is present on the target"
else
    fail "written record is missing on the target"
fi

# --- Ownership and permissions must be unchanged -----------------------------
STAT=$(remote "stat -c '%a %U:%G' $ENTRIES" | tr -d '\r')
if [ "$STAT" = "644 root:root" ]; then
    pass "records file kept mode 644 and owner root:root"
else
    fail "records file is now '$STAT', expected '644 root:root'"
fi

DIR_MODE=$(remote "stat -c '%a' /etc/unbound" | tr -d '\r')
if [ "$DIR_MODE" = "755" ]; then
    pass "/etc/unbound kept mode 755"
else
    fail "/etc/unbound is now $DIR_MODE, expected 755"
fi

# --- Reload ------------------------------------------------------------------
if remote "sudo /usr/sbin/service unbound reload" >/dev/null 2>&1; then
    pass "sudo service unbound reload succeeded"
else
    fail "sudo service unbound reload failed"
fi

# --- Restore -----------------------------------------------------------------
RESTORE_B64=$(base64 < "$ORIGINAL" | tr -d '\n')
RESTORE_SUM=$(printf '%s' "$RESTORE_B64" | remote "/usr/bin/base64 -d | sudo /usr/bin/tee $TMP > /dev/null; /usr/bin/sha256sum $TMP" | awk '{print $1}')

if [ "$RESTORE_SUM" = "$REMOTE_HASH" ] && remote "sudo /usr/bin/mv $TMP $ENTRIES"; then
    RESTORED_HASH=$(remote "sha256sum $ENTRIES" | awk '{print $1}')
    if [ "$RESTORED_HASH" = "$REMOTE_HASH" ]; then
        pass "target restored to its original content"
    else
        fail "restore left a different hash, $RESTORED_HASH instead of $REMOTE_HASH"
    fi
else
    fail "restore write failed, the target is left modified"
fi

echo
if [ "$FAILURES" -gt 0 ]; then
    echo "$FAILURES check(s) failed"
    exit 1
fi
echo "all protocol checks passed"
