#!/bin/bash
# Creates the panel test accounts inside the development container.
#
# The matrix covers every branch of the account policy:
#
#   root         uid 0     -> accepted, admin role
#   dnsadmin     sudo      -> accepted, admin role
#   dnsuser      plain     -> accepted, user role
#   svcacct      nologin   -> rejected by the shell rule
#   lowuid       uid 500   -> rejected by MIN_UID
#   lockeduser   locked    -> rejected by pam_authenticate
#   expireduser  expired   -> rejected by pam_acct_mgmt
#   nopwuser     no passwd -> rejected by the empty password rule
#
# Passwords come from the environment. They are never baked into the image.

set -euo pipefail

log() { printf '[testusers] %s\n' "$*"; }

create_account() {
    local name=$1 uid=$2 shell=$3
    if id -u "$name" >/dev/null 2>&1; then
        return 0
    fi
    useradd --uid "$uid" --create-home --shell "$shell" "$name"
    log "created $name (uid $uid)"
}

set_password() {
    local name=$1 password=$2
    if [ -z "$password" ]; then
        log "error: no password supplied for $name"
        log "copy .env.dev.example to .env.dev and fill in every value"
        exit 1
    fi
    printf '%s:%s\n' "$name" "$password" | chpasswd
}

create_account dnsadmin    1001 /bin/bash
create_account dnsuser     1002 /bin/bash
create_account svcacct     1003 /usr/sbin/nologin
create_account lowuid       500 /bin/bash
create_account lockeduser  1004 /bin/bash
create_account expireduser 1005 /bin/bash
create_account nopwuser    1006 /bin/bash

usermod -aG sudo dnsadmin

set_password root        "${DEV_PASSWORD_ROOT:-}"
set_password dnsadmin    "${DEV_PASSWORD_DNSADMIN:-}"
set_password dnsuser     "${DEV_PASSWORD_DNSUSER:-}"
set_password svcacct     "${DEV_PASSWORD_SVCACCT:-}"
set_password lowuid      "${DEV_PASSWORD_LOWUID:-}"
set_password lockeduser  "${DEV_PASSWORD_LOCKEDUSER:-}"
set_password expireduser "${DEV_PASSWORD_EXPIREDUSER:-}"

# Locked after the password is set, so pam_authenticate is the step that
# rejects this account.
passwd -l lockeduser >/dev/null
log "locked lockeduser"

# Expired on 1970-01-02, so pam_acct_mgmt is the step that rejects it. The
# password itself stays valid, which is what separates this case from the
# locked account.
chage -E 1 expireduser
log "expired expireduser"

# Empty password field. Debian common-auth carries nullok, so PAM would accept
# an empty password here. The panel must reject it before the helper runs.
passwd -d nopwuser >/dev/null
log "cleared the password of nopwuser"

log "test accounts ready"
