-- Initial schema for the JBound panel.
--
-- There is no users table. Authentication goes through PAM against the local
-- accounts of the panel host, so passwords never reach this database.
--
-- Every timestamp column stores UTC in 'YYYY-MM-DD HH:MM:SS' form, which is
-- what SQLite's datetime('now') produces. The view layer converts to local
-- time. Mixing the two would make audit trails unreadable.

-- ---------------------------------------------------------------------------
-- Managed DNS servers
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS servers (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    name              TEXT    NOT NULL UNIQUE,
    host              TEXT    NOT NULL,
    ssh_port          INTEGER NOT NULL DEFAULT 22
                              CHECK (ssh_port BETWEEN 1 AND 65535),
    -- Only ssh exists in version one. The agent transport lands later and
    -- fills the same interface, so the column is ready for it.
    transport         TEXT    NOT NULL DEFAULT 'ssh'
                              CHECK (transport IN ('ssh')),
    ssh_user          TEXT    NOT NULL,
    -- Path relative to the data directory. The key itself never enters the
    -- database, so a database leak does not hand over the fleet.
    ssh_key_path      TEXT    NOT NULL,
    -- Pinned host key line. Empty until an operator approves the fingerprint.
    host_key          TEXT    NOT NULL DEFAULT '',
    host_entries_path TEXT    NOT NULL DEFAULT '/etc/unbound/host_entries.conf',
    reload_cmd        TEXT    NOT NULL DEFAULT 'sudo /usr/sbin/service unbound reload',
    status_cmd        TEXT    NOT NULL DEFAULT 'systemctl is-active unbound',
    cat_path          TEXT    NOT NULL DEFAULT '/bin/cat',
    base64_path       TEXT    NOT NULL DEFAULT '/usr/bin/base64',
    tee_path          TEXT    NOT NULL DEFAULT '/usr/bin/tee',
    mv_path           TEXT    NOT NULL DEFAULT '/bin/mv',
    enabled           INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    last_seen_at      TEXT,
    last_error        TEXT    NOT NULL DEFAULT '',
    created_at        TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
    updated_at        TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now'))
);

CREATE TRIGGER IF NOT EXISTS servers_touch_updated_at
AFTER UPDATE ON servers
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE servers
       SET updated_at = strftime('%Y-%m-%d %H:%M:%S', 'now')
     WHERE id = NEW.id;
END;

-- ---------------------------------------------------------------------------
-- Server groups
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS server_groups (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    description TEXT    NOT NULL DEFAULT '',
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
    updated_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now'))
);

CREATE TRIGGER IF NOT EXISTS server_groups_touch_updated_at
AFTER UPDATE ON server_groups
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE server_groups
       SET updated_at = strftime('%Y-%m-%d %H:%M:%S', 'now')
     WHERE id = NEW.id;
END;

-- A server may belong to several groups, so redundant resolvers can be
-- targeted together while still appearing in a narrower group.
CREATE TABLE IF NOT EXISTS server_group_members (
    group_id  INTEGER NOT NULL REFERENCES server_groups(id) ON DELETE CASCADE,
    server_id INTEGER NOT NULL REFERENCES servers(id)       ON DELETE CASCADE,
    PRIMARY KEY (group_id, server_id)
);

CREATE INDEX IF NOT EXISTS idx_group_members_server
    ON server_group_members (server_id);

-- ---------------------------------------------------------------------------
-- Per server state
-- ---------------------------------------------------------------------------
-- applied_sha256 records what the resolver last loaded, per server.
-- A difference against file_sha256 means the server carries unapplied changes.
CREATE TABLE IF NOT EXISTS server_state (
    server_id      INTEGER PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
    file_sha256    TEXT    NOT NULL DEFAULT '',
    applied_sha256 TEXT    NOT NULL DEFAULT '',
    fetched_at     TEXT,
    reachable      INTEGER NOT NULL DEFAULT 0 CHECK (reachable IN (0, 1)),
    unbound_active INTEGER NOT NULL DEFAULT 0 CHECK (unbound_active IN (0, 1)),
    record_count   INTEGER NOT NULL DEFAULT 0,
    last_error     TEXT    NOT NULL DEFAULT ''
);

-- ---------------------------------------------------------------------------
-- Record cache
-- ---------------------------------------------------------------------------
-- A read cache only. The host entries file on each server stays authoritative,
-- so writes go to the file first and the cache is refilled afterwards.
CREATE TABLE IF NOT EXISTS record_cache (
    server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    line      INTEGER NOT NULL,
    fqdn      TEXT    NOT NULL,
    type      TEXT    NOT NULL,
    value     TEXT    NOT NULL,
    priority  INTEGER NOT NULL DEFAULT 0,
    raw       TEXT    NOT NULL,
    PRIMARY KEY (server_id, line)
);

CREATE INDEX IF NOT EXISTS idx_record_cache_fqdn  ON record_cache (server_id, fqdn);
CREATE INDEX IF NOT EXISTS idx_record_cache_type  ON record_cache (server_id, type);
-- Drives the diff view, which groups identical records across servers.
CREATE INDEX IF NOT EXISTS idx_record_cache_tuple ON record_cache (fqdn, type, value);

-- ---------------------------------------------------------------------------
-- Audit log
-- ---------------------------------------------------------------------------
-- user_id holds a POSIX uid. server_id stays NULL for actions that target no
-- server. Audit rows outlive the server they refer to, so the reference is
-- cleared instead of cascading.
CREATE TABLE IF NOT EXISTS audit_logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    username   TEXT    NOT NULL,
    server_id  INTEGER REFERENCES servers(id) ON DELETE SET NULL,
    action     TEXT    NOT NULL,
    details    TEXT    NOT NULL DEFAULT '',
    ip_address TEXT    NOT NULL DEFAULT '',
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_audit_user_id    ON audit_logs (user_id);
CREATE INDEX IF NOT EXISTS idx_audit_action     ON audit_logs (action);
CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_logs (created_at);
CREATE INDEX IF NOT EXISTS idx_audit_server_id  ON audit_logs (server_id);

-- ---------------------------------------------------------------------------
-- Login attempts
-- ---------------------------------------------------------------------------
-- Rate limiting keys on the address: ten
-- attempts per fifteen minutes.
CREATE TABLE IF NOT EXISTS login_attempts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address   TEXT    NOT NULL,
    username     TEXT    NOT NULL DEFAULT '',
    attempted_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_time
    ON login_attempts (ip_address, attempted_at);

-- ---------------------------------------------------------------------------
-- Sessions
-- ---------------------------------------------------------------------------
-- Server side sessions. The browser only carries the identifier in a cookie.
-- No password or PAM handle is stored here.
CREATE TABLE IF NOT EXISTS sessions (
    id              TEXT    PRIMARY KEY,
    uid             INTEGER NOT NULL,
    username        TEXT    NOT NULL,
    role            TEXT    NOT NULL CHECK (role IN ('admin', 'user')),
    fingerprint     TEXT    NOT NULL,
    csrf_token      TEXT    NOT NULL,
    last_active     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
    regenerated_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_sessions_last_active ON sessions (last_active);
