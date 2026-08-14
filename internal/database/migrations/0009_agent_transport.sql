-- Lets a server record name an agent.
--
-- The transport column has carried a CHECK of ('ssh') since the first
-- migration, with a comment saying the agent transport would land later. This
-- is later. SQLite cannot alter a CHECK constraint, so the table is rebuilt.
--
-- Two other things are corrected in the same rebuild, because rebuilding a
-- table five others reference is not worth doing twice:
--
--   * records_path defaults to local_records.conf, which is what the code has
--     used since the rename. The old default was unreachable, since every
--     insert passes a path ApplyDefaults has already filled, but a schema that
--     says one thing while the panel does another is a trap for whoever reads
--     it next.
--   * agent_port is added, defaulting to 8443.
--
-- Dropping the old table is what makes this need care. SQLite runs an implicit
-- DELETE for a DROP, which fires every ON DELETE CASCADE pointing at it, and
-- five tables point here. The runner suspends the foreign keys for the whole
-- migration run and asks for a foreign_key_check afterwards, so the rows
-- survive the drop and a rebuild that broke a reference fails the start.
--
-- ssh_user stays NOT NULL with an empty default rather than becoming nullable.
-- An agent server has no account to log in as, and an empty string says that
-- more plainly than a null the read path would have to handle everywhere.

CREATE TABLE servers_new (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    name              TEXT    NOT NULL UNIQUE,
    host              TEXT    NOT NULL,
    ssh_port          INTEGER NOT NULL DEFAULT 22
                              CHECK (ssh_port BETWEEN 1 AND 65535),
    transport         TEXT    NOT NULL DEFAULT 'ssh'
                              CHECK (transport IN ('ssh', 'agent')),
    -- Where the agent listens. Ignored on an ssh server.
    agent_port        INTEGER NOT NULL DEFAULT 8443
                              CHECK (agent_port BETWEEN 1 AND 65535),
    ssh_user          TEXT    NOT NULL DEFAULT '',
    -- Path relative to the data directory. It holds the private key on an ssh
    -- server and the bearer token on an agent one. Neither secret enters this
    -- database, so a database leak does not hand over the fleet.
    ssh_key_path      TEXT    NOT NULL,
    -- What the far end has to prove it is: an authorized_keys line on ssh, the
    -- SHA-256 fingerprint of the TLS certificate on an agent. Empty until an
    -- operator approves it.
    host_key          TEXT    NOT NULL DEFAULT '',
    records_path      TEXT    NOT NULL DEFAULT '/etc/unbound/local_records.conf',
    reload_cmd        TEXT    NOT NULL DEFAULT 'sudo /usr/sbin/service unbound reload',
    status_cmd        TEXT    NOT NULL DEFAULT 'systemctl is-active unbound',
    base64_path       TEXT    NOT NULL DEFAULT '/usr/bin/base64',
    tee_path          TEXT    NOT NULL DEFAULT '/usr/bin/tee',
    mv_path           TEXT    NOT NULL DEFAULT '/bin/mv',
    sha256_path       TEXT    NOT NULL DEFAULT '/usr/bin/sha256sum',
    check_conf_cmd    TEXT    NOT NULL DEFAULT '',
    reload_fallback_cmd TEXT  NOT NULL DEFAULT '',
    restart_cmd       TEXT    NOT NULL DEFAULT '',
    ensure_include_cmd TEXT   NOT NULL DEFAULT '',
    enabled           INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    last_seen_at      TEXT,
    last_error        TEXT    NOT NULL DEFAULT '',
    created_at        TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
    updated_at        TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now'))
);

INSERT INTO servers_new
    (id, name, host, ssh_port, transport, ssh_user, ssh_key_path, host_key,
     records_path, reload_cmd, status_cmd,
     base64_path, tee_path, mv_path, sha256_path,
     check_conf_cmd, reload_fallback_cmd, restart_cmd, ensure_include_cmd,
     enabled, last_seen_at, last_error, created_at, updated_at)
SELECT
     id, name, host, ssh_port, transport, ssh_user, ssh_key_path, host_key,
     records_path, reload_cmd, status_cmd,
     base64_path, tee_path, mv_path, sha256_path,
     check_conf_cmd, reload_fallback_cmd, restart_cmd, ensure_include_cmd,
     enabled, last_seen_at, last_error, created_at, updated_at
FROM servers;

DROP TABLE servers;

ALTER TABLE servers_new RENAME TO servers;

-- The trigger went with the old table.
CREATE TRIGGER IF NOT EXISTS servers_touch_updated_at
AFTER UPDATE ON servers
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE servers
       SET updated_at = strftime('%Y-%m-%d %H:%M:%S', 'now')
     WHERE id = NEW.id;
END;
