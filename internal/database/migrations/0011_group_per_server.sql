-- Gives every server a single group, and every group its own source server.
--
-- Membership was a many to many table, so one server could sit in several
-- groups. That made two things impossible to state. A record could not belong
-- to a group, because the file a server holds would have been the union of
-- every group it was in, and deleting a line would have had to ask the other
-- groups first. And the reference a synchronisation copies from was a single
-- panel wide setting, which nothing tied to the group being synchronised: a
-- mirror could overwrite one group with another group's records.
--
-- Both columns are nullable with a NULL default, which is the one shape SQLite
-- accepts on ALTER TABLE ADD COLUMN with a REFERENCES clause. No table is
-- rebuilt here.
--
-- A server that sat in several groups keeps the one with the smallest id. The
-- memberships that drop are written to the audit trail rather than only to a
-- log line, because the trail survives a restart, reaches the SIEM, and is
-- where an operator looks for what changed.

ALTER TABLE servers
    ADD COLUMN group_id INTEGER REFERENCES server_groups(id) ON DELETE SET NULL;

ALTER TABLE server_groups
    ADD COLUMN source_server_id INTEGER REFERENCES servers(id) ON DELETE SET NULL;

UPDATE servers
   SET group_id = (SELECT MIN(m.group_id)
                     FROM server_group_members m
                    WHERE m.server_id = servers.id);

INSERT INTO audit_logs (user_id, username, server_id, action, details, ip_address)
SELECT 0, 'system', m.server_id, 'group_collapse',
       'Server ' || s.name || ' left group #' || m.group_id ||
       ': a server now belongs to a single group',
       'unknown'
  FROM server_group_members m
  JOIN servers s ON s.id = m.server_id
 WHERE s.group_id IS NULL OR m.group_id <> s.group_id
 ORDER BY m.server_id, m.group_id;

-- The old panel wide source becomes the source of its own group, and of no
-- other. A source that ends up in no group leaves every group without one,
-- which is what stops a mirror until an operator names a reference.
UPDATE server_groups
   SET source_server_id = (
       SELECT s.id
         FROM servers s
        WHERE s.group_id = server_groups.id
          AND s.id = (SELECT CAST(value AS INTEGER)
                        FROM settings
                       WHERE key = 'source_server_id'));

DELETE FROM settings WHERE key = 'source_server_id';

DROP INDEX IF EXISTS idx_group_members_server;
DROP TABLE server_group_members;

CREATE INDEX IF NOT EXISTS idx_servers_group ON servers (group_id);
