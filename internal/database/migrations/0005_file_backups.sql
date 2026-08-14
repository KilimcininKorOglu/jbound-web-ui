-- The host entries file of each server as it was before the last write.
--
-- A write replaces the remote file in one move, so the content that was there
-- is gone the moment it lands. A wrong edit or a delete on a group therefore
-- had no way back other than typing the change again on every machine.
--
-- One row per server, holding the last known good copy rather than a history.
-- What an operator wants back is the change they just made, and a history would
-- need a growth bound, a pruning rule and a listing of its own.
--
-- The content is DNS records rather than a secret. The same lines already sit
-- in record_cache.

CREATE TABLE IF NOT EXISTS file_backups (
    server_id INTEGER PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
    content   TEXT NOT NULL,
    sha256    TEXT NOT NULL,
    saved_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now'))
);
