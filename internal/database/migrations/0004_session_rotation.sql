-- The identifier a session carried before its last rotation.
--
-- A live session gets a new identifier every few minutes. The panel makes
-- overlapping requests by design, so a second request can still be carrying the
-- previous identifier when the first one has already replaced it. Without a
-- record of what the identifier was, that request looks like an unknown session
-- and signs the user out.
--
-- Both columns stay NULL until the first rotation, and a session that has never
-- rotated behaves exactly as it did before this migration.

ALTER TABLE sessions ADD COLUMN previous_id TEXT;
ALTER TABLE sessions ADD COLUMN rotated_at TEXT;

CREATE INDEX IF NOT EXISTS idx_sessions_previous_id ON sessions (previous_id);
