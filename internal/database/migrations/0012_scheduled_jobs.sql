-- A DNS record change an operator has left for a chosen time.
--
-- The panel writes a record the moment the form is submitted. This table holds
-- the changes an operator wants applied later: an addition, an edit or a
-- deletion that a background timer runs once, when run_at arrives.
--
-- The change is a fleet.Operation, stored as the JSON the panel already builds
-- for an immediate write, so the scheduled path and the direct path run the
-- same operation. scope with server_id or group_id names the target the same
-- way a live request does.
--
-- A job is tied to its target by a foreign key. A server or a group that is
-- deleted takes its pending jobs with it, because a job with no target has
-- nowhere to run.
--
-- on_conflict is the answer to a question the timer cannot ask: what a
-- scheduled addition does when the name already answers on a server. It is
-- meaningful only for an addition and is ignored for an edit or a deletion.
CREATE TABLE scheduled_jobs (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    kind               TEXT    NOT NULL,
    operation          TEXT    NOT NULL,
    scope              TEXT    NOT NULL,
    server_id          INTEGER REFERENCES servers(id)       ON DELETE CASCADE,
    group_id           INTEGER REFERENCES server_groups(id) ON DELETE CASCADE,
    on_conflict        TEXT    NOT NULL DEFAULT 'fail',
    run_at             TEXT    NOT NULL,
    status             TEXT    NOT NULL DEFAULT 'pending',
    requested_uid      INTEGER NOT NULL,
    requested_username TEXT    NOT NULL,
    result             TEXT    NOT NULL DEFAULT '',
    created_at         TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
    ran_at             TEXT
);

-- The timer reads pending jobs whose time has come, oldest first. The index
-- carries both columns of that query so a full scan is never needed.
CREATE INDEX idx_scheduled_jobs_due ON scheduled_jobs (status, run_at);
