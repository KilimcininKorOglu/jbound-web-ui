-- How far the SIEM receiver has been caught up.
--
-- The panel forwards its audit trail itself rather than handing it to a local
-- syslog daemon, and this is what makes a receiver outage recoverable. Every
-- audit row already has a monotonic id, so one number is enough to say which
-- rows have gone out and which have not. A receiver that comes back gets the
-- rows it missed, in order.
--
-- Its own table rather than a row in settings, because settings is what the
-- operator edits on the settings page and this is not a value anybody chooses.
--
-- One row, forced by the CHECK. There is one receiver, and a second row would
-- be a second answer to a question with one.
CREATE TABLE IF NOT EXISTS siem_cursor (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    last_sent_id INTEGER NOT NULL DEFAULT 0,
    updated_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now'))
);
