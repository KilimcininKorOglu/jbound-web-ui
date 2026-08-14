package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"unbound-web/internal/auth"
	"unbound-web/internal/logging"
)

// ErrNotFound is returned when a lookup finds no row.
var ErrNotFound = errors.New("not found")

// Sessions stores server side sessions.
type Sessions struct {
	db *sql.DB
}

// NewSessions builds the session store.
func NewSessions(db *sql.DB) *Sessions { return &Sessions{db: db} }

// Create inserts a new session.
func (s *Sessions) Create(ctx context.Context, session auth.Session) error {
	const query = `
INSERT INTO sessions
    (id, uid, username, role, fingerprint, csrf_token,
     last_active, regenerated_at, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := s.db.ExecContext(ctx, query,
		session.ID, session.UID, session.Username, session.Role,
		session.Fingerprint, session.CSRFToken,
		formatTime(session.LastActive),
		formatTime(session.RegeneratedAt),
		formatTime(session.CreatedAt),
	)
	if err != nil {
		return fmt.Errorf("cannot insert the session: %w", err)
	}
	return nil
}

// Get reads one session by identifier.
func (s *Sessions) Get(ctx context.Context, id string) (auth.Session, error) {
	const query = `
SELECT id, uid, username, role, fingerprint, csrf_token,
       last_active, regenerated_at, created_at
  FROM sessions
 WHERE id = ?`

	var (
		session                          auth.Session
		lastActive, regenerated, created string
	)
	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&session.ID, &session.UID, &session.Username, &session.Role,
		&session.Fingerprint, &session.CSRFToken,
		&lastActive, &regenerated, &created,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.Session{}, ErrNotFound
	}
	if err != nil {
		return auth.Session{}, fmt.Errorf("cannot read the session: %w", err)
	}

	// A stored timestamp that will not parse means the row is corrupt. Treating
	// it as the zero time would expire the session silently and hide that.
	for _, field := range []struct {
		raw    string
		target *time.Time
	}{
		{lastActive, &session.LastActive},
		{regenerated, &session.RegeneratedAt},
		{created, &session.CreatedAt},
	} {
		parsed, perr := parseTime(field.raw)
		if perr != nil {
			return auth.Session{}, perr
		}
		*field.target = parsed
	}
	return session, nil
}

// Touch records activity on a session.
func (s *Sessions) Touch(ctx context.Context, id string, at time.Time) error {
	result, err := s.db.ExecContext(ctx,
		"UPDATE sessions SET last_active = ? WHERE id = ?", formatTime(at), id)
	if err != nil {
		return fmt.Errorf("cannot touch the session: %w", err)
	}
	return requireOneRow(result, "session", id)
}

// Rotate gives a live session a new identifier.
//
// One statement rather than a delete followed by an insert. A failure between
// the two would drop a valid session, and the primary key would reject any
// overlap anyway.
func (s *Sessions) Rotate(ctx context.Context, oldID, newID string, at time.Time) error {
	const query = `
UPDATE sessions
   SET id = ?, regenerated_at = ?, last_active = ?
 WHERE id = ?`

	stamp := formatTime(at)
	result, err := s.db.ExecContext(ctx, query, newID, stamp, stamp, oldID)
	if err != nil {
		return fmt.Errorf("cannot rotate the session: %w", err)
	}
	return requireOneRow(result, "session", oldID)
}

// Delete removes one session.
//
// A delete that matched nothing is reported rather than swallowed, because it
// means a sign out left the session alive on the server.
func (s *Sessions) Delete(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("cannot delete the session: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("cannot count the affected rows: %w", err)
	}
	if affected == 0 {
		// The cleanup loop may have swept it a moment earlier, so this does
		// not fail the sign out. The identifier stays out of the line: it is
		// live credential material until the row is gone.
		logging.From(ctx).Warn("a session delete matched no row")
	}
	return nil
}

// ListLive summarises the sessions that are still usable, one row per account.
//
// No identifier leaves this method. A session identifier is the credential the
// browser presents, so a page that named one would be handing it out.
//
// Rows older than the cutoff are left out rather than shown as live. The
// cleanup loop removes them on its own timer, up to ten minutes later, and
// until then they are sessions nobody can use.
func (s *Sessions) ListLive(ctx context.Context, since time.Time) ([]auth.SessionSummary, error) {
	const query = `
SELECT uid, username, role, COUNT(*), MIN(created_at), MAX(last_active)
  FROM sessions
 WHERE last_active >= ?
 GROUP BY uid, username, role
 ORDER BY MAX(last_active) DESC`

	rows, err := s.db.QueryContext(ctx, query, formatTime(since))
	if err != nil {
		return nil, fmt.Errorf("cannot list the sessions: %w", err)
	}
	defer rows.Close()

	var summaries []auth.SessionSummary
	for rows.Next() {
		var (
			summary         auth.SessionSummary
			first, lastSeen string
		)
		if err := rows.Scan(&summary.UID, &summary.Username, &summary.Role,
			&summary.Count, &first, &lastSeen); err != nil {
			return nil, fmt.Errorf("cannot read a session row: %w", err)
		}

		if summary.FirstSeen, err = parseTime(first); err != nil {
			return nil, fmt.Errorf("cannot read the first login of %s: %w", summary.Username, err)
		}
		if summary.LastActive, err = parseTime(lastSeen); err != nil {
			return nil, fmt.Errorf("cannot read the last activity of %s: %w", summary.Username, err)
		}
		summaries = append(summaries, summary)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cannot walk the sessions: %w", err)
	}
	return summaries, nil
}

// DeleteByUIDExcept removes every session of one account but the named one.
//
// The exception is the caller's own session. An administrator who signed the
// attacker out of their own account should not be signed out by the same
// click, because they could not then see whether it worked.
func (s *Sessions) DeleteByUIDExcept(ctx context.Context, uid int, keepID string) (int, error) {
	result, err := s.db.ExecContext(ctx,
		"DELETE FROM sessions WHERE uid = ? AND id <> ?", uid, keepID)
	if err != nil {
		return 0, fmt.Errorf("cannot delete the sessions of uid %d: %w", uid, err)
	}
	return countAffected(result)
}

// DeleteAllExcept removes every session on the panel but the named one.
func (s *Sessions) DeleteAllExcept(ctx context.Context, keepID string) (int, error) {
	result, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE id <> ?", keepID)
	if err != nil {
		return 0, fmt.Errorf("cannot delete the sessions: %w", err)
	}
	return countAffected(result)
}

// countAffected reports how many rows a delete removed.
func countAffected(result sql.Result) (int, error) {
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("cannot count the affected rows: %w", err)
	}
	return int(affected), nil
}

// requireOneRow turns a no op update into an error. An update that matched
// nothing means the row vanished between the read and the write.
func requireOneRow(result sql.Result, kind, id string) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("cannot count the affected rows: %w", err)
	}
	if affected == 0 {
		return fmt.Errorf("%s %s: %w", kind, id, ErrNotFound)
	}
	return nil
}
