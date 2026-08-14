package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"unbound-web/internal/auth"
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
		slog.Warn("a session delete matched no row")
	}
	return nil
}

// DeleteByUID removes every session of one account.
func (s *Sessions) DeleteByUID(ctx context.Context, uid int) error {
	if _, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE uid = ?", uid); err != nil {
		return fmt.Errorf("cannot delete the sessions of uid %d: %w", uid, err)
	}
	return nil
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
