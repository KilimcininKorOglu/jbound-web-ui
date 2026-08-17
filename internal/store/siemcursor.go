package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// SIEMCursor remembers how far the receiver has been caught up.
//
// It is one number: the identifier of the last audit row that reached the
// receiver. Everything after it is still owed, which is what makes a receiver
// outage recoverable rather than a hole in the trail.
type SIEMCursor struct {
	db *sql.DB
}

// NewSIEMCursor builds the cursor store.
func NewSIEMCursor(db *sql.DB) *SIEMCursor { return &SIEMCursor{db: db} }

// Read returns the last identifier that reached the receiver.
//
// A panel that has never forwarded anything has no row, and zero is what that
// reads as. The sender turns that into "start at the newest row" rather than
// "send the whole history", because the decision of where to begin belongs to
// the sender and not to the schema.
func (c *SIEMCursor) Read(ctx context.Context) (int64, error) {
	var last int64
	err := c.db.QueryRowContext(ctx,
		"SELECT last_sent_id FROM siem_cursor WHERE id = 1").Scan(&last)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("cannot read the SIEM cursor: %w", err)
	}
	return last, nil
}

// Write records how far the receiver has been caught up.
//
// It never moves backwards. A caller that passes an older identifier is a
// caller that read a stale value, and honouring it would send rows the receiver
// already holds.
func (c *SIEMCursor) Write(ctx context.Context, lastSent int64) error {
	_, err := c.db.ExecContext(ctx, `
INSERT INTO siem_cursor (id, last_sent_id)
VALUES (1, ?)
ON CONFLICT (id) DO UPDATE
   SET last_sent_id = MAX(excluded.last_sent_id, siem_cursor.last_sent_id),
       updated_at   = strftime('%Y-%m-%d %H:%M:%S', 'now')`, lastSent)
	if err != nil {
		return fmt.Errorf("cannot write the SIEM cursor: %w", err)
	}
	return nil
}

// NewestAuditID returns the identifier of the latest audit row, or zero when
// there are none.
//
// The sender asks for it once, to start at the present rather than at the
// beginning of a trail that may be months long.
func (c *SIEMCursor) NewestAuditID(ctx context.Context) (int64, error) {
	var newest int64
	err := c.db.QueryRowContext(ctx,
		"SELECT COALESCE(MAX(id), 0) FROM audit_logs").Scan(&newest)
	if err != nil {
		return 0, fmt.Errorf("cannot read the newest audit identifier: %w", err)
	}
	return newest, nil
}

// Pending counts the rows the receiver has not been given yet.
//
// The SIEM page shows it, because an operator whose receiver is down needs to
// see the backlog growing rather than read that everything is fine.
func (c *SIEMCursor) Pending(ctx context.Context, cursor int64) (int, error) {
	var pending int
	err := c.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM audit_logs WHERE id > ?", cursor).Scan(&pending)
	if err != nil {
		return 0, fmt.Errorf("cannot count the pending audit rows: %w", err)
	}
	return pending, nil
}
