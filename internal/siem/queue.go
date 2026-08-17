package siem

import (
	"context"
	"time"

	"jbound/internal/audit"
	"jbound/internal/logging"
)

// batchSize is how many rows one round takes.
//
// A round holds the receiver connection for as long as it runs, so a bound
// keeps a panel catching up after a long outage from starving the rows arriving
// while it does. What is left is picked up by the next round immediately.
const batchSize = 200

// sweepInterval is how often the queue looks without being told to.
//
// It is the recovery path rather than the normal one: an event wakes the queue
// the moment it is written. This is what gets a backlog moving again after the
// receiver comes back, and what covers a wake-up that was dropped because a
// round was already running.
const sweepInterval = 30 * time.Second

// RowReader reads the audit rows a receiver has not been given yet.
type RowReader interface {
	After(ctx context.Context, cursor int64, limit int) ([]audit.Row, error)
}

// CursorStore remembers how far the receiver has been caught up.
type CursorStore interface {
	Read(ctx context.Context) (int64, error)
	Write(ctx context.Context, lastSent int64) error
	NewestAuditID(ctx context.Context) (int64, error)
	Pending(ctx context.Context, cursor int64) (int, error)
}

// Queue sends the audit trail to the receiver, in order, and remembers where it
// got to.
//
// The database is the queue. Every audit row is already durable before this
// runs, so a receiver that is down costs nothing but a growing backlog, and one
// that comes back is given exactly the rows it missed. Nothing is held in
// memory that a restart would lose.
type Queue struct {
	rows   RowReader
	cursor CursorStore
	sender *Sender

	panelHost string

	// enabled is the mirror switch. It is read per round, so an operator can
	// stop a flow to a noisy receiver without a restart.
	enabled func() bool

	// wake carries one pending wake-up. A buffer of one is all that is needed:
	// two writes arriving while a round runs mean the same thing as one, which
	// is that there is something to read afterwards.
	wake chan struct{}
}

// NewQueue builds the queue.
func NewQueue(rows RowReader, cursor CursorStore, sender *Sender,
	panelHost string, enabled func() bool) *Queue {

	return &Queue{
		rows:      rows,
		cursor:    cursor,
		sender:    sender,
		panelHost: panelHost,
		enabled:   enabled,
		wake:      make(chan struct{}, 1),
	}
}

// Notify says there may be something to send. It never blocks, because the
// caller is the audit write path and an audit entry must not wait on a
// receiver.
func (q *Queue) Notify() {
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

// RunLoop sends what is owed until the context is cancelled.
func (q *Queue) RunLoop(ctx context.Context) {
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()

	for {
		// A round runs before the first wait, so a panel that restarts with a
		// backlog starts clearing it rather than waiting for the next event.
		q.Drain(ctx)

		select {
		case <-ctx.Done():
			return
		case <-q.wake:
		case <-ticker.C:
		}
	}
}

// Drain sends every row the receiver is owed, oldest first.
//
// It stops at the first row that could not be sent and leaves the cursor where
// that row begins, so the next round starts there. Skipping it and carrying on
// would put a hole in the receiver's copy of the trail that nothing later
// fills.
func (q *Queue) Drain(ctx context.Context) {
	if !q.sender.Configured() {
		return
	}

	for {
		sent, more, err := q.round(ctx)
		if err != nil {
			logging.From(ctx).Error("cannot forward the audit trail", "error", err)
			return
		}
		if !more || sent == 0 {
			return
		}
	}
}

// round sends up to one batch. It reports how many rows moved and whether more
// were waiting behind them.
func (q *Queue) round(ctx context.Context) (int, bool, error) {
	cursor, err := q.start(ctx)
	if err != nil {
		return 0, false, err
	}

	rows, err := q.rows.After(ctx, cursor, batchSize)
	if err != nil {
		return 0, false, err
	}
	if len(rows) == 0 {
		return 0, false, nil
	}

	forwarding := q.enabled()

	sent := 0
	for _, row := range rows {
		if forwarding || alwaysForwarded(row.Action) {
			if err := q.send(row); err != nil {
				// The cursor stops before this row. Reporting the failure here
				// rather than returning it keeps the caller from treating a
				// receiver that is down as a reason to stop trying.
				logging.From(ctx).Warn("the receiver did not take an audit event",
					"id", row.ID, "action", row.Action, "error", err)
				break
			}
		}
		cursor = row.ID
		sent++
	}

	if sent > 0 {
		if err := q.cursor.Write(ctx, cursor); err != nil {
			return sent, false, err
		}
	}
	return sent, len(rows) == batchSize, nil
}

// send renders one row and hands it to the sender.
func (q *Queue) send(row audit.Row) error {
	return q.sender.Send(row.Action, FormatRow(row, q.panelHost), row.CreatedAt)
}

// start returns the cursor to read from, placing it at the present the first
// time a receiver is configured.
//
// A panel that has been running for months has a trail to match. Starting at
// zero would empty all of it into a receiver that asked for none of it, and the
// operator who configured the receiver today wants what happens from today.
func (q *Queue) start(ctx context.Context) (int64, error) {
	cursor, err := q.cursor.Read(ctx)
	if err != nil {
		return 0, err
	}
	if cursor > 0 {
		return cursor, nil
	}

	newest, err := q.cursor.NewestAuditID(ctx)
	if err != nil {
		return 0, err
	}
	if newest == 0 {
		return 0, nil
	}
	if err := q.cursor.Write(ctx, newest); err != nil {
		return 0, err
	}
	return newest, nil
}

// Pending reports how many rows the receiver has not been given.
func (q *Queue) Pending(ctx context.Context) (int, error) {
	cursor, err := q.cursor.Read(ctx)
	if err != nil {
		return 0, err
	}
	return q.cursor.Pending(ctx, cursor)
}

// alwaysForwarded reports the actions that go out even with the mirror off.
//
// The entry that turns forwarding off is the one a receiver cannot afford to
// miss, because everything after it is silence rather than quiet.
func alwaysForwarded(action string) bool {
	return action == audit.ActionSIEMConfig
}
