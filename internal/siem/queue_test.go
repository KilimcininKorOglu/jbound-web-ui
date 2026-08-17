package siem

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"jbound/internal/audit"
)

// fakeRows is an audit trail in memory, read the way the store reads it.
type fakeRows struct {
	rows []audit.Row
	err  error
}

func (r *fakeRows) After(_ context.Context, cursor int64, limit int) ([]audit.Row, error) {
	if r.err != nil {
		return nil, r.err
	}

	var out []audit.Row
	for _, row := range r.rows {
		if row.ID > cursor {
			out = append(out, row)
		}
		if len(out) == limit {
			break
		}
	}
	return out, nil
}

// fakeCursor is the cursor store, which refuses to move backwards the way the
// real one does.
type fakeCursor struct {
	last   int64
	newest int64
	writes int
}

func (c *fakeCursor) Read(context.Context) (int64, error) { return c.last, nil }

func (c *fakeCursor) Write(_ context.Context, lastSent int64) error {
	c.writes++
	if lastSent > c.last {
		c.last = lastSent
	}
	return nil
}

func (c *fakeCursor) NewestAuditID(context.Context) (int64, error) { return c.newest, nil }

func (c *fakeCursor) Pending(_ context.Context, cursor int64) (int, error) {
	return int(c.newest - cursor), nil
}

// trail builds n rows, oldest first, all of the same action unless named.
func trail(n int, actions ...string) []audit.Row {
	var rows []audit.Row
	for i := range n {
		action := audit.ActionLogin
		if i < len(actions) {
			action = actions[i]
		}
		rows = append(rows, audit.Row{
			ID:        int64(i + 1),
			UID:       1000,
			Username:  "dnsadmin",
			Action:    action,
			Details:   "row " + action,
			IPAddress: "192.0.2.1",
			CreatedAt: time.Date(2026, 3, 1, 12, i, 0, 0, time.UTC),
		})
	}
	return rows
}

// queueOver wires a queue over the given trail and a sender writing to a socket
// the test controls.
func queueOver(rows []audit.Row, cursor *fakeCursor,
	enabled bool) (*Queue, *fakeRows, *fakeSocket) {

	reader := &fakeRows{rows: rows}
	socket := &fakeSocket{}
	sender, _ := senderOver(socket, ProtocolTCP, "siem.example", 514)

	queue := NewQueue(reader, cursor, sender, "panel.example",
		func() bool { return enabled })
	return queue, reader, socket
}

func TestEveryRowGoesOutOnceAndTheCursorFollows(t *testing.T) {
	cursor := &fakeCursor{last: 0, newest: 3}
	queue, _, socket := queueOver(trail(3), cursor, true)

	// The cursor starts at the newest row, so nothing is owed yet.
	queue.Drain(context.Background())
	if len(socket.lines()) != 0 {
		t.Fatalf("a first run sent %d rows of history", len(socket.lines()))
	}

	// Now three more arrive behind it.
	reader := &fakeRows{rows: append(trail(3), trail(6)[3:]...)}
	queue.rows = reader
	cursor.newest = 6

	queue.Drain(context.Background())
	if got := len(socket.lines()); got != 3 {
		t.Fatalf("got %d rows, want 3", got)
	}
	if cursor.last != 6 {
		t.Errorf("cursor = %d, want 6", cursor.last)
	}

	// A second drain has nothing to do.
	queue.Drain(context.Background())
	if got := len(socket.lines()); got != 3 {
		t.Errorf("a second drain sent %d rows in total, want 3", got)
	}
}

func TestForwardingStartsAtThePresentRatherThanTheBeginning(t *testing.T) {
	// A panel that has been running for months has a trail to match. Enabling a
	// receiver today means what happens from today.
	cursor := &fakeCursor{last: 0, newest: 5}
	queue, _, socket := queueOver(trail(5), cursor, true)

	queue.Drain(context.Background())

	if len(socket.lines()) != 0 {
		t.Errorf("the history was emptied into the receiver: %d rows",
			len(socket.lines()))
	}
	if cursor.last != 5 {
		t.Errorf("cursor = %d, want it placed at the newest row", cursor.last)
	}
}

func TestARowTheReceiverRefusedIsSentAgainLater(t *testing.T) {
	// The whole reason the cursor exists. A receiver that is down costs a
	// backlog rather than a hole in its copy of the trail.
	cursor := &fakeCursor{last: 0, newest: 0}
	queue, _, socket := queueOver(trail(3), cursor, true)

	// The receiver refuses every connection for now.
	queue.sender.dial = func(string, string) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}

	queue.Drain(context.Background())
	if cursor.last != 0 {
		t.Fatalf("cursor = %d, want it to stay before the first refused row", cursor.last)
	}

	// It comes back.
	queue.sender.dial = func(string, string) (net.Conn, error) { return socket, nil }

	queue.Drain(context.Background())
	lines := socket.lines()
	if len(lines) != 3 {
		t.Fatalf("got %d rows after the receiver came back, want 3", len(lines))
	}
	if cursor.last != 3 {
		t.Errorf("cursor = %d, want 3", cursor.last)
	}

	// In order, oldest first, which is the only order a trail reads in.
	for i, want := range []string{"12:00:00Z", "12:01:00Z", "12:02:00Z"} {
		if !strings.Contains(lines[i], want) {
			t.Errorf("line %d is %q, want the event at %s", i, lines[i], want)
		}
	}
}

func TestAFailureInTheMiddleStopsTheCursorThere(t *testing.T) {
	// Skipping the row that failed and carrying on would leave a gap nothing
	// later fills, and the receiver would have no way to know.
	cursor := &fakeCursor{last: 0, newest: 0}
	queue, _, socket := queueOver(trail(4), cursor, true)

	// The receiver takes the first two rows and then goes away. The third row
	// fails, the retry on a fresh connection fails too.
	socket.failFrom = 3

	queue.Drain(context.Background())

	if got := len(socket.lines()); got != 2 {
		t.Fatalf("got %d rows through, want 2", got)
	}
	if cursor.last != 2 {
		t.Errorf("cursor = %d, want 2 so the third row is sent again", cursor.last)
	}
}

func TestTheMirrorSwitchStopsTheFlowAndTheCursorKeepsUp(t *testing.T) {
	// Off means off. Re-enabling it must not empty everything that happened in
	// between into the receiver, because the operator turned it off on purpose.
	cursor := &fakeCursor{last: 0, newest: 0}
	queue, _, socket := queueOver(trail(3), cursor, false)

	queue.Drain(context.Background())

	if len(socket.lines()) != 0 {
		t.Errorf("a disabled mirror sent %d rows", len(socket.lines()))
	}
	if cursor.last != 3 {
		t.Errorf("cursor = %d, want it to keep up with the trail", cursor.last)
	}
}

func TestTheEntryThatTurnsForwardingOffStillGoesOut(t *testing.T) {
	// Everything after it is silence rather than quiet, and a receiver that was
	// not told cannot tell the two apart.
	// The switch is reachable from two pages, and each writes its own action.
	for _, action := range []string{audit.ActionSIEMConfig, audit.ActionSettingsUpdate} {
		cursor := &fakeCursor{last: 0, newest: 0}
		queue, _, socket := queueOver(
			trail(3, audit.ActionLogin, action, audit.ActionLogin), cursor, false)

		queue.Drain(context.Background())

		lines := socket.lines()
		if len(lines) != 1 {
			t.Fatalf("%s: got %d rows, want the configuration change alone",
				action, len(lines))
		}
		if !strings.Contains(lines[0], action) {
			t.Errorf("%s: the wrong row went out: %q", action, lines[0])
		}
	}
}

func TestNothingIsReadWithoutAReceiver(t *testing.T) {
	// A panel with no receiver must not query the trail on every audit entry.
	cursor := &fakeCursor{last: 0, newest: 0}
	reader := &fakeRows{rows: trail(3), err: errors.New("After must not be called")}
	socket := &fakeSocket{}
	sender, _ := senderOver(socket, ProtocolOff, "", 514)

	queue := NewQueue(reader, cursor, sender, "panel.example", func() bool { return true })
	queue.Drain(context.Background())

	if cursor.writes != 0 {
		t.Errorf("the cursor was written %d times with no receiver", cursor.writes)
	}
}

func TestABacklogLargerThanOneRoundIsCleared(t *testing.T) {
	// One round is bounded so a long catch-up does not starve the rows arriving
	// while it runs. What is left has to be picked up without waiting for the
	// next event.
	cursor := &fakeCursor{last: 0, newest: 0}
	queue, _, socket := queueOver(trail(batchSize+5), cursor, true)

	queue.Drain(context.Background())

	if got := len(socket.lines()); got != batchSize+5 {
		t.Errorf("got %d rows, want %d", got, batchSize+5)
	}
	if cursor.last != int64(batchSize+5) {
		t.Errorf("cursor = %d, want %d", cursor.last, batchSize+5)
	}
}

func TestTheForwardedLineIsTheCEFOfTheRow(t *testing.T) {
	// The receiver reads the target as a name. A row that lost its server name
	// on the way through the queue would name the panel instead.
	cursor := &fakeCursor{last: 0, newest: 0}
	rows := trail(1, audit.ActionDNSAdd)
	rows[0].ServerName = "dns1"
	queue, _, socket := queueOver(rows, cursor, true)

	queue.Drain(context.Background())

	lines := socket.lines()
	if len(lines) != 1 {
		t.Fatalf("got %d rows, want 1", len(lines))
	}
	if !strings.Contains(lines[0], "dhost=dns1") {
		t.Errorf("the target was lost: %q", lines[0])
	}
	if !strings.Contains(lines[0], "dvchost=panel.example") {
		t.Errorf("the panel host was lost: %q", lines[0])
	}
	if !strings.Contains(lines[0], "suser=dnsadmin") {
		t.Errorf("the actor was lost: %q", lines[0])
	}
}

func TestPendingIsWhatTheReceiverIsOwed(t *testing.T) {
	cursor := &fakeCursor{last: 2, newest: 7}
	queue, _, _ := queueOver(trail(7), cursor, true)

	pending, err := queue.Pending(context.Background())
	if err != nil {
		t.Fatalf("Pending returned an error: %v", err)
	}
	if pending != 5 {
		t.Errorf("pending = %d, want 5", pending)
	}
}

func TestAWakeUpNeverBlocksTheCallerThatWritesTheRow(t *testing.T) {
	// It runs on the audit write path. An entry that waited on a receiver would
	// make the action that caused it wait too.
	cursor := &fakeCursor{}
	queue, _, _ := queueOver(trail(1), cursor, true)

	done := make(chan struct{})
	go func() {
		for range 100 {
			queue.Notify()
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Notify blocked")
	}
}

func TestACollectorThatClosedDoesNotAdvanceTheCursor(t *testing.T) {
	// The failure this whole design exists to prevent, and the one measured on
	// the development stack: the collector shuts down, the socket goes to
	// CLOSE_WAIT, writes to it keep succeeding, and the cursor walks past
	// events nothing received.
	cursor := &fakeCursor{last: 0, newest: 0}
	queue, reader, socket := queueOver(trail(1), cursor, true)

	// One row goes out while the collector is up, which is what leaves the
	// sender holding a connection.
	queue.Drain(context.Background())
	if cursor.last != 1 || len(socket.lines()) != 1 {
		t.Fatalf("the first row did not go out: cursor %d, %d lines",
			cursor.last, len(socket.lines()))
	}

	// Now the collector shuts down. The socket it left behind still takes
	// writes, and a new connection is refused.
	socket.mu.Lock()
	socket.peerClosed = true
	socket.mu.Unlock()
	queue.sender.dial = func(string, string) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}
	reader.rows = trail(4)

	queue.Drain(context.Background())

	if cursor.last != 1 {
		t.Errorf("cursor = %d, want it to stay at 1", cursor.last)
	}
	if got := len(socket.lines()); got != 1 {
		t.Errorf("%d lines were written in total, want the first one only", got)
	}
}
