package siem

import (
	"errors"
	"log/syslog"
	"strings"
	"sync"
	"testing"

	"unbound-web/internal/audit"
)

// fakeConn stands in for the syslog connection.
type fakeConn struct {
	mu     sync.Mutex
	lines  []string
	closed int
	err    error
}

func (f *fakeConn) write(level, message string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.err != nil {
		return f.err
	}
	f.lines = append(f.lines, level+" "+message)
	return nil
}

func (f *fakeConn) Info(message string) error    { return f.write("info", message) }
func (f *fakeConn) Notice(message string) error  { return f.write("notice", message) }
func (f *fakeConn) Warning(message string) error { return f.write("warning", message) }

func (f *fakeConn) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.closed++
	return nil
}

func (f *fakeConn) written() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.lines...)
}

// harness returns a forwarder over a connection the test controls.
func harness(t *testing.T, conns ...*fakeConn) (*Forwarder, func() int) {
	t.Helper()

	var dials int
	forwarder := NewForwarder("panel.example.net")
	forwarder.dial = func() (conn, error) {
		dials++
		if dials > len(conns) {
			return nil, errors.New("no connection left")
		}
		return conns[dials-1], nil
	}
	return forwarder, func() int { return dials }
}

func TestTheEntryReachesSyslogAtItsOwnSeverity(t *testing.T) {
	client := &fakeConn{}
	forwarder, _ := harness(t, client)

	if err := forwarder.Forward(entry(audit.ActionDNSDelete)); err != nil {
		t.Fatalf("Forward returned an error: %v", err)
	}

	lines := client.written()
	if len(lines) != 1 {
		t.Fatalf("got %d lines, want 1", len(lines))
	}
	if !strings.HasPrefix(lines[0], "warning CEF:0|JanBound|") {
		t.Errorf("line = %q", lines[0])
	}
}

func TestTheConnectionIsOpenedOnceAndKept(t *testing.T) {
	client := &fakeConn{}
	forwarder, dials := harness(t, client)

	for range 3 {
		if err := forwarder.Forward(entry(audit.ActionLogin)); err != nil {
			t.Fatalf("Forward returned an error: %v", err)
		}
	}
	if dials() != 1 {
		t.Errorf("the forwarder dialled %d times", dials())
	}
	if len(client.written()) != 3 {
		t.Errorf("got %d lines, want 3", len(client.written()))
	}
}

func TestABrokenConnectionIsReopened(t *testing.T) {
	// A syslog daemon restart must not silence the panel until the panel
	// itself restarts.
	broken := &fakeConn{err: errors.New("broken pipe")}
	fresh := &fakeConn{}
	forwarder, dials := harness(t, broken, fresh)

	if err := forwarder.Forward(entry(audit.ActionLogin)); err != nil {
		t.Fatalf("the first entry failed: %v", err)
	}

	// The first line was lost with the connection, and the retry carries it.
	if len(fresh.written()) != 1 {
		t.Fatalf("the retry wrote %d lines", len(fresh.written()))
	}
	if dials() != 2 || broken.closed != 1 {
		t.Errorf("dials = %d, closed = %d", dials(), broken.closed)
	}
}

func TestAFailureIsReportedRatherThanSwallowed(t *testing.T) {
	first := &fakeConn{err: errors.New("broken pipe")}
	second := &fakeConn{err: errors.New("still broken")}
	forwarder, _ := harness(t, first, second)

	if err := forwarder.Forward(entry(audit.ActionLogin)); err == nil {
		t.Fatal("a failing forwarder reported success")
	}
}

func TestADaemonThatIsDownDoesNotStopTheWrite(t *testing.T) {
	// The panel starts before the daemon may be up, so the first connection is
	// opened at the first entry rather than at start.
	forwarder := NewForwarder("panel.example.net")
	forwarder.dial = func() (conn, error) { return nil, errors.New("connection refused") }

	err := forwarder.Forward(entry(audit.ActionLogin))
	if err == nil {
		t.Fatal("an unreachable daemon reported success")
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("the reason was lost: %v", err)
	}
}

func TestTheFacilityAndTagAreTheOnesTheRulesSelect(t *testing.T) {
	// An rsyslog rule selects the panel's events by facility alone, so this is
	// what the configuration written on the SIEM page has to match.
	if Facility != syslog.LOG_LOCAL6 {
		t.Errorf("facility = %d", Facility)
	}
	if Tag != "unbound-dns-panel" {
		t.Errorf("tag = %q", Tag)
	}
}
