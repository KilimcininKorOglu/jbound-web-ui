package siem

import (
	"errors"
	"log/syslog"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSocket collects what the sender wrote and can be told to fail.
type fakeSocket struct {
	mu      sync.Mutex
	written []string
	closed  bool

	// failWrite fails the next write and clears itself, which is how a
	// collector that dropped an idle connection behaves: the panel only finds
	// out by writing to it.
	failWrite bool

	// failFrom fails this write and every one after it, counting from one. Zero
	// never fails. It stands in for a receiver that goes away part way through
	// a batch rather than between two of them.
	failFrom int
	attempts int
}

func (s *fakeSocket) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.attempts++
	if s.failWrite {
		s.failWrite = false
		return 0, errors.New("broken pipe")
	}
	if s.failFrom > 0 && s.attempts >= s.failFrom {
		return 0, errors.New("connection reset by peer")
	}
	s.written = append(s.written, string(p))
	return len(p), nil
}

func (s *fakeSocket) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

func (s *fakeSocket) lines() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.written...)
}

func (s *fakeSocket) Read([]byte) (int, error)         { return 0, nil }
func (s *fakeSocket) LocalAddr() net.Addr              { return nil }
func (s *fakeSocket) RemoteAddr() net.Addr             { return nil }
func (s *fakeSocket) SetDeadline(time.Time) error      { return nil }
func (s *fakeSocket) SetReadDeadline(time.Time) error  { return nil }
func (s *fakeSocket) SetWriteDeadline(time.Time) error { return nil }

// senderOver returns a sender that dials the given socket, and counts the
// dials, because the retry is about opening a second connection.
func senderOver(socket net.Conn, protocol, host string, port int) (*Sender, *int) {
	dials := 0
	sender := NewSender("panel.example",
		func() string { return protocol },
		func() string { return host },
		func() int { return port })

	sender.dial = func(string, string) (net.Conn, error) {
		dials++
		return socket, nil
	}
	return sender, &dials
}

func TestAnEventReachesTheReceiverAsOneSyslogLine(t *testing.T) {
	socket := &fakeSocket{}
	sender, _ := senderOver(socket, ProtocolTCP, "siem.example", 514)

	at := time.Date(2026, 3, 1, 12, 30, 0, 0, time.UTC)
	if err := sender.Send("dns_add", "CEF:0|JBound|x|1.0|dns_add|Added|3|msg=x", at); err != nil {
		t.Fatalf("Send returned an error: %v", err)
	}

	lines := socket.lines()
	if len(lines) != 1 {
		t.Fatalf("got %d writes, want 1", len(lines))
	}
	line := lines[0]

	// The priority is the facility and the severity of the action together. A
	// receiver sorts on it, so a wrong one is a filter that never matches.
	want := int(Facility) | int(Classify("dns_add").Priority)
	if !strings.HasPrefix(line, "<"+strconv.Itoa(want)+">1 ") {
		t.Errorf("the frame does not open with the priority and the version: %q", line)
	}
	if !strings.Contains(line, "2026-03-01T12:30:00Z") {
		t.Errorf("the frame does not carry the time of the event: %q", line)
	}
	if !strings.Contains(line, " panel.example "+Tag+" - - - CEF:0|") {
		t.Errorf("the frame header is not RFC 5424: %q", line)
	}
	if !strings.HasSuffix(line, "\n") {
		t.Errorf("the frame does not end the line: %q", line)
	}
	if strings.Count(line, "\n") != 1 {
		t.Errorf("the frame holds more than one line: %q", line)
	}
}

func TestTheTimeSentIsTheTimeOfTheEvent(t *testing.T) {
	// A batch that goes out after an outage would otherwise arrive stamped with
	// the recovery, and the receiver would read the order of events as the order
	// the panel happened to catch up in.
	socket := &fakeSocket{}
	sender, _ := senderOver(socket, ProtocolTCP, "siem.example", 514)

	old := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := sender.Send("login", "CEF:0|x", old); err != nil {
		t.Fatalf("Send returned an error: %v", err)
	}

	if !strings.Contains(socket.lines()[0], "2026-01-02T03:04:05Z") {
		t.Errorf("the frame was stamped with the send rather than the event: %q",
			socket.lines()[0])
	}
}

func TestAWriteThatFailsIsRetriedOnAFreshConnection(t *testing.T) {
	// A collector that closed an idle socket is the usual failure, and the
	// panel only learns about it by writing.
	socket := &fakeSocket{failWrite: true}
	sender, dials := senderOver(socket, ProtocolTCP, "siem.example", 514)

	if err := sender.Send("login", "CEF:0|x", time.Now()); err != nil {
		t.Fatalf("Send returned an error: %v", err)
	}
	if *dials != 2 {
		t.Errorf("dials = %d, want a second one after the failed write", *dials)
	}
	if !socket.closed {
		t.Error("the broken connection was not closed")
	}
	if len(socket.lines()) != 1 {
		t.Errorf("got %d lines, want the retry to have landed", len(socket.lines()))
	}
}

func TestNothingIsSentWithoutAReceiver(t *testing.T) {
	// Off is a state an operator chooses, not a failure to report.
	socket := &fakeSocket{}

	for _, tc := range []struct{ protocol, host string }{
		{ProtocolOff, "siem.example"},
		{ProtocolTCP, ""},
	} {
		sender, dials := senderOver(socket, tc.protocol, tc.host, 514)

		err := sender.Send("login", "CEF:0|x", time.Now())
		if !errors.Is(err, ErrNoReceiver) {
			t.Errorf("protocol %q host %q: got %v, want ErrNoReceiver",
				tc.protocol, tc.host, err)
		}
		if *dials != 0 {
			t.Errorf("protocol %q host %q opened a connection", tc.protocol, tc.host)
		}
		if sender.Configured() {
			t.Errorf("protocol %q host %q reads as configured", tc.protocol, tc.host)
		}
	}
}

func TestTheStateCarriesTheLastFailureAndClearsIt(t *testing.T) {
	// The page shows it. An operator whose receiver is refusing connections
	// reads the reason there rather than in the panel log.
	sender, _ := senderOver(nil, ProtocolTCP, "siem.example", 514)
	sender.dial = func(string, string) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}

	if err := sender.Send("login", "CEF:0|x", time.Now()); err == nil {
		t.Fatal("a refused connection reported success")
	}

	state := sender.State()
	if !strings.Contains(state.LastError, "connection refused") {
		t.Errorf("LastError = %q", state.LastError)
	}
	if state.Connected {
		t.Error("a sender that never connected reports a connection")
	}
	if state.Address != "siem.example:514" {
		t.Errorf("Address = %q, want siem.example:514", state.Address)
	}

	socket := &fakeSocket{}
	sender.dial = func(string, string) (net.Conn, error) { return socket, nil }
	if err := sender.Send("login", "CEF:0|x", time.Now()); err != nil {
		t.Fatalf("Send returned an error: %v", err)
	}

	state = sender.State()
	if state.LastError != "" {
		t.Errorf("LastError = %q after a send that worked", state.LastError)
	}
	if !state.Connected {
		t.Error("a sender holding a connection reports none")
	}
	if state.LastSent.IsZero() {
		t.Error("LastSent was not recorded")
	}
}

func TestAnAddressWithNoReceiverStaysEmpty(t *testing.T) {
	// The page reads it, and ":514" beside a receiver that is off would ask the
	// operator to work out that it means nothing.
	sender, _ := senderOver(nil, ProtocolOff, "", 514)

	if address := sender.State().Address; address != "" {
		t.Errorf("Address = %q, want it empty while the receiver is off", address)
	}
}

func TestAHostWithNoNameReadsAsTheReservedField(t *testing.T) {
	// RFC 5424 wants one printable word there, and a panel whose host name
	// could not be read has none.
	line := string(frame(syslog.LOG_INFO, time.Now(), "", "CEF:0|x"))
	if !strings.Contains(line, " - "+Tag+" ") {
		t.Errorf("the empty host was not replaced: %q", line)
	}
}
