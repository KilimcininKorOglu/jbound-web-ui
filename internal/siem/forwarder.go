package siem

import (
	"fmt"
	"log/syslog"
	"sync"

	"unbound-web/internal/audit"
)

// Facility is where the panel writes. An rsyslog rule selects the panel's
// events by this facility alone, so nothing else on the host may use it.
const Facility = syslog.LOG_LOCAL6

// Tag is the syslog ident of every line the panel writes.
const Tag = "unbound-dns-panel"

// conn is the part of a syslog connection the forwarder uses.
//
// It is an interface so the forwarder can be covered without a syslog daemon
// on the machine running the tests.
type conn interface {
	Info(message string) error
	Notice(message string) error
	Warning(message string) error
	Close() error
}

// Forwarder sends audit entries to the local syslog daemon.
//
// The connection is opened once and kept. A write that fails reopens it and
// tries again, because a daemon restart must not silence the panel until the
// panel itself restarts.
type Forwarder struct {
	panelHost string

	mu     sync.Mutex
	client conn
	dial   func() (conn, error)
}

// NewForwarder builds the forwarder. It does not connect yet, because a syslog
// daemon that is not up at start must not stop the panel from starting.
func NewForwarder(panelHost string) *Forwarder {
	return &Forwarder{panelHost: panelHost, dial: dialSyslog}
}

func dialSyslog() (conn, error) {
	client, err := syslog.New(Facility, Tag)
	if err != nil {
		return nil, fmt.Errorf("cannot open the syslog connection: %w", err)
	}
	return client, nil
}

// Forward sends one entry as a CEF line.
func (f *Forwarder) Forward(entry audit.Entry) error {
	line := Format(entry, f.panelHost)
	priority := Classify(entry.Action).Priority

	f.mu.Lock()
	defer f.mu.Unlock()

	if err := f.send(priority, line); err == nil {
		return nil
	} else if f.client == nil {
		// Nothing was open, so the failure is the connection itself and a
		// second attempt would fail the same way.
		return err
	}

	f.reset()
	return f.send(priority, line)
}

// send writes one line, opening the connection when it is not open yet.
func (f *Forwarder) send(priority syslog.Priority, line string) error {
	if f.client == nil {
		client, err := f.dial()
		if err != nil {
			return err
		}
		f.client = client
	}

	var err error
	switch priority {
	case syslog.LOG_WARNING:
		err = f.client.Warning(line)
	case syslog.LOG_NOTICE:
		err = f.client.Notice(line)
	default:
		err = f.client.Info(line)
	}
	if err != nil {
		return fmt.Errorf("cannot write to syslog: %w", err)
	}
	return nil
}

// reset drops the connection so the next write opens a new one.
func (f *Forwarder) reset() {
	if f.client != nil {
		_ = f.client.Close()
		f.client = nil
	}
}

// Close releases the connection.
func (f *Forwarder) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.reset()
	return nil
}
