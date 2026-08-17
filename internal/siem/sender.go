package siem

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/syslog"
	"net"
	"strconv"
	"sync"
	"time"
)

// Protocols the panel speaks to a receiver.
//
// Off is a receiver that has not been configured, which is what a panel with no
// SIEM runs with and what every existing install starts as.
const (
	ProtocolOff = "off"
	ProtocolUDP = "udp"
	ProtocolTCP = "tcp"
	ProtocolTLS = "tls"
)

// ErrNoReceiver marks a send attempted with no receiver configured.
//
// It is not a failure to report to the operator. It is the state of a panel
// that keeps its trail in the database, so the queue treats it as nothing to
// do rather than as something to retry.
var ErrNoReceiver = errors.New("no receiver is configured")

// dialTimeout bounds one connection attempt.
//
// A receiver behind a firewall that drops rather than refuses would otherwise
// hold the sender until the kernel gives up, and the audit rows behind it wait
// that long too.
const dialTimeout = 10 * time.Second

// writeTimeout bounds one write.
//
// A collector that stops reading fills the socket buffer and then blocks
// forever, which looks exactly like a healthy connection from here.
const writeTimeout = 10 * time.Second

// Sender writes audit events to a receiver over the network.
//
// The connection is opened once and kept, because a panel under load writes
// several events a second and a connection per event would spend more time in
// handshakes than in sending. A write that fails drops the connection so the
// next attempt opens a new one.
//
// Nothing here decides what to send or remembers what was sent. That is the
// queue's job, and keeping the two apart is what lets the queue retry.
type Sender struct {
	panelHost string

	protocol func() string
	host     func() string
	port     func() int

	mu   sync.Mutex
	conn net.Conn

	// dial is a field so a test can stand in for the network. Every other way
	// of covering this would need a listener per case.
	dial func(protocol, address string) (net.Conn, error)

	lastError string
	lastSent  time.Time
}

// NewSender builds the sender. It does not connect yet, because a receiver that
// is down at start must not stop the panel from starting.
func NewSender(panelHost string, protocol, host func() string, port func() int) *Sender {
	return &Sender{
		panelHost: panelHost,
		protocol:  protocol,
		host:      host,
		port:      port,
		dial:      dialReceiver,
	}
}

// State is what the SIEM page reports about the connection.
type State struct {
	// Protocol is what the operator configured, including off.
	Protocol string

	// Address is host:port, or empty when no receiver is configured.
	Address string

	// Connected reports whether a connection is open right now. A sender that
	// has not been asked to send anything yet reports false, which is honest:
	// it has not reached the receiver.
	Connected bool

	// LastError is the reason the last attempt failed, and empty after one
	// that worked.
	LastError string

	// LastSent is when an event last reached the receiver.
	LastSent time.Time
}

// State reports the connection as it stands.
func (s *Sender) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()

	state := State{
		Protocol:  s.protocol(),
		Connected: s.conn != nil,
		LastError: s.lastError,
		LastSent:  s.lastSent,
	}
	if state.Protocol != ProtocolOff {
		state.Address = s.address()
	}
	return state
}

// Configured reports whether a receiver is set up at all.
func (s *Sender) Configured() bool {
	return s.protocol() != ProtocolOff && s.host() != ""
}

// Send writes one event.
//
// A write that fails is retried once on a fresh connection, because the usual
// failure is a collector that closed an idle socket and the panel only finds
// out by writing to it.
func (s *Sender) Send(action, line string, at time.Time) error {
	if !s.Configured() {
		return ErrNoReceiver
	}

	frame := frame(Classify(action).Priority, at, s.panelHost, line)

	s.mu.Lock()
	defer s.mu.Unlock()

	err := s.write(frame)
	if err != nil && s.conn != nil {
		s.reset()
		err = s.write(frame)
	}

	if err != nil {
		s.lastError = err.Error()
		return err
	}
	s.lastError = ""
	s.lastSent = time.Now()
	return nil
}

// write sends one frame, opening the connection when it is not open yet. The
// caller holds the lock.
func (s *Sender) write(frame []byte) error {
	if s.conn == nil {
		conn, err := s.dial(s.protocol(), s.address())
		if err != nil {
			return err
		}
		s.conn = conn
	}

	if err := s.conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return fmt.Errorf("cannot set the write deadline: %w", err)
	}
	if _, err := s.conn.Write(frame); err != nil {
		return fmt.Errorf("cannot write to the receiver: %w", err)
	}
	return nil
}

// address renders host:port. The caller holds the lock.
func (s *Sender) address() string {
	return net.JoinHostPort(s.host(), strconv.Itoa(s.port()))
}

// reset drops the connection so the next write opens a new one. The caller
// holds the lock.
func (s *Sender) reset() {
	if s.conn != nil {
		_ = s.conn.Close()
		s.conn = nil
	}
}

// Close releases the connection.
func (s *Sender) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.reset()
	return nil
}

// dialReceiver opens the connection the protocol asks for.
//
// tls verifies against the host trust store. There is no option to skip that:
// an operator who wants a private certificate authority adds it to the host,
// which is a decision made once and visible on disk rather than a checkbox in
// a table.
func dialReceiver(protocol, address string) (net.Conn, error) {
	switch protocol {
	case ProtocolUDP, ProtocolTCP:
		conn, err := net.DialTimeout(protocol, address, dialTimeout)
		if err != nil {
			return nil, fmt.Errorf("cannot reach the receiver: %w", err)
		}
		return conn, nil

	case ProtocolTLS:
		dialer := &net.Dialer{Timeout: dialTimeout}
		conn, err := tls.DialWithDialer(dialer, "tcp", address, nil)
		if err != nil {
			return nil, fmt.Errorf("cannot reach the receiver over TLS: %w", err)
		}
		return conn, nil

	default:
		return nil, fmt.Errorf("%w: %q", ErrNoReceiver, protocol)
	}
}

// frame wraps one CEF line in the syslog envelope of RFC 5424.
//
// The timestamp is the one the event carries rather than the moment of sending.
// A batch that goes out after a receiver outage would otherwise arrive stamped
// with the recovery, and the order it reads in would say nothing about when
// anything happened.
//
// Framing is one line, ended by a newline. The CEF renderer strips every
// control character from every field, so a line cannot end early.
func frame(severity syslog.Priority, at time.Time, host, line string) []byte {
	priority := int(Facility) | int(severity)

	return fmt.Appendf(nil, "<%d>1 %s %s %s - - - %s\n",
		priority, at.UTC().Format(time.RFC3339), hostField(host), Tag, line)
}

// hostField renders the host name the way RFC 5424 requires, which is one
// printable word. A host with no name at all reads as the nil value the
// standard reserves for it.
func hostField(host string) string {
	if host == "" {
		return "-"
	}
	return host
}
