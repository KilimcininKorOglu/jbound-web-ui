package transport

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// keepaliveInterval bounds how long a dead connection looks alive.
//
// A firewall that drops an idle flow says nothing about it. Without a
// keepalive the next command would block until the TCP timeout, which is
// minutes rather than seconds.
const keepaliveInterval = 30 * time.Second

// keepaliveTimeout bounds one ping.
//
// A connection that was dropped without an RST answers nothing at all, which
// is the exact case the keepalive exists to catch. Waiting for it is waiting
// for ever, so the reply gets a deadline and a silent connection is treated as
// the dead one it is.
const keepaliveTimeout = 10 * time.Second

// Pool keeps one connection per server.
//
// A fleet operation touches every member of a group, and each one would
// otherwise pay for a fresh handshake. One transport per server also gives
// each server its own write lock, which is what keeps two panel users from
// overwriting each other on the same host.
type Pool struct {
	mu      sync.Mutex
	entries map[int64]*poolEntry

	// idleTimeout is read on every sweep, so a shorter value set on the
	// settings page starts closing connections on the next one.
	idleTimeout func() time.Duration

	// pingTimeout bounds one keepalive. It is a field rather than the constant
	// so a test can wedge a peer without waiting out the real deadline.
	pingTimeout time.Duration

	closed bool
}

type poolEntry struct {
	transport *SSHTransport
	config    Config
	lastUsed  time.Time
}

// NewPool builds the pool and starts its maintenance loop.
//
// The loop ends with the context. Closing the connections is the caller's
// call, so a shutdown can drain its requests before the pool goes away.
func NewPool(ctx context.Context, idleTimeout func() time.Duration) *Pool {
	pool := &Pool{
		entries:     map[int64]*poolEntry{},
		idleTimeout: idleTimeout,
		pingTimeout: keepaliveTimeout,
	}
	go pool.maintain(ctx)
	return pool
}

// Get returns the transport of one server.
//
// A configuration change replaces the connection. A new address, port, user or
// approved host key means the old connection no longer goes where the record
// says it should.
//
// The return type is the interface rather than the SSH implementation, so a
// caller can be tested against a fake and the agent transport can take over
// later without touching them.
func (p *Pool) Get(cfg Config) (Transport, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil, ErrUnreachable
	}

	if entry, ok := p.entries[cfg.ID]; ok {
		if sameEndpoint(entry.config, cfg) {
			entry.lastUsed = time.Now()
			return entry.transport, nil
		}
		entry.transport.Close()
		delete(p.entries, cfg.ID)
	}

	transport, err := NewSSH(cfg)
	if err != nil {
		return nil, err
	}
	p.entries[cfg.ID] = &poolEntry{
		transport: transport,
		config:    cfg,
		lastUsed:  time.Now(),
	}
	return transport, nil
}

// Remove closes and forgets one server, which is what a deleted or disabled
// server record needs.
func (p *Pool) Remove(id int64) {
	p.mu.Lock()
	defer p.mu.Unlock()

	entry, ok := p.entries[id]
	if !ok {
		return
	}
	entry.transport.Close()
	delete(p.entries, id)
}

// Close releases every connection.
func (p *Pool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for id, entry := range p.entries {
		entry.transport.Close()
		delete(p.entries, id)
	}
	p.closed = true
}

// maintain drops idle connections and keeps the rest alive.
func (p *Pool) maintain(ctx context.Context) {
	ticker := time.NewTicker(keepaliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Only the maintenance stops here. The signal that cancels this
			// context also starts the shutdown grace of the HTTP server, and a
			// request inside that grace still has a fleet operation to finish.
			// The owner closes the pool once the server has drained.
			return
		case <-ticker.C:
			p.sweep()
		}
	}
}

// sweep closes what has gone idle and pings what has not.
func (p *Pool) sweep() {
	p.mu.Lock()
	type ping struct {
		id     int64
		client *SSHTransport
	}
	var alive []ping

	for id, entry := range p.entries {
		if time.Since(entry.lastUsed) > p.idleTimeout() {
			entry.transport.Close()
			delete(p.entries, id)
			continue
		}
		alive = append(alive, ping{id: id, client: entry.transport})
	}
	p.mu.Unlock()

	// The pings run without the pool lock and beside each other. One server
	// that takes the whole keepalive deadline to answer would otherwise push
	// the sweep of every server behind it past the next tick.
	var wait sync.WaitGroup
	for _, entry := range alive {
		wait.Go(func() {
			if err := entry.client.keepalive(p.pingTimeout); err != nil {
				slog.Debug("keepalive failed, the connection will be reopened",
					"server_id", entry.id, "error", err)
			}
		})
	}
	wait.Wait()
}

// sameEndpoint reports whether two records point at the same connection.
func sameEndpoint(a, b Config) bool {
	return a.Host == b.Host &&
		a.Port == b.Port &&
		a.User == b.User &&
		a.KeyPath == b.KeyPath &&
		a.HostKey == b.HostKey
}

// keepalive sends one request down an open connection.
//
// An idle connection is left alone rather than dialled, because opening a
// connection nobody asked for would turn an unreachable server into a stream
// of log noise.
func (t *SSHTransport) keepalive(timeout time.Duration) error {
	// A transport in the middle of an operation is alive by definition, and
	// waiting for its mutex would hold the sweep for as long as that operation
	// runs.
	if !t.mu.TryLock() {
		return nil
	}
	defer t.mu.Unlock()

	if t.client == nil {
		return nil
	}

	// The request name is arbitrary. The server answers that it does not know
	// it, and that answer is the proof the connection still carries traffic.
	client := t.client
	done := make(chan error, 1)
	go func() {
		_, _, err := client.SendRequest("keepalive@unbound-web", true, nil)
		done <- err
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case err := <-done:
		if err != nil {
			t.dropConnection()
			return err
		}
		return nil
	case <-timer.C:
		// Closing the connection is what ends the request, so the goroutine
		// above returns rather than waiting on a peer that never answers.
		t.dropConnection()
		return fmt.Errorf("%w: no keepalive reply within %s",
			ErrUnreachable, timeout)
	}
}
