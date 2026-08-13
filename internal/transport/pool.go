package transport

import (
	"context"
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

// Pool keeps one connection per server.
//
// A fleet operation touches every member of a group, and each one would
// otherwise pay for a fresh handshake. One transport per server also gives
// each server its own write lock, which is what keeps two panel users from
// overwriting each other on the same host.
type Pool struct {
	mu          sync.Mutex
	entries     map[int64]*poolEntry
	idleTimeout time.Duration
	closed      bool
}

type poolEntry struct {
	transport *SSHTransport
	config    Config
	lastUsed  time.Time
}

// NewPool builds the pool and starts its maintenance loop.
//
// The loop ends with the context, which closes every connection.
func NewPool(ctx context.Context, idleTimeout time.Duration) *Pool {
	pool := &Pool{
		entries:     map[int64]*poolEntry{},
		idleTimeout: idleTimeout,
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
			p.Close()
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
		if time.Since(entry.lastUsed) > p.idleTimeout {
			entry.transport.Close()
			delete(p.entries, id)
			continue
		}
		alive = append(alive, ping{id: id, client: entry.transport})
	}
	p.mu.Unlock()

	// The pings run without the pool lock. A keepalive that blocks would
	// otherwise stall every other server.
	for _, entry := range alive {
		if err := entry.client.keepalive(); err != nil {
			slog.Debug("keepalive failed, the connection will be reopened",
				"server_id", entry.id, "error", err)
		}
	}
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
func (t *SSHTransport) keepalive() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.client == nil {
		return nil
	}

	// The request name is arbitrary. The server answers that it does not know
	// it, and that answer is the proof the connection still carries traffic.
	_, _, err := t.client.SendRequest("keepalive@unbound-web", true, nil)
	if err != nil {
		t.dropConnection()
		return err
	}
	return nil
}
