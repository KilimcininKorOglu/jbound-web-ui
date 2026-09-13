package transport

import (
	"context"
	"testing"
	"time"
)

func fixedIdle(d time.Duration) func() time.Duration {
	return func() time.Duration { return d }
}

func TestACancelledContextStopsTheSweepAndNotThePool(t *testing.T) {
	// The signal that cancels this context also starts the shutdown grace of
	// the HTTP server. A request inside that grace still has a fleet operation
	// to finish, and a closed pool refuses every connection it asks for.
	ctx, cancel := context.WithCancel(context.Background())
	pool := NewPool(ctx, fixedIdle(time.Minute))
	t.Cleanup(pool.Close)

	cancel()
	// The maintenance goroutine only has to notice.
	time.Sleep(50 * time.Millisecond)

	pool.mu.Lock()
	closed := pool.closed
	pool.mu.Unlock()

	if closed {
		t.Fatal("the pool closed itself while the server was still draining")
	}
}

func TestAClosedPoolRefusesFurtherConnections(t *testing.T) {
	// Once the owner closes it, nothing may reopen a connection behind it.
	pool := NewPool(context.Background(), fixedIdle(time.Minute))
	pool.Close()

	if _, err := pool.Get(validConfig()); err == nil {
		t.Error("a closed pool handed out a transport")
	}
}

// stubTransport stands in for a pooled connection. Remove has to close the
// entry it forgets, and a real SSH transport cannot prove that without a
// server to dial.
type stubTransport struct{ closed bool }

var _ Transport = (*stubTransport)(nil)

func (s *stubTransport) ReadRecords(context.Context) ([]byte, string, error) { return nil, "", nil }
func (s *stubTransport) WriteRecords(context.Context, []byte, string) error  { return nil }
func (s *stubTransport) EnsureInclude(context.Context) (string, error)       { return "", nil }
func (s *stubTransport) CheckConfig(context.Context) (string, error)         { return "", nil }
func (s *stubTransport) Reload(context.Context) (string, error)              { return "", nil }
func (s *stubTransport) ReloadFallback(context.Context) (string, error)      { return "", nil }
func (s *stubTransport) Restart(context.Context) (string, error)             { return "", nil }
func (s *stubTransport) ServiceStatus(context.Context) (bool, string, error) { return true, "", nil }
func (s *stubTransport) Probe(context.Context) error                         { return nil }
func (s *stubTransport) Close() error {
	s.closed = true
	return nil
}

func TestRemovingAServerClosesAndForgetsItsConnection(t *testing.T) {
	// A deleted or disabled server record must not keep a live connection,
	// and nothing of it may survive in the pool.
	pool := NewPool(context.Background(), fixedIdle(time.Minute))
	t.Cleanup(pool.Close)

	stub := &stubTransport{}
	pool.mu.Lock()
	pool.entries[9] = &poolEntry{transport: stub, config: Config{ID: 9, Name: "dns9"}}
	pool.mu.Unlock()

	pool.Remove(9)

	if !stub.closed {
		t.Error("Remove did not close the connection it forgot")
	}
	pool.mu.Lock()
	defer pool.mu.Unlock()
	if len(pool.entries) != 0 {
		t.Errorf("the entry survived Remove: %d left", len(pool.entries))
	}
}

func TestRemovingAnUnknownServerLeavesTheOtherConnectionsAlone(t *testing.T) {
	// An id the pool never held is a no-op, not a closed connection that
	// happened to sit nearby.
	pool := NewPool(context.Background(), fixedIdle(time.Minute))
	t.Cleanup(pool.Close)

	stub := &stubTransport{}
	pool.mu.Lock()
	pool.entries[1] = &poolEntry{transport: stub, config: Config{ID: 1}}
	pool.mu.Unlock()

	pool.Remove(42)

	if stub.closed {
		t.Error("Remove closed a connection the id did not name")
	}
	pool.mu.Lock()
	defer pool.mu.Unlock()
	if len(pool.entries) != 1 {
		t.Errorf("the surviving entry disappeared: %d left", len(pool.entries))
	}
}

func TestARemovedServerIsBuiltAnewOnTheNextGet(t *testing.T) {
	// After the record went away the pool must not hand the old connection
	// back: a server the caller deleted has no right to a live transport.
	pool := NewPool(context.Background(), fixedIdle(time.Minute))
	t.Cleanup(pool.Close)

	first, err := pool.Get(validConfig())
	if err != nil {
		t.Fatalf("Get returned an error: %v", err)
	}

	pool.Remove(validConfig().ID)

	second, err := pool.Get(validConfig())
	if err != nil {
		t.Fatalf("Get returned an error: %v", err)
	}
	if first == second {
		t.Error("the pool handed back the removed connection")
	}
}
