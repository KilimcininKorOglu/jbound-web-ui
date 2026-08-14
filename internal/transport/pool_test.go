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
