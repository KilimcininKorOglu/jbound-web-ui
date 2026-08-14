package store_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"unbound-web/internal/store"
)

func TestAdmitCountsOnlyTheAddressInsideTheWindow(t *testing.T) {
	f := newFixture(t)
	attempts := store.NewLoginAttempts(f.db)
	ctx := context.Background()

	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	// A cutoff old enough that the seeding calls prune nothing.
	past := now.Add(-time.Hour)
	window := now.Add(-15 * time.Minute)

	seed := []struct {
		ip string
		at time.Time
	}{
		{"192.0.2.1", now},
		{"192.0.2.1", now.Add(-time.Minute)},
		{"192.0.2.1", now.Add(-2 * time.Minute)},
		{"192.0.2.2", now},
		// This one is already older than the window the probes below use.
		{"192.0.2.1", now.Add(-30 * time.Minute)},
	}
	for _, attempt := range seed {
		admitted, err := attempts.Admit(ctx, attempt.ip, "dnsadmin", past, attempt.at, 10)
		if err != nil {
			t.Fatalf("cannot seed the attempt: %v", err)
		}
		if !admitted {
			t.Fatalf("the seeded attempt from %s was refused", attempt.ip)
		}
	}

	admitted, err := attempts.Admit(ctx, "192.0.2.1", "dnsadmin", window, now, 3)
	if err != nil {
		t.Fatalf("Admit returned an error: %v", err)
	}
	if admitted {
		t.Error("the address was admitted although it reached the limit")
	}

	admitted, err = attempts.Admit(ctx, "192.0.2.2", "dnsadmin", window, now, 3)
	if err != nil {
		t.Fatalf("Admit returned an error: %v", err)
	}
	if !admitted {
		t.Error("another address was refused for the first one's attempts")
	}

	// Three rows from the first address, one seeded and one admitted from the
	// second, and the row from outside the window pruned on the way.
	var remaining int
	if err := f.db.QueryRow("SELECT COUNT(*) FROM login_attempts").Scan(&remaining); err != nil {
		t.Fatalf("cannot count the table: %v", err)
	}
	if remaining != 5 {
		t.Errorf("%d rows remain, want 5", remaining)
	}
}

func TestAdmitNeverExceedsTheLimitUnderAConcurrentBurst(t *testing.T) {
	// This is the whole point of the transaction. A count and an insert that
	// are two round trips let every request of a burst read the same pre-burst
	// number and pass, so the limit would bound sequential attempts only.
	const burst = 30
	const limit = 10

	f := newFixture(t)
	attempts := store.NewLoginAttempts(f.db)

	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	since := now.Add(-15 * time.Minute)

	var passed atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})

	for range burst {
		wg.Go(func() {
			<-start

			admitted, err := attempts.Admit(context.Background(),
				"192.0.2.1", "dnsadmin", since, now, limit)
			if err != nil {
				t.Errorf("Admit returned an error: %v", err)
				return
			}
			if admitted {
				passed.Add(1)
			}
		})
	}
	close(start)
	wg.Wait()

	if passed.Load() != limit {
		t.Errorf("%d of %d concurrent attempts were admitted, want %d",
			passed.Load(), burst, limit)
	}

	var rows int
	if err := f.db.QueryRow("SELECT COUNT(*) FROM login_attempts").Scan(&rows); err != nil {
		t.Fatalf("cannot count the table: %v", err)
	}
	if rows != limit {
		t.Errorf("%d rows were written, want %d", rows, limit)
	}
}
