package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"unbound-web/internal/settings"
)

// The limits the registry defaults to, restated so the limiter can be tested
// without a settings service behind it.
const (
	testRateWindow   = 15 * time.Minute
	testRateMaxTries = 10
)

type attempt struct {
	ip       string
	username string
	at       time.Time
}

type fakeAttemptRepo struct {
	attempts  []attempt
	recordErr error
	countErr  error
}

func (f *fakeAttemptRepo) Record(_ context.Context, ip, username string, at time.Time) error {
	if f.recordErr != nil {
		return f.recordErr
	}
	f.attempts = append(f.attempts, attempt{ip: ip, username: username, at: at})
	return nil
}

func (f *fakeAttemptRepo) CountSince(_ context.Context, ip string, since time.Time) (int, error) {
	if f.countErr != nil {
		return 0, f.countErr
	}
	count := 0
	for _, a := range f.attempts {
		if a.ip == ip && !a.at.Before(since) {
			count++
		}
	}
	return count, nil
}

func (f *fakeAttemptRepo) DeleteBefore(_ context.Context, before time.Time) error {
	kept := f.attempts[:0]
	for _, a := range f.attempts {
		if !a.at.Before(before) {
			kept = append(kept, a)
		}
	}
	f.attempts = kept
	return nil
}

func TestRateLimiterAllowsTenAttemptsAndRefusesTheEleventh(t *testing.T) {
	repo := &fakeAttemptRepo{}
	limiter := NewRateLimiter(repo, settings.Fixed(testRateWindow), settings.Fixed(testRateMaxTries))
	ctx := context.Background()

	for i := 1; i <= testRateMaxTries; i++ {
		allowed, err := limiter.Allow(ctx, "203.0.113.5")
		if err != nil {
			t.Fatalf("attempt %d failed: %v", i, err)
		}
		if !allowed {
			t.Fatalf("attempt %d was refused, the limit is %d", i, testRateMaxTries)
		}
		if err := limiter.Record(ctx, "203.0.113.5", "dnsuser"); err != nil {
			t.Fatalf("cannot record attempt %d: %v", i, err)
		}
	}

	allowed, err := limiter.Allow(ctx, "203.0.113.5")
	if err != nil {
		t.Fatalf("Allow returned an error: %v", err)
	}
	if allowed {
		t.Errorf("attempt %d was allowed", testRateMaxTries+1)
	}
}

func TestRateLimiterCountsPerAddress(t *testing.T) {
	// Keying on the user name instead would let anyone lock out a known
	// account by guessing at it.
	repo := &fakeAttemptRepo{}
	limiter := NewRateLimiter(repo, settings.Fixed(testRateWindow), settings.Fixed(testRateMaxTries))
	ctx := context.Background()

	for range testRateMaxTries {
		if err := limiter.Record(ctx, "203.0.113.5", "dnsuser"); err != nil {
			t.Fatalf("cannot record the attempt: %v", err)
		}
	}

	allowed, err := limiter.Allow(ctx, "198.51.100.9")
	if err != nil {
		t.Fatalf("Allow returned an error: %v", err)
	}
	if !allowed {
		t.Error("a different address was refused")
	}
}

func TestRateLimiterForgetsAttemptsOlderThanTheWindow(t *testing.T) {
	repo := &fakeAttemptRepo{}
	limiter := NewRateLimiter(repo, settings.Fixed(testRateWindow), settings.Fixed(testRateMaxTries))
	ctx := context.Background()

	base := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	limiter.now = func() time.Time { return base }

	for range testRateMaxTries {
		if err := limiter.Record(ctx, "203.0.113.5", "dnsuser"); err != nil {
			t.Fatalf("cannot record the attempt: %v", err)
		}
	}

	limiter.now = func() time.Time { return base.Add(testRateWindow + time.Minute) }

	allowed, err := limiter.Allow(ctx, "203.0.113.5")
	if err != nil {
		t.Fatalf("Allow returned an error: %v", err)
	}
	if !allowed {
		t.Error("the address is still blocked after the window passed")
	}
	if len(repo.attempts) != 0 {
		t.Errorf("%d stale attempts survived the prune", len(repo.attempts))
	}
}

func TestRateLimiterReportsStorageFailures(t *testing.T) {
	// A limiter that silently allowed everything when its storage broke would
	// be worse than no limiter, because nothing would report the fault.
	failure := errors.New("database is gone")
	ctx := context.Background()

	limiter := NewRateLimiter(&fakeAttemptRepo{countErr: failure},
		settings.Fixed(testRateWindow), settings.Fixed(testRateMaxTries))
	if _, err := limiter.Allow(ctx, "203.0.113.5"); !errors.Is(err, failure) {
		t.Errorf("Allow returned %v, want the storage failure", err)
	}

	limiter = NewRateLimiter(&fakeAttemptRepo{recordErr: failure},
		settings.Fixed(testRateWindow), settings.Fixed(testRateMaxTries))
	if err := limiter.Record(ctx, "203.0.113.5", "dnsuser"); !errors.Is(err, failure) {
		t.Errorf("Record returned %v, want the storage failure", err)
	}
}
