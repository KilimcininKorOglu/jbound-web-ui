package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"jbound/internal/settings"
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
	attempts []attempt
	err      error
}

// Admit models the store: prune, count, and record only what is admitted. The
// steps run under no lock here, which is enough because the fake is only ever
// driven from one goroutine. The transaction is proven against SQLite.
func (f *fakeAttemptRepo) Admit(_ context.Context, ip, username string,
	since, at time.Time, maxTries int) (bool, error) {

	if f.err != nil {
		return false, f.err
	}

	kept := f.attempts[:0]
	for _, a := range f.attempts {
		if !a.at.Before(since) {
			kept = append(kept, a)
		}
	}
	f.attempts = kept

	count := 0
	for _, a := range f.attempts {
		if a.ip == ip {
			count++
		}
	}
	if count >= maxTries {
		return false, nil
	}

	f.attempts = append(f.attempts, attempt{ip: ip, username: username, at: at})
	return true, nil
}

func TestRateLimiterAdmitsTenAttemptsAndRefusesTheEleventh(t *testing.T) {
	repo := &fakeAttemptRepo{}
	limiter := NewRateLimiter(repo, settings.Fixed(testRateWindow), settings.Fixed(testRateMaxTries))
	ctx := context.Background()

	for i := 1; i <= testRateMaxTries; i++ {
		admitted, err := limiter.Admit(ctx, "203.0.113.5", "dnsuser")
		if err != nil {
			t.Fatalf("attempt %d failed: %v", i, err)
		}
		if !admitted {
			t.Fatalf("attempt %d was refused, the limit is %d", i, testRateMaxTries)
		}
	}

	admitted, err := limiter.Admit(ctx, "203.0.113.5", "dnsuser")
	if err != nil {
		t.Fatalf("Admit returned an error: %v", err)
	}
	if admitted {
		t.Errorf("attempt %d was allowed", testRateMaxTries+1)
	}
}

func TestRateLimiterDoesNotRecordARefusedAttempt(t *testing.T) {
	// A refused attempt that was still recorded would push the window forward
	// on every retry, and an operator who keeps trying would never get back in.
	repo := &fakeAttemptRepo{}
	limiter := NewRateLimiter(repo, settings.Fixed(testRateWindow), settings.Fixed(testRateMaxTries))
	ctx := context.Background()

	for range testRateMaxTries + 5 {
		if _, err := limiter.Admit(ctx, "203.0.113.5", "dnsuser"); err != nil {
			t.Fatalf("Admit returned an error: %v", err)
		}
	}

	if len(repo.attempts) != testRateMaxTries {
		t.Errorf("%d attempts were stored, want %d", len(repo.attempts), testRateMaxTries)
	}
}

func TestRateLimiterCountsPerAddress(t *testing.T) {
	// Keying on the user name instead would let anyone lock out a known
	// account by guessing at it.
	repo := &fakeAttemptRepo{}
	limiter := NewRateLimiter(repo, settings.Fixed(testRateWindow), settings.Fixed(testRateMaxTries))
	ctx := context.Background()

	for range testRateMaxTries {
		if _, err := limiter.Admit(ctx, "203.0.113.5", "dnsuser"); err != nil {
			t.Fatalf("Admit returned an error: %v", err)
		}
	}

	admitted, err := limiter.Admit(ctx, "198.51.100.9", "dnsuser")
	if err != nil {
		t.Fatalf("Admit returned an error: %v", err)
	}
	if !admitted {
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
		if _, err := limiter.Admit(ctx, "203.0.113.5", "dnsuser"); err != nil {
			t.Fatalf("Admit returned an error: %v", err)
		}
	}

	limiter.now = func() time.Time { return base.Add(testRateWindow + time.Minute) }

	admitted, err := limiter.Admit(ctx, "203.0.113.5", "dnsuser")
	if err != nil {
		t.Fatalf("Admit returned an error: %v", err)
	}
	if !admitted {
		t.Error("the address is still blocked after the window passed")
	}
	if len(repo.attempts) != 1 {
		t.Errorf("%d attempts survived the prune, want only the new one", len(repo.attempts))
	}
}

func TestRateLimiterReportsStorageFailures(t *testing.T) {
	// A limiter that silently allowed everything when its storage broke would
	// be worse than no limiter, because nothing would report the fault.
	failure := errors.New("database is gone")

	limiter := NewRateLimiter(&fakeAttemptRepo{err: failure},
		settings.Fixed(testRateWindow), settings.Fixed(testRateMaxTries))

	admitted, err := limiter.Admit(context.Background(), "203.0.113.5", "dnsuser")
	if !errors.Is(err, failure) {
		t.Errorf("Admit returned %v, want the storage failure", err)
	}
	if admitted {
		t.Error("the attempt was admitted although the storage failed")
	}
}
