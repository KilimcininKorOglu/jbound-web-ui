package auth

import (
	"context"
	"fmt"
	"time"
)

// AttemptRepository stores login attempts.
type AttemptRepository interface {
	// Admit prunes the rows that left the window, counts what is left for one
	// address and records this attempt, all inside one transaction. It reports
	// whether the attempt is inside the limit it was given.
	Admit(ctx context.Context, ip, username string, since, at time.Time, maxTries int) (bool, error)
}

// RateLimiter throttles login attempts per source address.
//
// The address is the key rather than the user name. Keying on the name would
// let anyone lock a known account out by guessing at it.
type RateLimiter struct {
	repo AttemptRepository

	// window and maxTries are read on every attempt, so a limit raised on the
	// settings page takes effect without a restart. That matters most when an
	// operator is locked out and is trying to let themselves back in.
	window   func() time.Duration
	maxTries func() int

	now func() time.Time
}

// NewRateLimiter builds the limiter.
func NewRateLimiter(repo AttemptRepository, window func() time.Duration,
	maxTries func() int) *RateLimiter {

	return &RateLimiter{repo: repo, window: window, maxTries: maxTries, now: time.Now}
}

// Admit reports whether another attempt from this address is permitted, and
// records it when it is.
//
// The decision and the record are one call, because they have to be one step.
// A check that reads the count and writes the row separately lets requests that
// arrive together all see the same pre-burst count and all pass, so the limit
// would bound sequential attempts only.
//
// The row is written before the password is checked, so an attempt that never
// gets an answer still counts against the limit. Rows older than the window are
// pruned on the way, which is the only place that happens.
func (l *RateLimiter) Admit(ctx context.Context, ip, username string) (bool, error) {
	now := l.now().UTC()

	admitted, err := l.repo.Admit(ctx, ip, username, now.Add(-l.window()), now, l.maxTries())
	if err != nil {
		return false, fmt.Errorf("cannot check the login rate: %w", err)
	}
	return admitted, nil
}
