package auth

import (
	"context"
	"fmt"
	"time"
)

// Rate limit defaults, taken from the reference project: ten attempts per
// address in a fifteen minute window.
const (
	DefaultRateWindow   = 15 * time.Minute
	DefaultRateMaxTries = 10
)

// AttemptRepository stores login attempts.
type AttemptRepository interface {
	Record(ctx context.Context, ip, username string, at time.Time) error
	CountSince(ctx context.Context, ip string, since time.Time) (int, error)
	DeleteBefore(ctx context.Context, before time.Time) error
}

// RateLimiter throttles login attempts per source address.
//
// The address is the key rather than the user name. Keying on the name would
// let anyone lock a known account out by guessing at it.
type RateLimiter struct {
	repo     AttemptRepository
	window   time.Duration
	maxTries int
	now      func() time.Time
}

// NewRateLimiter builds the limiter.
func NewRateLimiter(repo AttemptRepository, window time.Duration, maxTries int) *RateLimiter {
	return &RateLimiter{repo: repo, window: window, maxTries: maxTries, now: time.Now}
}

// Allow reports whether another attempt from this address is permitted.
//
// Rows older than the window are removed first, matching the reference project.
// The cleanup loop does the same on a timer, so this only bounds the count of a
// single burst.
func (l *RateLimiter) Allow(ctx context.Context, ip string) (bool, error) {
	cutoff := l.now().UTC().Add(-l.window)

	if err := l.repo.DeleteBefore(ctx, cutoff); err != nil {
		return false, fmt.Errorf("cannot prune login attempts: %w", err)
	}

	count, err := l.repo.CountSince(ctx, ip, cutoff)
	if err != nil {
		return false, fmt.Errorf("cannot count login attempts: %w", err)
	}
	return count < l.maxTries, nil
}

// Record stores one attempt.
//
// It runs before the password is checked, so a failure that never returns an
// answer still counts against the limit.
func (l *RateLimiter) Record(ctx context.Context, ip, username string) error {
	if err := l.repo.Record(ctx, ip, username, l.now().UTC()); err != nil {
		return fmt.Errorf("cannot record the login attempt: %w", err)
	}
	return nil
}
