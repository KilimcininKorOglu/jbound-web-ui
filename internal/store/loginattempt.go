package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// LoginAttempts stores the rows the login rate limiter counts.
type LoginAttempts struct {
	db *sql.DB
}

// NewLoginAttempts builds the store.
func NewLoginAttempts(db *sql.DB) *LoginAttempts { return &LoginAttempts{db: db} }

// Admit prunes, counts and records one login attempt in a single transaction.
//
// The three steps have to be one step. Two round trips let requests that arrive
// together all read the same pre-burst count and all pass, which bounds
// sequential attempts only and leaves the panel open to a concurrent one.
//
// A refused attempt is not recorded. Recording it would push the window forward
// on every refused request, and a caller that keeps trying would never be let
// back in.
//
// The user name is kept for the operator who reads the table after an incident.
// No password or any part of one is stored.
func (a *LoginAttempts) Admit(ctx context.Context, ip, username string,
	since, at time.Time, maxTries int) (bool, error) {

	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("cannot start the login attempt transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx,
		"DELETE FROM login_attempts WHERE attempted_at < ?", formatTime(since)); err != nil {
		return false, fmt.Errorf("cannot delete stale login attempts: %w", err)
	}

	var count int
	err = tx.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM login_attempts WHERE ip_address = ? AND attempted_at >= ?",
		ip, formatTime(since)).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("cannot count the login attempts: %w", err)
	}

	if count >= maxTries {
		// The prune is worth keeping even though the attempt is refused.
		if err := tx.Commit(); err != nil {
			return false, fmt.Errorf("cannot commit the login attempt prune: %w", err)
		}
		return false, nil
	}

	if _, err := tx.ExecContext(ctx,
		"INSERT INTO login_attempts (ip_address, username, attempted_at) VALUES (?, ?, ?)",
		ip, username, formatTime(at)); err != nil {
		return false, fmt.Errorf("cannot insert the login attempt: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("cannot commit the login attempt: %w", err)
	}
	return true, nil
}
