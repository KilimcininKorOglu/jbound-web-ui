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

// Record stores one attempt.
//
// The user name is kept for the operator who reads the table after an incident.
// No password or any part of one is stored.
func (a *LoginAttempts) Record(ctx context.Context, ip, username string, at time.Time) error {
	_, err := a.db.ExecContext(ctx,
		"INSERT INTO login_attempts (ip_address, username, attempted_at) VALUES (?, ?, ?)",
		ip, username, formatTime(at))
	if err != nil {
		return fmt.Errorf("cannot insert the login attempt: %w", err)
	}
	return nil
}

// CountSince counts the attempts from one address inside the window.
func (a *LoginAttempts) CountSince(ctx context.Context, ip string, since time.Time) (int, error) {
	var count int
	err := a.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM login_attempts WHERE ip_address = ? AND attempted_at >= ?",
		ip, formatTime(since)).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("cannot count the login attempts: %w", err)
	}
	return count, nil
}

// DeleteBefore removes attempts that left the window.
func (a *LoginAttempts) DeleteBefore(ctx context.Context, before time.Time) error {
	_, err := a.db.ExecContext(ctx,
		"DELETE FROM login_attempts WHERE attempted_at < ?", formatTime(before))
	if err != nil {
		return fmt.Errorf("cannot delete stale login attempts: %w", err)
	}
	return nil
}
