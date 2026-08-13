// Package database opens the SQLite store and applies the schema.
//
// SQLite holds panel state only: managed servers, groups, per server state,
// the record cache, audit logs, login attempts and sessions. DNS records
// themselves stay in the host entries file on each managed server.
package database

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"os"
	"time"

	_ "modernc.org/sqlite" // pure Go driver, keeps the binary free of cgo
)

//go:embed migrations/*.sql
var migrations embed.FS

// DB wraps the SQLite handle.
type DB struct {
	*sql.DB
	path string
}

// pragmas run on every connection in the pool.
//
// SQLite applies most pragmas per connection, not per database, so setting
// them once after Open would leave later pool connections on the defaults.
var pragmas = []string{
	"PRAGMA journal_mode = WAL",
	"PRAGMA busy_timeout = 5000",
	"PRAGMA foreign_keys = ON",
	"PRAGMA synchronous = NORMAL",
}

// Open prepares the database file and applies the schema.
//
// The file is created with mode 0600 because audit rows record who changed
// which DNS record from which address.
func Open(ctx context.Context, path string) (*DB, error) {
	dsn := "file:" + path + "?_txlock=immediate"

	handle, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("cannot open %s: %w", path, err)
	}

	// A single writer avoids SQLITE_BUSY under concurrent fleet operations.
	// Reads still run in parallel thanks to WAL.
	handle.SetMaxOpenConns(1)
	handle.SetMaxIdleConns(1)
	handle.SetConnMaxLifetime(0)

	for _, pragma := range pragmas {
		if _, err := handle.ExecContext(ctx, pragma); err != nil {
			handle.Close()
			return nil, fmt.Errorf("cannot apply %q: %w", pragma, err)
		}
	}

	if err := os.Chmod(path, 0o600); err != nil {
		handle.Close()
		return nil, fmt.Errorf("cannot set mode 0600 on %s: %w", path, err)
	}

	db := &DB{DB: handle, path: path}
	if err := db.migrate(ctx); err != nil {
		handle.Close()
		return nil, err
	}
	return db, nil
}

// Path reports the database file location.
func (db *DB) Path() string { return db.path }

// migrate applies every embedded migration in name order.
//
// Each file is idempotent, so a second start is a no operation. The applied
// list is recorded anyway, so a future migration can tell what already ran.
func (db *DB) migrate(ctx context.Context) error {
	const createTable = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    name       TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now'))
)`
	if _, err := db.ExecContext(ctx, createTable); err != nil {
		return fmt.Errorf("cannot create schema_migrations: %w", err)
	}

	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("cannot read the migrations directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()

		var applied int
		row := db.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM schema_migrations WHERE name = ?", name)
		if err := row.Scan(&applied); err != nil {
			return fmt.Errorf("cannot check migration %s: %w", name, err)
		}
		if applied > 0 {
			continue
		}

		statements, err := migrations.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("cannot read migration %s: %w", name, err)
		}
		if _, err := db.ExecContext(ctx, string(statements)); err != nil {
			return fmt.Errorf("migration %s failed: %w", name, err)
		}
		if _, err := db.ExecContext(ctx,
			"INSERT INTO schema_migrations (name) VALUES (?)", name); err != nil {
			return fmt.Errorf("cannot record migration %s: %w", name, err)
		}
	}
	return nil
}

// Cleanup removes expired sessions and stale login attempts.
//
// Login attempts older than fifteen minutes no longer count towards the rate
// limit, matching the reference project, so keeping them serves no purpose.
func (db *DB) Cleanup(ctx context.Context, sessionTimeout time.Duration) error {
	cutoff := fmt.Sprintf("-%d seconds", int(sessionTimeout.Seconds()))

	if _, err := db.ExecContext(ctx,
		"DELETE FROM sessions WHERE last_active < datetime('now', ?)", cutoff); err != nil {
		return fmt.Errorf("cannot delete expired sessions: %w", err)
	}
	if _, err := db.ExecContext(ctx,
		"DELETE FROM login_attempts WHERE attempted_at < datetime('now', '-15 minutes')"); err != nil {
		return fmt.Errorf("cannot delete stale login attempts: %w", err)
	}
	return nil
}

// RunCleanupLoop calls Cleanup on a ticker until the context is cancelled.
func (db *DB) RunCleanupLoop(ctx context.Context, every time.Duration,
	sessionTimeout time.Duration, onError func(error)) {

	ticker := time.NewTicker(every)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := db.Cleanup(ctx, sessionTimeout); err != nil && onError != nil {
				onError(err)
			}
		}
	}
}
