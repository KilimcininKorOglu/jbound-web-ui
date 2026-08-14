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
	db, err := connect(ctx, path)
	if err != nil {
		return nil, err
	}

	if err := os.Chmod(path, 0o600); err != nil {
		db.Close()
		return nil, fmt.Errorf("cannot set mode 0600 on %s: %w", path, err)
	}

	if err := db.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// OpenExisting opens a database without changing it.
//
// No migration runs and the mode is left alone, so a command that only reads
// the file cannot alter the schema of a panel that is running a different
// version of the binary.
func OpenExisting(ctx context.Context, path string) (*DB, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", path, err)
	}
	return connect(ctx, path)
}

// connect opens the handle and applies the pragmas both entry points need.
func connect(ctx context.Context, path string) (*DB, error) {
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
	return &DB{DB: handle, path: path}, nil
}

// Path reports the database file location.
func (db *DB) Path() string { return db.path }

// migrate applies every embedded migration in name order.
//
// The applied list is what makes a second start a no operation. The first file
// is idempotent on its own, but a migration that alters a table cannot be, so
// the record of what already ran is the mechanism rather than a convenience.
func (db *DB) migrate(ctx context.Context) error {
	const createTable = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    name       TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now'))
)`
	if _, err := db.ExecContext(ctx, createTable); err != nil {
		return fmt.Errorf("cannot create schema_migrations: %w", err)
	}

	pending, applied, err := db.pendingMigrations(ctx)
	if err != nil {
		return err
	}
	if len(pending) == 0 {
		return nil
	}

	// Nothing to roll back to on a database that has never been migrated, so a
	// fresh install is not asked to keep a copy of an empty file.
	if applied > 0 {
		if err := db.snapshotBefore(ctx, pending[0]); err != nil {
			return err
		}
	}

	for _, name := range pending {
		if err := db.apply(ctx, name); err != nil {
			return err
		}
	}
	return nil
}

// pendingMigrations lists what has not run yet and how much already has.
func (db *DB) pendingMigrations(ctx context.Context) ([]string, int, error) {
	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		return nil, 0, fmt.Errorf("cannot read the migrations directory: %w", err)
	}

	var applied int
	if err := db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM schema_migrations").Scan(&applied); err != nil {
		return nil, 0, fmt.Errorf("cannot read the applied migrations: %w", err)
	}

	var pending []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()

		var seen int
		row := db.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM schema_migrations WHERE name = ?", name)
		if err := row.Scan(&seen); err != nil {
			return nil, 0, fmt.Errorf("cannot check migration %s: %w", name, err)
		}
		if seen == 0 {
			pending = append(pending, name)
		}
	}
	return pending, applied, nil
}

// snapshotBefore keeps a copy of the database from before the upgrade.
//
// A migration can be destructive: 0002 drops a column the previous binary
// reads, so once it has run there is no way back to the version that was
// running an hour ago. The copy is that way back.
//
// A failure here stops the start. The copy is what protects against the very
// step that follows it, and running a one way migration without it would take
// away the only answer to "put it back the way it was".
func (db *DB) snapshotBefore(ctx context.Context, name string) error {
	target := db.path + ".before-" + name

	// A copy from an earlier attempt describes the state before the first try,
	// which is the one worth keeping. Writing a second one over it would
	// replace the answer with the question.
	if _, err := os.Stat(target); err == nil {
		return nil
	}
	return db.SnapshotTo(ctx, target)
}

// apply runs one migration and records it in the same transaction.
//
// The two have to commit together. A file may hold several statements, and
// SQLite commits each one on its own outside a transaction, so an interrupted
// run left the schema half changed with nothing in the applied list. The next
// start replayed the file, died on the half that was already there, and
// systemd restarted into the same failure every five seconds.
func (db *DB) apply(ctx context.Context, name string) error {
	statements, err := migrations.ReadFile("migrations/" + name)
	if err != nil {
		return fmt.Errorf("cannot read migration %s: %w", name, err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("cannot start migration %s: %w", name, err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, string(statements)); err != nil {
		return fmt.Errorf("migration %s failed: %w", name, err)
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO schema_migrations (name) VALUES (?)", name); err != nil {
		return fmt.Errorf("cannot record migration %s: %w", name, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("cannot commit migration %s: %w", name, err)
	}
	return nil
}

// Cleanup removes expired sessions and stale login attempts.
//
// A login attempt older than the rate limit window no longer counts towards
// the limit, so keeping it serves no purpose.
func (db *DB) Cleanup(ctx context.Context, sessionTimeout,
	attemptWindow time.Duration) error {

	if _, err := db.ExecContext(ctx,
		"DELETE FROM sessions WHERE last_active < datetime('now', ?)",
		secondsAgo(sessionTimeout)); err != nil {
		return fmt.Errorf("cannot delete expired sessions: %w", err)
	}
	if _, err := db.ExecContext(ctx,
		"DELETE FROM login_attempts WHERE attempted_at < datetime('now', ?)",
		secondsAgo(attemptWindow)); err != nil {
		return fmt.Errorf("cannot delete stale login attempts: %w", err)
	}
	return nil
}

// secondsAgo renders a duration as the modifier SQLite reads.
func secondsAgo(d time.Duration) string {
	return fmt.Sprintf("-%d seconds", int(d.Seconds()))
}

// RunCleanupLoop calls Cleanup on a ticker until the context is cancelled.
//
// The two durations are accessors, because both are settings now and a value
// read once at startup would keep rows the operator asked the panel to drop.
func (db *DB) RunCleanupLoop(ctx context.Context, every time.Duration,
	sessionTimeout, attemptWindow func() time.Duration, onError func(error)) {

	ticker := time.NewTicker(every)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := db.Cleanup(ctx, sessionTimeout(), attemptWindow()); err != nil && onError != nil {
				onError(err)
			}
		}
	}
}
