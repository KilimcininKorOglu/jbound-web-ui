package database

import (
	"context"
	"fmt"
	"os"
)

// SnapshotTo writes a consistent copy of the database to target.
//
// A file level copy cannot be trusted while the panel runs. The database is
// open in WAL mode, so the state is spread across the file and its -wal
// sidecar, and a copy taken with cp or tar can catch the two at different
// moments. The restored file is then either short of committed transactions or
// refused as corrupt, which is discovered during the recovery itself.
//
// VACUUM INTO runs under a read transaction and writes one self contained
// database, so the result is a single point in time and needs no sidecar.
//
// The snapshot is read back and checked before this returns. A backup nobody
// verified is a backup nobody can rely on.
func (db *DB) SnapshotTo(ctx context.Context, target string) error {
	// SQLite refuses to write over an existing file, which is the behaviour we
	// want. Saying so here reads better than the driver's own message.
	if _, err := os.Stat(target); err == nil {
		return fmt.Errorf("%s already exists", target)
	}

	if _, err := db.ExecContext(ctx, "VACUUM INTO ?", target); err != nil {
		return fmt.Errorf("cannot write the snapshot to %s: %w", target, err)
	}

	// The source is 0600 because the audit rows name who changed which record
	// from which address. A copy of them is worth no less.
	if err := os.Chmod(target, 0o600); err != nil {
		return fmt.Errorf("cannot set mode 0600 on %s: %w", target, err)
	}

	return verifySnapshot(ctx, target)
}

// verifySnapshot opens the written file and asks SQLite whether it is sound.
func verifySnapshot(ctx context.Context, target string) error {
	snapshot, err := OpenExisting(ctx, target)
	if err != nil {
		return fmt.Errorf("cannot reopen the snapshot: %w", err)
	}
	defer snapshot.Close()

	var result string
	if err := snapshot.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&result); err != nil {
		return fmt.Errorf("cannot check the snapshot: %w", err)
	}
	if result != "ok" {
		return fmt.Errorf("the snapshot did not pass the integrity check: %s", result)
	}
	return nil
}
