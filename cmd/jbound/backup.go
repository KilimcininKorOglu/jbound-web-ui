package main

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"jbound/internal/config"
	"jbound/internal/database"
	"jbound/internal/preflight"
	"jbound/internal/server"
)

// runBackup writes a self contained copy of the panel state.
//
// It is a command rather than a page. The directory holds the SSH private key
// of every managed resolver, and no HTTP response may carry one of those.
//
// Nothing is written to the audit trail. A command whose whole point is to
// leave the database untouched should not begin by writing to it.
func runBackup(target string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	preflight.WarnIfRoot("the backup will belong to root, " +
		"and the service account will not read it back")

	// The database is opened before the directory is created, so a run that
	// cannot read it leaves no empty directory behind for the next attempt to
	// trip over.
	db, err := database.OpenExisting(context.Background(), cfg.DBPath)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := os.Mkdir(target, 0o700); err != nil {
		return fmt.Errorf("cannot create %s: %w", target, err)
	}

	if err := db.SnapshotTo(context.Background(), filepath.Join(target, "jbound.db")); err != nil {
		return err
	}

	keys, err := copyKeys(cfg.KeyDir, filepath.Join(target, server.KeySubdir))
	if err != nil {
		return err
	}

	fmt.Printf("Wrote the database and %d key(s) to %s.\n", keys, target)
	fmt.Println("The keys reach every managed resolver, so encrypt this directory before it leaves the host.")
	return nil
}

// copyKeys copies the private keys and reports how many it wrote.
func copyKeys(source, target string) (int, error) {
	if err := os.Mkdir(target, 0o700); err != nil {
		return 0, fmt.Errorf("cannot create %s: %w", target, err)
	}

	entries, err := os.ReadDir(source)
	if err != nil {
		return 0, fmt.Errorf("cannot read %s: %w", source, err)
	}

	copied := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".key") {
			continue
		}
		if err := copyKey(filepath.Join(source, entry.Name()),
			filepath.Join(target, entry.Name())); err != nil {
			return 0, err
		}
		copied++
	}
	return copied, nil
}

// copyKey writes one key with the mode the original has to keep.
func copyKey(source, target string) error {
	content, err := os.ReadFile(source)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", source, err)
	}
	if err := os.WriteFile(target, content, fs.FileMode(0o600)); err != nil {
		return fmt.Errorf("cannot write %s: %w", target, err)
	}
	return nil
}
