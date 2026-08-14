package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"jbound/internal/database"
)

// seedDataDir builds a data directory the way the panel leaves one behind.
func seedDataDir(t *testing.T) string {
	t.Helper()

	dataDir := t.TempDir()
	keyDir := filepath.Join(dataDir, "keys")
	if err := os.Mkdir(keyDir, 0o700); err != nil {
		t.Fatalf("cannot create the key directory: %v", err)
	}

	db, err := database.Open(context.Background(), filepath.Join(dataDir, "jbound.db"))
	if err != nil {
		t.Fatalf("cannot create the database: %v", err)
	}
	if _, err := db.Exec(
		"INSERT INTO servers (name, host, ssh_user, ssh_port, ssh_key_path) VALUES (?, ?, ?, ?, ?)",
		"dns1", "dns1.example", "dnsops", 22, "keys/1.key"); err != nil {
		t.Fatalf("cannot seed a server: %v", err)
	}
	db.Close()

	for _, name := range []string{"1.key", "2.key"} {
		if err := os.WriteFile(filepath.Join(keyDir, name),
			[]byte("PRIVATE KEY "+name), 0o600); err != nil {
			t.Fatalf("cannot write a key: %v", err)
		}
	}
	// Something that is not a key, which the backup has no business copying.
	if err := os.WriteFile(filepath.Join(keyDir, "notes.txt"), []byte("scratch"), 0o600); err != nil {
		t.Fatalf("cannot write the extra file: %v", err)
	}

	t.Setenv("DATA_DIR", dataDir)
	return dataDir
}

func TestBackupWritesTheDatabaseAndTheKeys(t *testing.T) {
	seedDataDir(t)
	target := filepath.Join(t.TempDir(), "backup")

	if err := runBackup(target); err != nil {
		t.Fatalf("runBackup returned an error: %v", err)
	}

	db, err := database.OpenExisting(context.Background(), filepath.Join(target, "jbound.db"))
	if err != nil {
		t.Fatalf("the backup database cannot be opened: %v", err)
	}
	defer db.Close()

	var name string
	if err := db.QueryRow("SELECT name FROM servers").Scan(&name); err != nil {
		t.Fatalf("cannot read the backup: %v", err)
	}
	if name != "dns1" {
		t.Errorf("the backup holds %q", name)
	}

	for _, key := range []string{"1.key", "2.key"} {
		content, err := os.ReadFile(filepath.Join(target, "keys", key))
		if err != nil {
			t.Errorf("%s is missing from the backup: %v", key, err)
			continue
		}
		if string(content) != "PRIVATE KEY "+key {
			t.Errorf("%s came out as %q", key, content)
		}
	}

	if _, err := os.Stat(filepath.Join(target, "keys", "notes.txt")); err == nil {
		t.Error("the backup copied a file that is not a key")
	}
}

func TestBackupKeepsTheKeysUnreadableToOthers(t *testing.T) {
	seedDataDir(t)
	target := filepath.Join(t.TempDir(), "backup")

	if err := runBackup(target); err != nil {
		t.Fatalf("runBackup returned an error: %v", err)
	}

	dir, err := os.Stat(filepath.Join(target, "keys"))
	if err != nil {
		t.Fatalf("cannot stat the key directory: %v", err)
	}
	if dir.Mode().Perm() != 0o700 {
		t.Errorf("the key directory is %v, want 0700", dir.Mode().Perm())
	}

	key, err := os.Stat(filepath.Join(target, "keys", "1.key"))
	if err != nil {
		t.Fatalf("cannot stat the key: %v", err)
	}
	if key.Mode().Perm() != 0o600 {
		t.Errorf("the key is %v, want 0600", key.Mode().Perm())
	}
}

func TestBackupRefusesATargetThatExists(t *testing.T) {
	// Writing into a directory that is already there could mix two backups
	// taken at different times into one that matches neither.
	seedDataDir(t)

	target := filepath.Join(t.TempDir(), "backup")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("cannot create the target: %v", err)
	}

	if err := runBackup(target); err == nil {
		t.Fatal("an existing target was accepted")
	}
}

func TestBackupLeavesNothingBehindWhenTheDatabaseIsMissing(t *testing.T) {
	t.Setenv("DATA_DIR", t.TempDir())
	target := filepath.Join(t.TempDir(), "backup")

	if err := runBackup(target); err == nil {
		t.Fatal("a missing database was accepted")
	}
	if _, err := os.Stat(target); err == nil {
		t.Error("a failed backup left its target directory behind")
	}
}

func TestBackupDoesNotChangeTheSourceDatabase(t *testing.T) {
	// The command reads. A panel of another version may be running against
	// this file, and a migration applied from here would be a surprise.
	dataDir := seedDataDir(t)
	source := filepath.Join(dataDir, "jbound.db")

	before, err := os.Stat(source)
	if err != nil {
		t.Fatalf("cannot stat the source: %v", err)
	}

	if err := runBackup(filepath.Join(t.TempDir(), "backup")); err != nil {
		t.Fatalf("runBackup returned an error: %v", err)
	}

	after, err := os.Stat(source)
	if err != nil {
		t.Fatalf("cannot stat the source: %v", err)
	}
	if before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		t.Error("the backup changed the database it was reading")
	}
}
