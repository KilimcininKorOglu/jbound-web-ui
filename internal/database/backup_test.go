package database

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// seedServer writes one row the snapshot has to carry.
func seedServer(t *testing.T, db *DB, name string) {
	t.Helper()

	_, err := db.Exec(
		"INSERT INTO servers (name, host, ssh_user, ssh_port, ssh_key_path) VALUES (?, ?, ?, ?, ?)",
		name, name+".example", "dnsops", 22, "keys/1.key")
	if err != nil {
		t.Fatalf("cannot seed a server: %v", err)
	}
}

func TestASnapshotCarriesWhatTheSourceHeld(t *testing.T) {
	db := openTestDB(t)
	seedServer(t, db, "dns1")
	seedServer(t, db, "dns2")

	target := filepath.Join(t.TempDir(), "snapshot.db")
	if err := db.SnapshotTo(context.Background(), target); err != nil {
		t.Fatalf("SnapshotTo returned an error: %v", err)
	}

	snapshot, err := OpenExisting(context.Background(), target)
	if err != nil {
		t.Fatalf("cannot open the snapshot: %v", err)
	}
	defer snapshot.Close()

	var count int
	if err := snapshot.QueryRow("SELECT COUNT(*) FROM servers").Scan(&count); err != nil {
		t.Fatalf("cannot read the snapshot: %v", err)
	}
	if count != 2 {
		t.Errorf("the snapshot holds %d servers, want 2", count)
	}
}

func TestASnapshotNeedsNoSidecarToBeReadable(t *testing.T) {
	// This is the whole reason the command exists. A cp of a live WAL database
	// depends on the -wal file being copied at the same instant; a snapshot
	// must stand on its own.
	db := openTestDB(t)
	seedServer(t, db, "dns1")

	dir := t.TempDir()
	target := filepath.Join(dir, "snapshot.db")
	if err := db.SnapshotTo(context.Background(), target); err != nil {
		t.Fatalf("SnapshotTo returned an error: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("cannot read the target directory: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("the snapshot left %d files behind, want the database alone", len(entries))
	}
}

func TestASnapshotIsCheckedBeforeItIsCalledDone(t *testing.T) {
	db := openTestDB(t)
	seedServer(t, db, "dns1")

	target := filepath.Join(t.TempDir(), "snapshot.db")
	if err := db.SnapshotTo(context.Background(), target); err != nil {
		t.Fatalf("SnapshotTo returned an error: %v", err)
	}

	snapshot, err := OpenExisting(context.Background(), target)
	if err != nil {
		t.Fatalf("cannot open the snapshot: %v", err)
	}
	defer snapshot.Close()

	var result string
	if err := snapshot.QueryRow("PRAGMA integrity_check").Scan(&result); err != nil {
		t.Fatalf("cannot check the snapshot: %v", err)
	}
	if result != "ok" {
		t.Errorf("integrity_check = %q", result)
	}
}

func TestASnapshotRefusesToWriteOverAnExistingFile(t *testing.T) {
	db := openTestDB(t)

	target := filepath.Join(t.TempDir(), "snapshot.db")
	if err := os.WriteFile(target, []byte("an older backup"), 0o600); err != nil {
		t.Fatalf("cannot place the existing file: %v", err)
	}

	if err := db.SnapshotTo(context.Background(), target); err == nil {
		t.Fatal("an existing backup was overwritten")
	}

	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("cannot read the target: %v", err)
	}
	if string(content) != "an older backup" {
		t.Error("the existing file was changed")
	}
}

func TestASnapshotIsWrittenWithMode0600(t *testing.T) {
	// It carries the audit rows, which name who changed which record from
	// which address, and the whole server inventory.
	db := openTestDB(t)

	target := filepath.Join(t.TempDir(), "snapshot.db")
	if err := db.SnapshotTo(context.Background(), target); err != nil {
		t.Fatalf("SnapshotTo returned an error: %v", err)
	}

	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("cannot stat the snapshot: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestASnapshotTakenDuringWritesIsStillSound(t *testing.T) {
	db := openTestDB(t)
	seedServer(t, db, "dns0")

	var wait sync.WaitGroup
	stop := make(chan struct{})

	wait.Go(func() {
		for i := range 200 {
			select {
			case <-stop:
				return
			default:
			}
			_, _ = db.Exec(
				"INSERT INTO audit_logs (uid, username, action, details, ip_address) "+
					"VALUES (?, ?, ?, ?, ?)",
				1000+i, "dnsadmin", "dns_add", "a record", "192.0.2.1")
		}
	})

	target := filepath.Join(t.TempDir(), "snapshot.db")
	err := db.SnapshotTo(context.Background(), target)
	close(stop)
	wait.Wait()

	if err != nil {
		t.Fatalf("SnapshotTo returned an error: %v", err)
	}

	snapshot, err := OpenExisting(context.Background(), target)
	if err != nil {
		t.Fatalf("cannot open the snapshot: %v", err)
	}
	defer snapshot.Close()

	var servers int
	if err := snapshot.QueryRow("SELECT COUNT(*) FROM servers").Scan(&servers); err != nil {
		t.Fatalf("cannot read the snapshot: %v", err)
	}
	if servers != 1 {
		t.Errorf("the snapshot holds %d servers, want 1", servers)
	}
}

func TestOpenExistingLeavesTheSchemaAlone(t *testing.T) {
	// A command that only reads the file must not migrate a database a panel
	// of another version is running against.
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	db, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open returned an error: %v", err)
	}
	if _, err := db.Exec("DELETE FROM schema_migrations"); err != nil {
		t.Fatalf("cannot clear the applied list: %v", err)
	}
	db.Close()

	again, err := OpenExisting(context.Background(), path)
	if err != nil {
		t.Fatalf("OpenExisting returned an error: %v", err)
	}
	defer again.Close()

	var applied int
	if err := again.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&applied); err != nil {
		t.Fatalf("cannot count the applied migrations: %v", err)
	}
	if applied != 0 {
		t.Errorf("%d migrations were applied by a read only open", applied)
	}
}

func TestOpenExistingRefusesAMissingFile(t *testing.T) {
	_, err := OpenExisting(context.Background(), filepath.Join(t.TempDir(), "absent.db"))
	if err == nil {
		t.Fatal("a missing database was accepted")
	}
}
