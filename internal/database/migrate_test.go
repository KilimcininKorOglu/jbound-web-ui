package database

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// hasColumn reports whether a table carries a column.
func hasColumn(t *testing.T, db *DB, table, column string) bool {
	t.Helper()

	rows, err := db.Query("SELECT name FROM pragma_table_info(?)", table)
	if err != nil {
		t.Fatalf("cannot read the columns of %s: %v", table, err)
	}
	defer rows.Close()

	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("cannot scan a column name: %v", err)
		}
		if name == column {
			return true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("cannot walk the columns of %s: %v", table, err)
	}
	return false
}

func TestAFailedMigrationLeavesTheSchemaAsItWas(t *testing.T) {
	// 0002 holds two statements: it adds sha256_path and then drops cat_path.
	// The state below makes the first succeed and the second fail, which is
	// exactly what an interrupted upgrade leaves behind. Without one
	// transaction around the file, the added column survives the failure and
	// every later start dies on "duplicate column name".
	path := filepath.Join(t.TempDir(), "wedged.db")

	db, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open returned an error: %v", err)
	}
	if _, err := db.Exec("ALTER TABLE servers DROP COLUMN sha256_path"); err != nil {
		t.Fatalf("cannot undo the column: %v", err)
	}
	if _, err := db.Exec(
		"DELETE FROM schema_migrations WHERE name = '0002_transfer_tools.sql'"); err != nil {
		t.Fatalf("cannot clear the applied row: %v", err)
	}
	db.Close()

	_, err = Open(context.Background(), path)
	if err == nil {
		t.Fatal("the replayed migration was reported as successful")
	}
	if !strings.Contains(err.Error(), "0002_transfer_tools.sql") {
		t.Errorf("the error does not name the migration: %v", err)
	}

	after, err := OpenExisting(context.Background(), path)
	if err != nil {
		t.Fatalf("the database cannot be opened after the failure: %v", err)
	}
	defer after.Close()

	if hasColumn(t, after, "servers", "sha256_path") {
		t.Error("the first half of the migration survived the failure of the second")
	}

	var recorded int
	err = after.QueryRow(
		"SELECT COUNT(*) FROM schema_migrations WHERE name = '0002_transfer_tools.sql'").Scan(&recorded)
	if err != nil {
		t.Fatalf("cannot read the applied list: %v", err)
	}
	if recorded != 0 {
		t.Error("a migration that failed was recorded as applied")
	}
}

func TestAnUpgradeKeepsACopyOfWhatItFound(t *testing.T) {
	// 0002 drops a column the previous binary reads, so the copy taken here is
	// the only way back to the version that was running before the upgrade.
	dir := t.TempDir()
	path := filepath.Join(dir, "panel.db")

	db, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open returned an error: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO servers (name, host, ssh_user, ssh_key_path)
		 VALUES ('dns1', 'dns1', 'dnsops', 'keys/1.key')`); err != nil {
		t.Fatalf("cannot seed a server: %v", err)
	}
	// Put the database back to where it was before the settings migration.
	if _, err := db.Exec("DROP TABLE settings"); err != nil {
		t.Fatalf("cannot drop the settings table: %v", err)
	}
	if _, err := db.Exec(
		"DELETE FROM schema_migrations WHERE name = '0003_settings.sql'"); err != nil {
		t.Fatalf("cannot clear the applied row: %v", err)
	}
	db.Close()

	upgraded, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("the upgrade failed: %v", err)
	}
	defer upgraded.Close()

	copyPath := path + ".before-0003_settings.sql"
	before, err := OpenExisting(context.Background(), copyPath)
	if err != nil {
		t.Fatalf("no copy was kept before the migration: %v", err)
	}
	defer before.Close()

	var name string
	if err := before.QueryRow("SELECT name FROM servers").Scan(&name); err != nil {
		t.Fatalf("the copy cannot be read: %v", err)
	}
	if name != "dns1" {
		t.Errorf("the copy holds %q", name)
	}

	// The copy is from before the migration, so it must not carry the table
	// the migration created.
	var settings int
	err = before.QueryRow(
		"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='settings'").Scan(&settings)
	if err != nil {
		t.Fatalf("cannot inspect the copy: %v", err)
	}
	if settings != 0 {
		t.Error("the copy was taken after the migration rather than before it")
	}
}

func TestASecondUpgradeAttemptKeepsTheFirstCopy(t *testing.T) {
	// The copy from the first attempt describes the state the operator wants
	// back. Overwriting it with the state after a partial run would replace
	// the answer with the question.
	dir := t.TempDir()
	path := filepath.Join(dir, "panel.db")
	copyPath := path + ".before-0003_settings.sql"

	db, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open returned an error: %v", err)
	}
	db.Close()

	if err := os.WriteFile(copyPath, []byte("the first attempt"), 0o600); err != nil {
		t.Fatalf("cannot place the earlier copy: %v", err)
	}
	if _, err := os.Stat(copyPath); err != nil {
		t.Fatalf("cannot stat the earlier copy: %v", err)
	}

	db, err = Open(context.Background(), path)
	if err != nil {
		t.Fatalf("reopen failed: %v", err)
	}
	if _, err := db.Exec("DROP TABLE settings"); err != nil {
		t.Fatalf("cannot drop the settings table: %v", err)
	}
	if _, err := db.Exec(
		"DELETE FROM schema_migrations WHERE name = '0003_settings.sql'"); err != nil {
		t.Fatalf("cannot clear the applied row: %v", err)
	}
	db.Close()

	again, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("the upgrade failed: %v", err)
	}
	defer again.Close()

	content, err := os.ReadFile(copyPath)
	if err != nil {
		t.Fatalf("cannot read the copy: %v", err)
	}
	if string(content) != "the first attempt" {
		t.Error("the copy from the first attempt was overwritten")
	}
}

func TestAFreshDatabaseKeepsNoPreMigrationCopy(t *testing.T) {
	// There is nothing to go back to, and an empty file next to the database
	// only invites the question of what it is for.
	dir := t.TempDir()

	db, err := Open(context.Background(), filepath.Join(dir, "panel.db"))
	if err != nil {
		t.Fatalf("Open returned an error: %v", err)
	}
	defer db.Close()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("cannot read the directory: %v", err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".before-") {
			t.Errorf("a fresh install kept %s", entry.Name())
		}
	}
}
