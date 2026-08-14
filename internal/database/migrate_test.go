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

func TestTheLadderMigrationFillsTheServersThatWereAlreadyThere(t *testing.T) {
	// ApplyDefaults only runs when a record is created, so a panel upgraded
	// into these columns would otherwise carry servers with no configuration
	// check and no escalation, and nothing in the interface would say so.
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

	// Put the database back to where it was before this migration ran.
	for _, statement := range []string{
		"ALTER TABLE servers DROP COLUMN check_conf_cmd",
		"ALTER TABLE servers DROP COLUMN reload_fallback_cmd",
		"ALTER TABLE servers DROP COLUMN restart_cmd",
		"DELETE FROM schema_migrations WHERE name = '0006_reload_ladder.sql'",
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("cannot undo the migration (%s): %v", statement, err)
		}
	}
	db.Close()

	upgraded, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("the upgrade failed: %v", err)
	}
	defer upgraded.Close()

	var check, fallback, restart string
	if err := upgraded.QueryRow(
		"SELECT check_conf_cmd, reload_fallback_cmd, restart_cmd FROM servers").
		Scan(&check, &fallback, &restart); err != nil {
		t.Fatalf("cannot read the server back: %v", err)
	}
	for name, got := range map[string]string{
		"check":    check,
		"fallback": fallback,
		"restart":  restart,
	} {
		if strings.TrimSpace(got) == "" {
			t.Errorf("the %s command of the existing server is empty", name)
		}
	}
}

func TestTheLadderMigrationLeavesTheStoredReloadCommandAlone(t *testing.T) {
	// The reload command names a path a sudoers rule on that target holds.
	// Rewriting it during an upgrade would point the panel at a command the
	// target refuses.
	dir := t.TempDir()
	path := filepath.Join(dir, "panel.db")

	db, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open returned an error: %v", err)
	}
	const chosen = "sudo /usr/sbin/service unbound reload"
	if _, err := db.Exec(
		`INSERT INTO servers (name, host, ssh_user, ssh_key_path, reload_cmd)
		 VALUES ('dns1', 'dns1', 'dnsops', 'keys/1.key', ?)`, chosen); err != nil {
		t.Fatalf("cannot seed a server: %v", err)
	}
	for _, statement := range []string{
		"ALTER TABLE servers DROP COLUMN check_conf_cmd",
		"ALTER TABLE servers DROP COLUMN reload_fallback_cmd",
		"ALTER TABLE servers DROP COLUMN restart_cmd",
		"DELETE FROM schema_migrations WHERE name = '0006_reload_ladder.sql'",
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("cannot undo the migration (%s): %v", statement, err)
		}
	}
	db.Close()

	upgraded, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("the upgrade failed: %v", err)
	}
	defer upgraded.Close()

	var reload string
	if err := upgraded.QueryRow("SELECT reload_cmd FROM servers").Scan(&reload); err != nil {
		t.Fatalf("cannot read the server back: %v", err)
	}
	if reload != chosen {
		t.Errorf("reload command = %q, want the stored %q", reload, chosen)
	}
}

func TestTheRenameKeepsTheStoredRecordsPath(t *testing.T) {
	// The stored path names a file the sudoers rules on that target were
	// written for. An upgrade that rewrote it to the new default would point
	// the panel at a file that is not there, on every server that was set up
	// with anything other than the default.
	dir := t.TempDir()
	path := filepath.Join(dir, "panel.db")

	db, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open returned an error: %v", err)
	}

	// Put the database back to where it was before this migration ran, then
	// seed a server that names its own file.
	const chosen = "/opt/unbound/zones/managed.conf"
	for _, statement := range []string{
		"ALTER TABLE servers RENAME COLUMN records_path TO host_entries_path",
		"DELETE FROM schema_migrations WHERE name = '0007_records_path.sql'",
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("cannot undo the migration (%s): %v", statement, err)
		}
	}
	if _, err := db.Exec(
		`INSERT INTO servers (name, host, ssh_user, ssh_key_path, host_entries_path)
		 VALUES ('dns1', 'dns1', 'dnsops', 'keys/1.key', ?)`, chosen); err != nil {
		t.Fatalf("cannot seed a server: %v", err)
	}
	db.Close()

	upgraded, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("the upgrade failed: %v", err)
	}
	defer upgraded.Close()

	if hasColumn(t, upgraded, "servers", "host_entries_path") {
		t.Error("the old column is still there after the rename")
	}

	var stored string
	if err := upgraded.QueryRow("SELECT records_path FROM servers").Scan(&stored); err != nil {
		t.Fatalf("cannot read the server back: %v", err)
	}
	if stored != chosen {
		t.Errorf("records path = %q, want the stored %q", stored, chosen)
	}
}

func TestTheIncludeMigrationFillsTheServersThatWereAlreadyThere(t *testing.T) {
	// A server added before this step has no command for it. Leaving the
	// column empty would skip the repair on exactly the servers that were set
	// up when nothing checked the include line.
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

	for _, statement := range []string{
		"ALTER TABLE servers DROP COLUMN ensure_include_cmd",
		"DELETE FROM schema_migrations WHERE name = '0008_ensure_include.sql'",
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("cannot undo the migration (%s): %v", statement, err)
		}
	}
	db.Close()

	upgraded, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("the upgrade failed: %v", err)
	}
	defer upgraded.Close()

	var command string
	if err := upgraded.QueryRow(
		"SELECT ensure_include_cmd FROM servers").Scan(&command); err != nil {
		t.Fatalf("cannot read the server back: %v", err)
	}
	if strings.TrimSpace(command) == "" {
		t.Error("the existing server has no include repair command")
	}

	// The command carries no arguments, so nothing the panel holds decides
	// which file a managed server writes.
	if fields := strings.Fields(command); len(fields) != 2 {
		t.Errorf("the command carries arguments: %q", command)
	}
}
