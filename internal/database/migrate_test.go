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
	defer func() { _ = rows.Close() }()

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
	_ = db.Close()

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
	defer func() { _ = after.Close() }()

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
	_ = db.Close()

	upgraded, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("the upgrade failed: %v", err)
	}
	defer func() { _ = upgraded.Close() }()

	copyPath := path + ".before-0003_settings.sql"
	before, err := OpenExisting(context.Background(), copyPath)
	if err != nil {
		t.Fatalf("no copy was kept before the migration: %v", err)
	}
	defer func() { _ = before.Close() }()

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
	_ = db.Close()

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
	_ = db.Close()

	again, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("the upgrade failed: %v", err)
	}
	defer func() { _ = again.Close() }()

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
	defer func() { _ = db.Close() }()

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
	_ = db.Close()

	upgraded, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("the upgrade failed: %v", err)
	}
	defer func() { _ = upgraded.Close() }()

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
	_ = db.Close()

	upgraded, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("the upgrade failed: %v", err)
	}
	defer func() { _ = upgraded.Close() }()

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
	_ = db.Close()

	upgraded, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("the upgrade failed: %v", err)
	}
	defer func() { _ = upgraded.Close() }()

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
	_ = db.Close()

	upgraded, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("the upgrade failed: %v", err)
	}
	defer func() { _ = upgraded.Close() }()

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

func TestTheAgentMigrationKeepsEveryRowThatPointsAtAServer(t *testing.T) {
	// The table is rebuilt, and five others reference it. A rebuild that
	// dropped the rows pointing at a server would take a group's membership,
	// its cached records and its stored file with it, and the operator would
	// find out when a group operation reached nobody.
	dir := t.TempDir()
	path := filepath.Join(dir, "panel.db")

	db, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open returned an error: %v", err)
	}
	for _, statement := range []string{
		`INSERT INTO servers (id, name, host, ssh_user, ssh_key_path)
		 VALUES (7, 'dns1', 'dns1', 'dnsops', 'keys/7.key')`,
		`INSERT INTO server_groups (id, name) VALUES (3, 'resolvers')`,
		`UPDATE servers SET group_id = 3 WHERE id = 7`,
		`INSERT INTO server_state (server_id, file_sha256) VALUES (7, 'abc')`,
		`INSERT INTO record_cache (server_id, line, fqdn, type, value, raw)
		 VALUES (7, 1, 'www.example.net', 'A', '192.0.2.10', 'local-data: ...')`,
		`INSERT INTO file_backups (server_id, content, sha256)
		 VALUES (7, 'server:', 'def')`,
		`INSERT INTO audit_logs (user_id, username, action, server_id, created_at)
		 VALUES (1001, 'dnsadmin', 'dns_add', 7, '2026-01-01 00:00:00')`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("cannot seed (%s): %v", statement, err)
		}
	}
	_ = db.Close()

	// Replay the migration against a database that already holds all of it.
	db, err = Open(context.Background(), path)
	if err != nil {
		t.Fatalf("cannot reopen: %v", err)
	}
	if _, err := db.Exec(
		"DELETE FROM schema_migrations WHERE name = '0009_agent_transport.sql'"); err != nil {
		t.Fatalf("cannot clear the applied row: %v", err)
	}
	if _, err := db.Exec("ALTER TABLE servers DROP COLUMN agent_port"); err != nil {
		t.Fatalf("cannot undo the column: %v", err)
	}
	_ = db.Close()

	upgraded, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("the upgrade failed: %v", err)
	}
	defer func() { _ = upgraded.Close() }()

	for table, want := range map[string]int{
		"servers": 1, "server_groups": 1, "server_state": 1,
		"record_cache": 1, "file_backups": 1, "audit_logs": 1,
	} {
		var count int
		if err := upgraded.QueryRow(
			"SELECT COUNT(*) FROM " + table).Scan(&count); err != nil {
			t.Fatalf("cannot count %s: %v", table, err)
		}
		if count != want {
			t.Errorf("%s holds %d rows after the rebuild, want %d", table, count, want)
		}
	}

	// The trigger went with the old table and has to be back, or every later
	// edit leaves updated_at at whatever it was.
	var triggers int
	if err := upgraded.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master
		  WHERE type = 'trigger' AND name = 'servers_touch_updated_at'`).Scan(&triggers); err != nil {
		t.Fatalf("cannot look for the trigger: %v", err)
	}
	if triggers != 1 {
		t.Error("the rebuild left the servers table without its updated_at trigger")
	}
}

func TestAnAgentServerCanBeStoredOnlyAfterTheRebuild(t *testing.T) {
	// The CHECK on the transport column has read ('ssh') since the first
	// migration. A row naming an agent is the proof it now reads both.
	dir := t.TempDir()
	path := filepath.Join(dir, "panel.db")

	db, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open returned an error: %v", err)
	}
	defer func() { _ = db.Close() }()

	if _, err := db.Exec(
		`INSERT INTO servers (name, host, transport, agent_port, ssh_key_path)
		 VALUES ('dns4', 'dns4', 'agent', 8443, 'keys/1.token')`); err != nil {
		t.Fatalf("an agent server was refused: %v", err)
	}

	// And nothing else. A third value would mean the constraint stopped
	// constraining.
	if _, err := db.Exec(
		`INSERT INTO servers (name, host, transport, ssh_key_path)
		 VALUES ('dns5', 'dns5', 'carrier-pigeon', 'keys/2.key')`); err == nil {
		t.Error("the transport column accepted a value the panel cannot speak")
	}

	// An agent server needs no account, so ssh_user has to take an empty one.
	var user string
	if err := db.QueryRow(
		"SELECT ssh_user FROM servers WHERE name = 'dns4'").Scan(&user); err != nil {
		t.Fatalf("cannot read the server back: %v", err)
	}
	if user != "" {
		t.Errorf("ssh_user = %q, want it empty on an agent server", user)
	}
}

func TestTheRebuildCorrectsTheRecordsPathDefault(t *testing.T) {
	// The schema said host_entries.conf while the panel used local_records.conf.
	// The default was unreachable, since every insert passes a path, but a
	// schema that contradicts the code is a trap for whoever reads it next.
	dir := t.TempDir()
	path := filepath.Join(dir, "panel.db")

	db, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open returned an error: %v", err)
	}
	defer func() { _ = db.Close() }()

	if _, err := db.Exec(
		`INSERT INTO servers (name, host, ssh_user, ssh_key_path)
		 VALUES ('dns1', 'dns1', 'dnsops', 'keys/1.key')`); err != nil {
		t.Fatalf("cannot seed a server: %v", err)
	}

	var stored string
	if err := db.QueryRow("SELECT records_path FROM servers").Scan(&stored); err != nil {
		t.Fatalf("cannot read the server back: %v", err)
	}
	if stored != "/etc/unbound/local_records.conf" {
		t.Errorf("the schema default is %q", stored)
	}
}

func TestAnUpgradeThatBrokeAReferenceStopsTheStart(t *testing.T) {
	// The foreign keys are suspended for the migration run, so the check
	// afterwards is the only thing standing between a bad rebuild and a panel
	// that runs for weeks on rows pointing at nothing. This proves the check
	// is wired rather than merely written.
	dir := t.TempDir()
	path := filepath.Join(dir, "panel.db")

	db, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open returned an error: %v", err)
	}

	// A group naming a source server that is not there. Reaching this state
	// takes the suspension the migration run uses, which is exactly the state
	// a broken rebuild would leave.
	for _, statement := range []string{
		"PRAGMA foreign_keys = OFF",
		`INSERT INTO server_groups (id, name, source_server_id) VALUES (1, 'resolvers', 999)`,
		"PRAGMA foreign_keys = ON",
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("cannot arrange the dangling row (%s): %v", statement, err)
		}
	}
	_ = db.Close()

	reopened, err := OpenExisting(context.Background(), path)
	if err != nil {
		t.Fatalf("cannot reopen: %v", err)
	}
	defer func() { _ = reopened.Close() }()

	if err := reopened.checkForeignKeys(context.Background()); err == nil {
		t.Fatal("the check passed a row pointing at nothing")
	} else if !strings.Contains(err.Error(), "server_groups") {
		t.Errorf("the failure does not name the table: %v", err)
	}
}

func TestTheGroupMigrationKeepsTheSmallestGroupAndRecordsTheRest(t *testing.T) {
	// A server that sat in two groups has to end up in exactly one, and the
	// membership that drops has to be visible afterwards. The old panel wide
	// source becomes the source of its own group and of no other, which is the
	// whole point of moving it: a mirror can no longer copy one group over
	// another.
	dir := t.TempDir()
	path := filepath.Join(dir, "panel.db")

	db, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open returned an error: %v", err)
	}

	// Put the database back to where it was before the group migration.
	for _, statement := range []string{
		"DROP INDEX IF EXISTS idx_servers_group",
		"ALTER TABLE servers DROP COLUMN group_id",
		"ALTER TABLE server_groups DROP COLUMN source_server_id",
		`CREATE TABLE server_group_members (
		     group_id  INTEGER NOT NULL REFERENCES server_groups(id) ON DELETE CASCADE,
		     server_id INTEGER NOT NULL REFERENCES servers(id)       ON DELETE CASCADE,
		     PRIMARY KEY (group_id, server_id))`,
		"CREATE INDEX idx_group_members_server ON server_group_members (server_id)",
		"DELETE FROM schema_migrations WHERE name = '0011_group_per_server.sql'",
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("cannot undo the migration (%s): %v", statement, err)
		}
	}

	for _, statement := range []string{
		`INSERT INTO servers (id, name, host, ssh_user, ssh_key_path)
		 VALUES (7, 'dns1', 'dns1', 'dnsops', 'keys/7.key')`,
		`INSERT INTO server_groups (id, name) VALUES (3, 'resolvers')`,
		`INSERT INTO server_groups (id, name) VALUES (5, 'edge')`,
		`INSERT INTO server_group_members (group_id, server_id) VALUES (3, 7)`,
		`INSERT INTO server_group_members (group_id, server_id) VALUES (5, 7)`,
		`INSERT INTO settings (key, value) VALUES ('source_server_id', '7')`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("cannot seed (%s): %v", statement, err)
		}
	}
	_ = db.Close()

	upgraded, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("the upgrade failed: %v", err)
	}
	defer func() { _ = upgraded.Close() }()

	var group int64
	if err := upgraded.QueryRow("SELECT group_id FROM servers WHERE id = 7").Scan(&group); err != nil {
		t.Fatalf("cannot read the group of the server: %v", err)
	}
	if group != 3 {
		t.Errorf("the server is in group %d, want the smallest one, 3", group)
	}

	// The dropped membership is in the trail, naming the group it left.
	var details string
	if err := upgraded.QueryRow(
		"SELECT details FROM audit_logs WHERE action = 'group_collapse'").Scan(&details); err != nil {
		t.Fatalf("the dropped membership was not recorded: %v", err)
	}
	if !strings.Contains(details, "#5") || !strings.Contains(details, "dns1") {
		t.Errorf("the recorded row does not name the server and the group it left: %q", details)
	}

	// The source lands on its own group only.
	sources := map[int64]any{}
	rows, err := upgraded.Query("SELECT id, source_server_id FROM server_groups")
	if err != nil {
		t.Fatalf("cannot read the groups: %v", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id int64
		var source any
		if err := rows.Scan(&id, &source); err != nil {
			t.Fatalf("cannot scan a group: %v", err)
		}
		sources[id] = source
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("cannot walk the groups: %v", err)
	}
	if sources[3] != int64(7) {
		t.Errorf("group 3 names %v as its source, want 7", sources[3])
	}
	if sources[5] != nil {
		t.Errorf("group 5 took a source it never had: %v", sources[5])
	}

	// The panel wide setting is gone, so nothing reads it after the upgrade.
	var left int
	if err := upgraded.QueryRow(
		"SELECT COUNT(*) FROM settings WHERE key = 'source_server_id'").Scan(&left); err != nil {
		t.Fatalf("cannot read the settings: %v", err)
	}
	if left != 0 {
		t.Error("the panel wide source server setting survived the upgrade")
	}
}
