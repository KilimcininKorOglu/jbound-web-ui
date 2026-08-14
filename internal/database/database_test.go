package database

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func openTestDB(t *testing.T) *DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	db, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open returned an error: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestTheProbeAnswersForAWorkingDatabase(t *testing.T) {
	db := openTestDB(t)

	if err := db.Probe(context.Background()); err != nil {
		t.Fatalf("Probe returned an error on a working database: %v", err)
	}
}

func TestTheProbeReportsADatabaseItCannotRead(t *testing.T) {
	db := openTestDB(t)
	if err := db.Close(); err != nil {
		t.Fatalf("cannot close the database: %v", err)
	}

	if err := db.Probe(context.Background()); err == nil {
		t.Fatal("Probe reported a closed database as healthy")
	}
}

func TestTheProbeReportsADatabaseWithNoAppliedMigration(t *testing.T) {
	// An empty file opens and answers queries, so the row count is what tells
	// it apart from the database this binary was started against.
	db := openTestDB(t)

	if _, err := db.Exec("DELETE FROM schema_migrations"); err != nil {
		t.Fatalf("cannot clear the applied migrations: %v", err)
	}
	if err := db.Probe(context.Background()); err == nil {
		t.Fatal("Probe reported a database with no schema as healthy")
	}
}

func TestOpenCreatesEverySchemaObject(t *testing.T) {
	db := openTestDB(t)

	wantTables := []string{
		"servers", "server_groups", "server_group_members", "server_state",
		"record_cache", "audit_logs", "login_attempts", "sessions",
		"schema_migrations",
	}
	for _, name := range wantTables {
		var found string
		err := db.QueryRow(
			"SELECT name FROM sqlite_master WHERE type='table' AND name=?", name).Scan(&found)
		if err != nil {
			t.Errorf("table %s is missing: %v", name, err)
		}
	}

	// No users table. Authentication goes through PAM, so passwords must have
	// nowhere to live in this database.
	var users int
	if err := db.QueryRow(
		"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='users'").Scan(&users); err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if users != 0 {
		t.Error("a users table exists, authentication must stay with PAM")
	}
}

func TestOpenAppliesPragmas(t *testing.T) {
	db := openTestDB(t)

	var journalMode string
	if err := db.QueryRow("PRAGMA journal_mode").Scan(&journalMode); err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if journalMode != "wal" {
		t.Errorf("journal_mode = %q, want wal", journalMode)
	}

	var foreignKeys int
	if err := db.QueryRow("PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
		t.Fatalf("query failed: %v", err)
	}
	// Cascade rules only work with this on, so a wrong value would silently
	// leave orphaned cache rows behind.
	if foreignKeys != 1 {
		t.Error("foreign_keys is off, cascade rules would not run")
	}
}

func TestOpenSetsFileMode0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "perm.db")
	db, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open returned an error: %v", err)
	}
	defer db.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	// Audit rows record who changed what from where, so the file is private.
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("database file mode is %o, want 600", got)
	}
}

func TestOpenIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "twice.db")

	first, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("first Open failed: %v", err)
	}
	if _, err := first.Exec(
		`INSERT INTO servers (name, host, ssh_user, ssh_key_path)
		 VALUES ('dns1', 'dns1', 'dnsops', 'keys/1.key')`); err != nil {
		t.Fatalf("insert failed: %v", err)
	}
	first.Close()

	second, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("second Open failed: %v", err)
	}
	defer second.Close()

	var count int
	if err := second.QueryRow("SELECT COUNT(*) FROM servers").Scan(&count); err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if count != 1 {
		t.Errorf("server count is %d after reopening, want 1", count)
	}

	// Every migration is recorded exactly once. A second row for the same file
	// would mean it ran twice, and a migration that alters a table cannot
	// survive that.
	var duplicated int
	err = second.QueryRow(`
SELECT COUNT(*) FROM (
    SELECT name FROM schema_migrations GROUP BY name HAVING COUNT(*) > 1
)`).Scan(&duplicated)
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if duplicated != 0 {
		t.Errorf("%d migrations are recorded more than once", duplicated)
	}
}

// Deleting a server must drop its cached records, but the audit trail of what
// happened on that server has to survive.
func TestDeletingAServerCascadesToStateAndCacheButKeepsAuditRows(t *testing.T) {
	db := openTestDB(t)

	res, err := db.Exec(
		`INSERT INTO servers (name, host, ssh_user, ssh_key_path)
		 VALUES ('dns1', 'dns1', 'dnsops', 'keys/1.key')`)
	if err != nil {
		t.Fatalf("insert failed: %v", err)
	}
	serverID, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("LastInsertId failed: %v", err)
	}

	if _, err := db.Exec(
		"INSERT INTO server_state (server_id, file_sha256) VALUES (?, 'abc')",
		serverID); err != nil {
		t.Fatalf("insert state failed: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO record_cache (server_id, line, fqdn, type, value, raw)
		 VALUES (?, 1, 'a.example.local', 'A', '10.0.0.1', 'raw')`,
		serverID); err != nil {
		t.Fatalf("insert cache failed: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO audit_logs (user_id, username, server_id, action, details)
		 VALUES (0, 'root', ?, 'dns_add', 'added a record')`,
		serverID); err != nil {
		t.Fatalf("insert audit failed: %v", err)
	}

	groupRes, err := db.Exec("INSERT INTO server_groups (name) VALUES ('resolvers')")
	if err != nil {
		t.Fatalf("insert group failed: %v", err)
	}
	groupID, _ := groupRes.LastInsertId()
	if _, err := db.Exec(
		"INSERT INTO server_group_members (group_id, server_id) VALUES (?, ?)",
		groupID, serverID); err != nil {
		t.Fatalf("insert membership failed: %v", err)
	}

	if _, err := db.Exec("DELETE FROM servers WHERE id = ?", serverID); err != nil {
		t.Fatalf("delete failed: %v", err)
	}

	for _, table := range []string{"server_state", "record_cache", "server_group_members"} {
		var count int
		if err := db.QueryRow(
			"SELECT COUNT(*) FROM " + table + " WHERE server_id = " +
				itoa(serverID)).Scan(&count); err != nil {
			t.Fatalf("count on %s failed: %v", table, err)
		}
		if count != 0 {
			t.Errorf("%s still holds %d row(s) after the server was deleted", table, count)
		}
	}

	var auditCount int
	var auditServerID any
	if err := db.QueryRow(
		"SELECT COUNT(*) FROM audit_logs").Scan(&auditCount); err != nil {
		t.Fatalf("audit count failed: %v", err)
	}
	if auditCount != 1 {
		t.Fatalf("audit rows were deleted, %d remain, want 1", auditCount)
	}
	if err := db.QueryRow("SELECT server_id FROM audit_logs").Scan(&auditServerID); err != nil {
		t.Fatalf("audit query failed: %v", err)
	}
	if auditServerID != nil {
		t.Errorf("audit server_id is %v, want NULL after the server was deleted", auditServerID)
	}
}

func TestServerNameIsUnique(t *testing.T) {
	db := openTestDB(t)

	insert := `INSERT INTO servers (name, host, ssh_user, ssh_key_path)
	           VALUES ('dns1', 'dns1', 'dnsops', 'keys/1.key')`
	if _, err := db.Exec(insert); err != nil {
		t.Fatalf("first insert failed: %v", err)
	}
	if _, err := db.Exec(insert); err == nil {
		t.Error("a duplicate server name was accepted")
	}
}

func TestSessionRoleIsConstrained(t *testing.T) {
	db := openTestDB(t)

	_, err := db.Exec(
		`INSERT INTO sessions (id, uid, username, role, fingerprint, csrf_token)
		 VALUES ('s1', 1000, 'dnsuser', 'superadmin', 'fp', 'token')`)
	if err == nil {
		t.Error("an unknown role was accepted, only admin and user exist")
	}
}

func TestUpdatingAServerTouchesUpdatedAt(t *testing.T) {
	db := openTestDB(t)

	if _, err := db.Exec(
		`INSERT INTO servers (name, host, ssh_user, ssh_key_path, created_at, updated_at)
		 VALUES ('dns1', 'dns1', 'dnsops', 'keys/1.key', '2020-01-01 00:00:00', '2020-01-01 00:00:00')`); err != nil {
		t.Fatalf("insert failed: %v", err)
	}
	if _, err := db.Exec("UPDATE servers SET host = 'dns1.example' WHERE name = 'dns1'"); err != nil {
		t.Fatalf("update failed: %v", err)
	}

	var updatedAt string
	if err := db.QueryRow("SELECT updated_at FROM servers WHERE name = 'dns1'").Scan(&updatedAt); err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if updatedAt == "2020-01-01 00:00:00" {
		t.Error("updated_at was not refreshed by the trigger")
	}
}

func TestCleanupRemovesExpiredSessionsAndStaleAttempts(t *testing.T) {
	db := openTestDB(t)

	// One current session and one that has been idle for two hours.
	if _, err := db.Exec(
		`INSERT INTO sessions (id, uid, username, role, fingerprint, csrf_token, last_active)
		 VALUES ('fresh', 1000, 'dnsuser', 'user', 'fp', 'token', datetime('now'))`); err != nil {
		t.Fatalf("insert failed: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO sessions (id, uid, username, role, fingerprint, csrf_token, last_active)
		 VALUES ('stale', 1000, 'dnsuser', 'user', 'fp', 'token', datetime('now', '-2 hours'))`); err != nil {
		t.Fatalf("insert failed: %v", err)
	}

	if _, err := db.Exec(
		`INSERT INTO login_attempts (ip_address, attempted_at)
		 VALUES ('10.0.0.1', datetime('now'))`); err != nil {
		t.Fatalf("insert failed: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO login_attempts (ip_address, attempted_at)
		 VALUES ('10.0.0.2', datetime('now', '-20 minutes'))`); err != nil {
		t.Fatalf("insert failed: %v", err)
	}

	if err := db.Cleanup(context.Background(), 30*time.Minute, 15*time.Minute); err != nil {
		t.Fatalf("Cleanup returned an error: %v", err)
	}

	var sessions int
	if err := db.QueryRow("SELECT COUNT(*) FROM sessions").Scan(&sessions); err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if sessions != 1 {
		t.Errorf("%d session(s) remain, want 1", sessions)
	}

	var attempts int
	if err := db.QueryRow("SELECT COUNT(*) FROM login_attempts").Scan(&attempts); err != nil {
		t.Fatalf("query failed: %v", err)
	}
	// Attempts older than fifteen minutes no longer count towards the limit.
	if attempts != 1 {
		t.Errorf("%d login attempt(s) remain, want 1", attempts)
	}
}

func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	digits := ""
	for v > 0 {
		digits = string(rune('0'+v%10)) + digits
		v /= 10
	}
	return digits
}
