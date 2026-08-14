package main

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"jbound/internal/audit"
	"jbound/internal/database"
)

func TestTheHeaderDecidesWhichColumnIsWhich(t *testing.T) {
	// A client writes the columns in whatever order the SELECT named them, and
	// a file that carries more than the panel needs is the normal case.
	const export = `created_at,extra,action,ip_address,username,details,id
2024-03-01 09:15:00,ignored,dns_add,10.0.0.5,alice,Added A record: a.example.net -> 10.0.0.1,7
`

	rows, err := readExport(strings.NewReader(export))
	if err != nil {
		t.Fatalf("cannot read the export: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}

	row := rows[0]
	if row.entry.Username != "alice" {
		t.Errorf("username is %q", row.entry.Username)
	}
	if row.entry.Action != "dns_add" {
		t.Errorf("action is %q", row.entry.Action)
	}
	if row.entry.IPAddress != "10.0.0.5" {
		t.Errorf("address is %q", row.entry.IPAddress)
	}
	if row.entry.Details != "Added A record: a.example.net -> 10.0.0.1" {
		t.Errorf("details are %q", row.entry.Details)
	}
	if want := time.Date(2024, 3, 1, 9, 15, 0, 0, time.UTC); !row.at.Equal(want) {
		t.Errorf("timestamp is %v, want %v", row.at, want)
	}
}

func TestTheImportedRowCarriesNoInventedUID(t *testing.T) {
	// The number in the export identifies a row of a user table the panel does
	// not have. Copying it into a column that means "POSIX uid" would put a
	// wrong number in the trail and forward it to the SIEM as suid.
	const export = `id,user_id,username,action,details,ip_address,created_at
7,42,alice,login,User 'alice' logged in,10.0.0.5,2024-03-01 09:15:00
`

	rows, err := readExport(strings.NewReader(export))
	if err != nil {
		t.Fatalf("cannot read the export: %v", err)
	}
	if rows[0].entry.UID != unknownUID {
		t.Errorf("uid is %d, want %d", rows[0].entry.UID, unknownUID)
	}
	if rows[0].entry.ServerID != nil {
		t.Error("the row names a server the panel cannot know")
	}
}

func TestAnExportWithoutTheColumnsIsRefusedByName(t *testing.T) {
	const export = `id,user_id,details
7,42,something happened
`

	_, err := readExport(strings.NewReader(export))
	if err == nil {
		t.Fatal("an export with no username, action or timestamp was accepted")
	}
	for _, want := range []string{"username", "action", "created_at"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %s: %v", want, err)
		}
	}
}

func TestABadRowNamesItsLineAndStopsTheImport(t *testing.T) {
	// Refusing the whole file is the point. A trail that stops at row three
	// with no sign of it is worse than one that was never imported.
	const export = `username,action,created_at
alice,login,2024-03-01 09:15:00
bob,login,yesterday
carol,login,2024-03-01 09:17:00
`

	_, err := readExport(strings.NewReader(export))
	if err == nil {
		t.Fatal("a row with an unreadable timestamp was accepted")
	}
	if !strings.Contains(err.Error(), "line 3") {
		t.Errorf("the refusal does not name the line: %v", err)
	}
}

func TestAnEmptyUsernameOrActionIsRefused(t *testing.T) {
	for name, export := range map[string]string{
		"no username": "username,action,created_at\n ,login,2024-03-01 09:15:00\n",
		"no action":   "username,action,created_at\nalice, ,2024-03-01 09:15:00\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := readExport(strings.NewReader(export)); err == nil {
				t.Error("the row was accepted")
			}
		})
	}
}

func TestTheTimestampIsReadInBothLayouts(t *testing.T) {
	cases := map[string]struct {
		value string
		want  time.Time
	}{
		"mysql datetime": {
			"2024-03-01 09:15:00",
			time.Date(2024, 3, 1, 9, 15, 0, 0, time.UTC),
		},
		"fractional seconds": {
			"2024-03-01 09:15:00.482",
			time.Date(2024, 3, 1, 9, 15, 0, 0, time.UTC),
		},
		// An offset removes the guess about which zone the old host ran on,
		// so a client that can write one is worth accepting.
		"rfc 3339 with an offset": {
			"2024-03-01T12:15:00+03:00",
			time.Date(2024, 3, 1, 9, 15, 0, 0, time.UTC),
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			at, err := parseTime(test.value)
			if err != nil {
				t.Fatalf("cannot read %q: %v", test.value, err)
			}
			if !at.Equal(test.want) {
				t.Errorf("read %q as %v, want %v", test.value, at, test.want)
			}
			if at.Location() != time.UTC {
				t.Errorf("the timestamp is not in UTC: %v", at.Location())
			}
		})
	}
}

func TestAnEmptyFileIsRefused(t *testing.T) {
	if _, err := readExport(strings.NewReader("")); err == nil {
		t.Fatal("an empty file was accepted")
	}
}

func TestTheImportWritesEveryRowAndOneRowAboutItself(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	rows := []importedRow{
		{entry: audit.Entry{UID: unknownUID, Username: "alice", Action: "login"},
			at: time.Date(2024, 3, 1, 9, 15, 0, 0, time.UTC)},
		{entry: audit.Entry{UID: unknownUID, Username: "bob", Action: "dns_add"},
			at: time.Date(2024, 3, 1, 9, 16, 0, 0, time.UTC)},
	}

	written, err := writeRows(ctx, db, rows, "old-audit.csv")
	if err != nil {
		t.Fatalf("cannot write the rows: %v", err)
	}
	if written != len(rows) {
		t.Errorf("reported %d rows, wrote %d", written, len(rows))
	}

	if total := count(t, db, `SELECT count(*) FROM audit_logs`); total != len(rows)+1 {
		t.Errorf("the table holds %d rows, want %d", total, len(rows)+1)
	}

	marker := count(t, db, `SELECT count(*) FROM audit_logs WHERE action = ?`,
		audit.ActionAuditImport)
	if marker != 1 {
		t.Errorf("the import left %d rows about itself, want 1", marker)
	}

	// The timestamp of the source row has to survive, or the trail is a list
	// of things that all happened at import time.
	kept := count(t, db, `SELECT count(*) FROM audit_logs WHERE created_at = ?`,
		"2024-03-01 09:15:00")
	if kept != 1 {
		t.Errorf("the original timestamp did not survive")
	}
}

func TestNothingIsWrittenWhenOneRowFails(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	// A server the panel does not hold breaks the foreign key, which is the
	// cheapest way to make one insert of a batch fail.
	missing := int64(4242)
	rows := []importedRow{
		{entry: audit.Entry{UID: unknownUID, Username: "alice", Action: "login"},
			at: time.Now()},
		{entry: audit.Entry{UID: unknownUID, Username: "bob", Action: "dns_add",
			ServerID: &missing}, at: time.Now()},
	}

	if _, err := writeRows(ctx, db, rows, "old-audit.csv"); err == nil {
		t.Fatal("a batch with a broken row was committed")
	}

	if total := count(t, db, `SELECT count(*) FROM audit_logs`); total != 0 {
		t.Errorf("the table holds %d rows after a failed import, want 0", total)
	}
}

func openTestDB(t *testing.T) *database.DB {
	t.Helper()

	db, err := database.Open(context.Background(),
		filepath.Join(t.TempDir(), "jbound.db"))
	if err != nil {
		t.Fatalf("cannot open a test database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func count(t *testing.T, db *database.DB, query string, args ...any) int {
	t.Helper()

	var total int
	if err := db.QueryRowContext(context.Background(), query, args...).
		Scan(&total); err != nil && err != sql.ErrNoRows {
		t.Fatalf("cannot count: %v", err)
	}
	return total
}
