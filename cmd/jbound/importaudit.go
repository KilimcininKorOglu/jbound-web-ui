package main

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"jbound/internal/audit"
	"jbound/internal/config"
	"jbound/internal/database"
	"jbound/internal/preflight"
	"jbound/internal/store"
)

// unknownUID marks a row whose actor cannot be named as a POSIX account.
//
// The panel identifies a user by the uid the operating system gave them. The
// installation these rows come from kept its own user table, so the number in
// the export belongs to a table that no longer exists. Copying it into a column
// that means "uid" would put a lie in the trail and forward it to the SIEM as
// suid. A negative value is not a uid any system hands out, so a reader can see
// at a glance that the number is missing rather than wrong.
const unknownUID = -1

// mysqlTime is the layout a MySQL DATETIME column exports in.
const mysqlTime = "2006-01-02 15:04:05"

// requiredColumns are the fields a row cannot be built without.
var requiredColumns = []string{"username", "action", "created_at"}

// importedRow is one line of the export, already checked.
type importedRow struct {
	entry audit.Entry
	at    time.Time
}

// runImportAudit copies the audit trail of an older installation into the
// panel.
//
// It exists for one migration and is run once. The rows it writes are history:
// they name no server, because the installation they come from managed a single
// resolver and the panel has no way to know which of its own records that
// became. Inventing the link would be worse than leaving it empty.
func runImportAudit(path string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	// The same check the panel makes. Rows written as root leave a database
	// the service account may no longer be able to write.
	if err := preflight.NotRoot(); err != nil {
		return err
	}

	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("cannot open %s: %w", path, err)
	}
	defer file.Close()

	rows, err := readExport(file)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if len(rows) == 0 {
		return fmt.Errorf("%s holds no rows", path)
	}

	ctx := context.Background()

	db, err := database.OpenExisting(ctx, cfg.DBPath)
	if err != nil {
		return err
	}
	defer db.Close()

	written, err := writeRows(ctx, db, rows, path)
	if err != nil {
		return err
	}

	fmt.Printf("Imported %d audit row(s) from %s.\n", written, path)
	fmt.Printf("They carry uid %d, because the accounts of the old installation are not POSIX accounts.\n",
		unknownUID)
	fmt.Println("They name no server, because the installation they come from managed one.")
	return nil
}

// writeRows inserts the whole export under one transaction.
//
// All of it or none of it: a half imported trail is worse than no import,
// because nobody can tell where it stops.
func writeRows(ctx context.Context, db *database.DB, rows []importedRow, path string) (int, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("cannot start the import: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, row := range rows {
		if err := store.WriteAuditTx(ctx, tx, row.entry, row.at); err != nil {
			return 0, err
		}
	}

	// One row about the import itself, so a trail that suddenly reaches
	// further back than the panel has existed says where that came from.
	if err := store.WriteAuditTx(ctx, tx, audit.Entry{
		UID:      os.Getuid(),
		Username: actorName(),
		Action:   audit.ActionAuditImport,
		Details: fmt.Sprintf("Imported %d audit entries from %s",
			len(rows), path),
		IPAddress: "local",
	}, time.Now()); err != nil {
		return 0, err
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("cannot finish the import: %w", err)
	}
	return len(rows), nil
}

// actorName names whoever ran the command.
func actorName() string {
	for _, key := range []string{"SUDO_USER", "USER", "LOGNAME"} {
		if name := strings.TrimSpace(os.Getenv(key)); name != "" {
			return name
		}
	}
	// The convention the panel already uses for an action with no session
	// behind it.
	return "system"
}

// readExport parses the whole file before anything is written.
//
// A comma separated export with a header row is what every MySQL client can
// produce, and naming the columns in the header means their order does not
// matter and a column the panel has no use for can stay in the file.
func readExport(source io.Reader) ([]importedRow, error) {
	reader := csv.NewReader(source)
	// Rows differ in width when a client quotes only some of them, and the
	// header decides which field is which anyway.
	reader.FieldsPerRecord = -1

	header, err := reader.Read()
	if errors.Is(err, io.EOF) {
		return nil, errors.New("the file is empty")
	}
	if err != nil {
		return nil, fmt.Errorf("cannot read the header: %w", err)
	}

	columns, err := indexColumns(header)
	if err != nil {
		return nil, err
	}

	var rows []importedRow
	for line := 2; ; line++ {
		record, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}

		row, err := buildRow(record, columns)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// indexColumns maps a header to field positions.
func indexColumns(header []string) (map[string]int, error) {
	columns := make(map[string]int, len(header))
	for i, name := range header {
		// A file written by a spreadsheet may carry a byte order mark on the
		// first name, and every client disagrees about case.
		clean := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(name, "\ufeff")))
		columns[clean] = i
	}

	var missing []string
	for _, name := range requiredColumns {
		if _, ok := columns[name]; !ok {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("the header names no %s column",
			strings.Join(missing, ", no "))
	}
	return columns, nil
}

// buildRow turns one record into an entry, or says what is wrong with it.
func buildRow(record []string, columns map[string]int) (importedRow, error) {
	at, err := parseTime(field(record, columns, "created_at"))
	if err != nil {
		return importedRow{}, err
	}

	username := strings.TrimSpace(field(record, columns, "username"))
	if username == "" {
		return importedRow{}, errors.New("the username is empty")
	}

	action := strings.TrimSpace(field(record, columns, "action"))
	if action == "" {
		return importedRow{}, errors.New("the action is empty")
	}

	return importedRow{
		entry: audit.Entry{
			UID:       unknownUID,
			Username:  username,
			Action:    action,
			Details:   field(record, columns, "details"),
			IPAddress: strings.TrimSpace(field(record, columns, "ip_address")),
		},
		at: at,
	}, nil
}

// field reads one column, or an empty string when the row is short.
func field(record []string, columns map[string]int, name string) string {
	index, ok := columns[name]
	if !ok || index >= len(record) {
		return ""
	}
	return record[index]
}

// parseTime reads the timestamp of one row.
//
// A MySQL DATETIME carries no zone, and the installation it comes from wrote
// local time. It is read as UTC, which is what the panel stores, so an export
// from a host that did not run on UTC is shifted. RFC 3339 is accepted as well,
// because a client that can add the offset removes the guess.
func parseTime(value string) (time.Time, error) {
	text := strings.TrimSpace(value)
	if text == "" {
		return time.Time{}, errors.New("the timestamp is empty")
	}

	if at, err := time.Parse(time.RFC3339, text); err == nil {
		return at.UTC(), nil
	}
	// A fractional part is what a client adds when the column is DATETIME(3).
	if index := strings.IndexByte(text, '.'); index != -1 {
		if _, err := strconv.Atoi(text[index+1:]); err == nil {
			text = text[:index]
		}
	}

	at, err := time.Parse(mysqlTime, text)
	if err != nil {
		return time.Time{}, fmt.Errorf(
			"cannot read the timestamp %q, expected %s or RFC 3339", value, mysqlTime)
	}
	return at, nil
}
