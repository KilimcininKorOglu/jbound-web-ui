package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"jbound/internal/audit"
)

// AuditLogs stores audit entries.
type AuditLogs struct {
	db *sql.DB
}

// NewAuditLogs builds the audit store.
func NewAuditLogs(db *sql.DB) *AuditLogs { return &AuditLogs{db: db} }

// Write inserts one audit entry.
func (a *AuditLogs) Write(ctx context.Context, entry audit.Entry, at time.Time) error {
	return writeAudit(ctx, a.db, entry, at)
}

// WriteAuditTx inserts one entry inside a transaction the caller owns.
//
// The import command writes a whole trail or none of it, and a half imported
// trail is worse than no import because nobody can tell where it stops.
func WriteAuditTx(ctx context.Context, tx *sql.Tx, entry audit.Entry, at time.Time) error {
	return writeAudit(ctx, tx, entry, at)
}

// execer is the part of *sql.DB and *sql.Tx that an insert needs.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func writeAudit(ctx context.Context, db execer, entry audit.Entry, at time.Time) error {
	const query = `
INSERT INTO audit_logs
    (user_id, username, server_id, action, details, ip_address, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?)`

	// A nil pointer becomes SQL NULL, which is what the schema expects for an
	// action that targets no server.
	var serverID any
	if entry.ServerID != nil {
		serverID = *entry.ServerID
	}

	_, err := db.ExecContext(ctx, query,
		entry.UID, entry.Username, serverID, entry.Action,
		entry.Details, entry.IPAddress, formatTime(at))
	if err != nil {
		return fmt.Errorf("cannot insert the audit entry: %w", err)
	}
	return nil
}

// List returns one page of the audit log, newest first.
//
// The server name comes from a left join, so a row survives the server it names
// being deleted. Losing the history of a server the moment it is removed would
// defeat the point of keeping it.
func (a *AuditLogs) List(ctx context.Context, query audit.Query) (audit.Page, error) {
	query.Normalise()
	where, args := auditFilter(query)

	var total int
	if err := a.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM audit_logs l"+where, args...).Scan(&total); err != nil {
		return audit.Page{}, fmt.Errorf("cannot count the audit rows: %w", err)
	}

	page := audit.NewPage(query, total)
	if total == 0 {
		return page, nil
	}

	rows, err := a.db.QueryContext(ctx, auditColumns+where+`
 ORDER BY l.created_at DESC, l.id DESC
 LIMIT ? OFFSET ?`, append(args, page.PerPage, page.Offset())...)
	if err != nil {
		return audit.Page{}, fmt.Errorf("cannot read the audit rows: %w", err)
	}

	if page.Rows, err = scanAuditRows(rows); err != nil {
		return audit.Page{}, err
	}
	return page, nil
}

// After returns up to limit rows newer than the given identifier, oldest first.
//
// This is what the SIEM sender reads. The order is the opposite of the listing
// on purpose: a receiver has to be told what happened in the order it happened,
// and the identifier is what the sender remembers between runs.
//
// The ordering is by id alone rather than by created_at. Two rows written in
// the same second are indistinguishable by time, and a sender that skipped one
// of them would never come back for it.
func (a *AuditLogs) After(ctx context.Context, cursor int64, limit int) ([]audit.Row, error) {
	rows, err := a.db.QueryContext(ctx, auditColumns+`
 WHERE l.id > ?
 ORDER BY l.id
 LIMIT ?`, cursor, limit)
	if err != nil {
		return nil, fmt.Errorf("cannot read the audit rows after %d: %w", cursor, err)
	}
	return scanAuditRows(rows)
}

// auditColumns is the select both readers share, so a column added for one of
// them cannot be missing from the other.
const auditColumns = `
SELECT l.id, l.user_id, l.username, l.server_id, COALESCE(s.name, ''),
       l.action, l.details, l.ip_address, l.created_at
  FROM audit_logs l
  LEFT JOIN servers s ON s.id = l.server_id`

// scanAuditRows reads a result set of auditColumns and closes it.
func scanAuditRows(rows *sql.Rows) ([]audit.Row, error) {
	defer func() { _ = rows.Close() }()

	var out []audit.Row
	for rows.Next() {
		var (
			row     audit.Row
			created string
		)
		err := rows.Scan(&row.ID, &row.UID, &row.Username, &row.ServerID,
			&row.ServerName, &row.Action, &row.Details, &row.IPAddress, &created)
		if err != nil {
			return nil, fmt.Errorf("cannot read an audit row: %w", err)
		}

		if row.CreatedAt, err = parseTime(created); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cannot read the audit row set: %w", err)
	}
	return out, nil
}

// auditFilter builds the shared WHERE clause of the count and the page, so the
// two can never disagree about which rows the page is counted from.
func auditFilter(query audit.Query) (string, []any) {
	var (
		clauses []string
		args    []any
	)

	if search := strings.TrimSpace(query.Search); search != "" {
		pattern := "%" + escapeLike(strings.ToLower(search)) + "%"
		clauses = append(clauses, `(LOWER(l.username) LIKE ? ESCAPE '\'`+
			` OR LOWER(l.details) LIKE ? ESCAPE '\'`+
			` OR LOWER(l.ip_address) LIKE ? ESCAPE '\')`)
		args = append(args, pattern, pattern, pattern)
	}

	if query.Action != "" {
		clauses = append(clauses, "l.action = ?")
		args = append(args, query.Action)
	}

	if query.ServerID != 0 {
		clauses = append(clauses, "l.server_id = ?")
		args = append(args, query.ServerID)
	}

	if len(clauses) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}
