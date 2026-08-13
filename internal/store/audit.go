package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"unbound-web/internal/audit"
)

// AuditLogs stores audit entries.
type AuditLogs struct {
	db *sql.DB
}

// NewAuditLogs builds the audit store.
func NewAuditLogs(db *sql.DB) *AuditLogs { return &AuditLogs{db: db} }

// Write inserts one audit entry.
func (a *AuditLogs) Write(ctx context.Context, entry audit.Entry, at time.Time) error {
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

	_, err := a.db.ExecContext(ctx, query,
		entry.UID, entry.Username, serverID, entry.Action,
		entry.Details, entry.IPAddress, formatTime(at))
	if err != nil {
		return fmt.Errorf("cannot insert the audit entry: %w", err)
	}
	return nil
}
