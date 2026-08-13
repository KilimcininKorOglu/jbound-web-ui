// Package audit records who changed what, from where.
//
// Faz 10 adds the syslog mirror and the SIEM configuration. The database
// remains the primary record, because the panel must still answer "who added
// this record" when the SIEM is unreachable.
package audit

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// Actions written by the panel. They are constants so a typo cannot create a
// second spelling that the log filters then miss.
const (
	ActionLogin  = "login"
	ActionLogout = "logout"

	ActionServerCreate = "server_create"
	ActionServerUpdate = "server_update"
	ActionServerDelete = "server_delete"
	ActionServerTrust  = "server_trust"

	ActionGroupCreate = "group_create"
	ActionGroupUpdate = "group_update"
	ActionGroupDelete = "group_delete"
)

// Entry is one audit row. ServerID stays nil for actions that target no
// managed server, such as a login.
type Entry struct {
	UID       int
	Username  string
	ServerID  *int64
	Action    string
	Details   string
	IPAddress string
}

// Repository stores audit entries.
type Repository interface {
	Write(ctx context.Context, entry Entry, at time.Time) error
}

// Logger writes audit entries.
type Logger struct {
	repo Repository
	now  func() time.Time
}

// NewLogger builds the audit logger.
func NewLogger(repo Repository) *Logger {
	return &Logger{repo: repo, now: time.Now}
}

// Write stores one entry.
//
// A failure is returned rather than swallowed. An action that cannot be
// recorded is an action nobody can account for later, so the caller decides
// whether to continue.
func (l *Logger) Write(ctx context.Context, entry Entry) error {
	if entry.Action == "" {
		return fmt.Errorf("audit entry has no action")
	}
	if err := l.repo.Write(ctx, entry, l.now().UTC()); err != nil {
		slog.Error("cannot write the audit entry",
			"action", entry.Action, "username", entry.Username, "error", err)
		return err
	}
	return nil
}
