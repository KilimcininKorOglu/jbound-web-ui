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
	ActionLogin       = "login"
	ActionLogout      = "logout"
	ActionLoginFailed = "login_failed"

	ActionServerCreate = "server_create"
	ActionServerUpdate = "server_update"
	ActionServerDelete = "server_delete"
	ActionServerTrust  = "server_trust"

	ActionGroupCreate = "group_create"
	ActionGroupUpdate = "group_update"
	ActionGroupDelete = "group_delete"

	ActionDNSAdd     = "dns_add"
	ActionDNSEdit    = "dns_edit"
	ActionDNSDelete  = "dns_delete"
	ActionDNSRestart = "dns_restart"
	ActionDNSQuery   = "dns_query"

	ActionDiffRepair   = "diff_repair"
	ActionCacheRefresh = "cache_refresh"

	ActionSIEMConfig = "siem_config"
	ActionSIEMTest   = "siem_test"

	ActionSettingsUpdate = "settings_update"
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

	// ServerName is not stored. It travels with the entry so the forwarded
	// event can name the target, which a receiver reads more easily than a row
	// identifier out of the panel database.
	ServerName string
}

// Defaults fill the two fields that may be missing.
//
// An action the panel takes on its own has no session, and a request may
// arrive without a readable address. Both read better as a word than as an
// empty column.
func (e *Entry) Defaults() {
	if e.Username == "" {
		e.Username = "system"
	}
	if e.IPAddress == "" {
		e.IPAddress = "unknown"
	}
}

// Repository stores and reads audit entries.
type Repository interface {
	Write(ctx context.Context, entry Entry, at time.Time) error
	List(ctx context.Context, query Query) (Page, error)
}

// Forwarder mirrors an entry to a system outside the panel.
type Forwarder interface {
	Forward(entry Entry) error
}

// Logger writes audit entries.
type Logger struct {
	repo      Repository
	forwarder Forwarder

	// forwarding reports whether the mirror is switched on. It is read per
	// entry, so an operator can stop the flow to a noisy receiver without
	// touching the forwarding rules and without a restart. A nil accessor
	// means on, which is what every caller with no settings service wants.
	forwarding func() bool

	now func() time.Time
}

// NewLogger builds the audit logger. A nil forwarder keeps the database as the
// only record, which is what a panel without a SIEM runs with.
func NewLogger(repo Repository, forwarder Forwarder) *Logger {
	return &Logger{repo: repo, forwarder: forwarder, now: time.Now}
}

// WithForwarding returns the logger with the mirror switch attached.
//
// It is a separate call rather than a constructor parameter, because the
// panel builds the logger before it knows whether the settings are readable.
func (l *Logger) WithForwarding(enabled func() bool) *Logger {
	l.forwarding = enabled
	return l
}

// forwards reports whether this entry should reach the mirror.
func (l *Logger) forwards() bool {
	return l.forwarder != nil && (l.forwarding == nil || l.forwarding())
}

// Write stores one entry and mirrors it.
//
// A database failure is returned rather than swallowed. An action that cannot
// be recorded is an action nobody can account for later, so the caller decides
// whether to continue.
//
// The mirror runs either way. It sits off the panel host, which is exactly
// where a record is worth having when the panel database is the thing that
// went wrong.
func (l *Logger) Write(ctx context.Context, entry Entry) error {
	if entry.Action == "" {
		return fmt.Errorf("audit entry has no action")
	}
	entry.Defaults()

	err := l.repo.Write(ctx, entry, l.now().UTC())
	if err != nil {
		slog.Error("cannot write the audit entry",
			"action", entry.Action, "username", entry.Username, "error", err)
	}

	if l.forwards() {
		if forwardErr := l.forwarder.Forward(entry); forwardErr != nil {
			// The entry is in the database. Failing the action over a syslog
			// socket would be worse than reporting that the mirror is down.
			slog.Error("cannot forward the audit entry",
				"action", entry.Action, "error", forwardErr)
		}
	}
	return err
}

// List returns one page of the audit log.
func (l *Logger) List(ctx context.Context, query Query) (Page, error) {
	return l.repo.List(ctx, query)
}
