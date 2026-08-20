// Package audit records who changed what, from where.
//
// The database is the primary record and the queue the receiver reads from, so
// the panel can still answer "who added this record" when the SIEM is
// unreachable.
package audit

import (
	"context"
	"fmt"
	"time"

	"jbound/internal/logging"
)

// Actions written by the panel. They are constants so a typo cannot create a
// second spelling that the log filters then miss.
const (
	ActionLogin         = "login"
	ActionLogout        = "logout"
	ActionLoginFailed   = "login_failed"
	ActionSessionRevoke = "session_revoke"

	ActionServerCreate    = "server_create"
	ActionServerUpdate    = "server_update"
	ActionServerDelete    = "server_delete"
	ActionServerTrust     = "server_trust"
	ActionServerRotateKey = "server_rotate_key"
	ActionServerTest      = "server_test"

	ActionGroupCreate = "group_create"
	ActionGroupUpdate = "group_update"
	ActionGroupDelete = "group_delete"

	// ActionGroupCollapse marks a membership the migration to one group per
	// server had to drop. The row is written by the migration itself, because a
	// server that quietly left a group is the one change an operator has no
	// other way to see.
	ActionGroupCollapse = "group_collapse"

	ActionDNSAdd     = "dns_add"
	ActionDNSEdit    = "dns_edit"
	ActionDNSDelete  = "dns_delete"
	ActionDNSRestart = "dns_restart"
	ActionDNSQuery   = "dns_query"

	ActionDiffRepair   = "diff_repair"
	ActionDiffSync     = "diff_sync"
	ActionCacheRefresh = "cache_refresh"
	ActionFileRestore  = "file_restore"

	// ActionConfigInclude marks a main resolver configuration the panel had to
	// repair, because it did not include the file the panel writes. It is its
	// own action rather than a note on the change that found it: the panel
	// edited a file outside the one it manages, on a server somebody else set
	// up.
	ActionConfigInclude = "config_include"

	ActionSIEMConfig = "siem_config"
	ActionSIEMTest   = "siem_test"

	ActionSettingsUpdate = "settings_update"

	// ActionAuditImport marks the one row the import command writes about
	// itself, so a trail that suddenly reaches further back says why.
	ActionAuditImport = "audit_import"
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

// Logger writes audit entries.
type Logger struct {
	repo Repository

	// notify tells the receiver queue that a row has landed. It is nil on a
	// panel that forwards nothing, and on every caller that has no queue.
	notify func()

	now func() time.Time
}

// NewLogger builds the audit logger.
func NewLogger(repo Repository) *Logger {
	return &Logger{repo: repo, now: time.Now}
}

// WithNotify returns the logger with a wake-up attached.
//
// The receiver queue reads the trail out of the database rather than being
// handed each entry, so all it needs is to be told that there is something new.
// The call must not block: an entry that waited on a receiver would make the
// action that caused it wait too.
//
// Whether an entry is forwarded is not decided here. The queue reads the switch
// when it picks the row up, which is what lets it keep its place while the
// mirror is off.
func (l *Logger) WithNotify(notify func()) *Logger {
	l.notify = notify
	return l
}

// Write stores one entry.
//
// A database failure is returned rather than swallowed. An action that cannot
// be recorded is an action nobody can account for later, so the caller decides
// whether to continue.
func (l *Logger) Write(ctx context.Context, entry Entry) error {
	return l.write(ctx, entry)
}

// storeTimeout bounds an audit insert once it is detached from the request.
//
// The row goes into a local SQLite database, so a write that has not landed in
// this long means the database is unavailable rather than busy, and holding the
// caller longer would not change the outcome.
const storeTimeout = 10 * time.Second

func (l *Logger) write(ctx context.Context, entry Entry) error {
	if entry.Action == "" {
		return fmt.Errorf("audit entry has no action")
	}
	entry.Defaults()

	// The entry describes something that already happened, so it outlives the
	// request that caused it. A browser that cancels, which htmx does whenever
	// it fires a second request from the same element, would otherwise leave a
	// changed resolver with no row in the log the operator reads.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
	defer cancel()

	err := l.repo.Write(ctx, entry, l.now().UTC())
	if err != nil {
		logging.From(ctx).Error("cannot write the audit entry",
			"action", entry.Action, "username", entry.Username, "error", err)
	}

	// The queue reads the row rather than this entry, so it is only worth
	// waking when the row landed.
	if err == nil && l.notify != nil {
		l.notify()
	}
	return err
}

// List returns one page of the audit log.
func (l *Logger) List(ctx context.Context, query Query) (Page, error) {
	return l.repo.List(ctx, query)
}
