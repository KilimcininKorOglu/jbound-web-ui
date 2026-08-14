// Package fleet keeps the panel's view of what every managed server holds.
//
// The host entries file on each server stays authoritative. What lives here is
// a read cache, refilled after every write and on a timer, so a page load does
// not have to reach out over SSH to answer.
package fleet

import (
	"time"

	"jbound/internal/dnsfile"
	"jbound/internal/paging"
)

// State is what the panel knows about one server's file.
type State struct {
	ServerID int64

	// FileSHA256 is the digest of the file as it was last read, which is what
	// a write is checked against before it replaces anything.
	FileSHA256 string

	// AppliedSHA256 is the digest that was in place the last time Apply Rules
	// reloaded the resolver. A difference means the server carries changes the
	// resolver has not picked up yet.
	AppliedSHA256 string

	// FetchedAt is when the cache was last filled. It stays nil for a server
	// nobody has read yet.
	FetchedAt *time.Time

	Reachable     bool
	UnboundActive bool
	RecordCount   int
	LastError     string
}

// Pending reports whether the file holds changes the resolver has not loaded.
func (s State) Pending() bool {
	return s.FileSHA256 != "" && s.FileSHA256 != s.AppliedSHA256
}

// Stale reports whether the cache is older than the panel is willing to trust.
//
// A stale entry is still shown. Hiding it would leave the operator with an
// empty page when a server goes quiet, which says less than old records and a
// warning next to them.
func (s State) Stale(now time.Time, after time.Duration) bool {
	if s.FetchedAt == nil {
		return true
	}
	return now.Sub(*s.FetchedAt) > after
}

// Scope names which servers a listing covers.
const (
	ScopeServer = "server"
	ScopeGroup  = "group"
	ScopeAll    = "all"
)

// DefaultPerPage is what a listing that names no page size falls back to when
// the operator has configured none. The bounds around it are shared with every
// other listing, in the paging package.
const DefaultPerPage = 25

// Query asks for a page of cached records.
type Query struct {
	// Scope decides whether ServerID, GroupID or neither is used.
	Scope    string
	ServerID int64
	GroupID  int64

	// Search matches the name or the value, without regard to case.
	Search string

	// Type filters on an exact record type.
	Type string

	Page    int
	PerPage int
}

// Normalise fills in the scope and clamps the paging fields.
func (q *Query) Normalise() {
	if q.Scope == "" {
		q.Scope = ScopeAll
	}
	q.Page, q.PerPage = paging.Clamp(q.Page, q.PerPage, DefaultPerPage)
}

// Row is one record as the target holds it.
//
// The same record usually sits on every server of a target, and a change
// through the panel reaches all of them at once. One row per server would
// therefore repeat the same record N times and offer N buttons that do the
// same thing, so the listing groups by the record and counts the servers.
type Row struct {
	dnsfile.Record

	// Holders are the servers of the target whose file carries this record.
	// A count below the size of the target is drift, which the diff view
	// explains server by server.
	Holders []int64

	// HolderNames carries the same servers by name, for the reader.
	HolderNames []string

	// Stale marks a row where at least one holder has not been read recently,
	// so the view can say so rather than presenting old records as current.
	Stale bool
}

// Complete reports whether every server of the target holds this record.
func (r Row) Complete(target int) bool { return target > 0 && len(r.Holders) >= target }

// Page is one page of a listing.
type Page struct {
	Rows []Row
	paging.Window

	// TargetServers is how many servers the listing covers, which is the
	// denominator of every row's holder count.
	TargetServers int
}

// NewPage places the requested page against the total.
func NewPage(query Query, total int) Page {
	return Page{Window: paging.Of(query.Page, query.PerPage, total)}
}
