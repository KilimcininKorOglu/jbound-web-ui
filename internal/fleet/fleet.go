// Package fleet keeps the panel's view of what every managed server holds.
//
// The host entries file on each server stays authoritative. What lives here is
// a read cache, refilled after every write and on a timer, so a page load does
// not have to reach out over SSH to answer.
package fleet

import (
	"time"

	"unbound-web/internal/dnsfile"
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

// Pagination bounds.
const (
	DefaultPerPage = 25
	MinPerPage     = 10
	MaxPerPage     = 100
)

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

// Normalise clamps the paging fields.
//
// The page itself cannot be clamped yet, because the total is only known once
// the query has run. Page does that afterwards.
func (q *Query) Normalise() {
	if q.Scope == "" {
		q.Scope = ScopeAll
	}
	if q.PerPage == 0 {
		q.PerPage = DefaultPerPage
	}
	q.PerPage = max(MinPerPage, min(MaxPerPage, q.PerPage))
	q.Page = max(1, q.Page)
}

// Row is one cached record together with the server it came from.
type Row struct {
	dnsfile.Record

	ServerID   int64
	ServerName string

	// Stale marks a row whose server has not been read recently, so the view
	// can say so rather than presenting old records as current.
	Stale bool
}

// Page is one page of a listing.
type Page struct {
	Rows       []Row
	Total      int
	Page       int
	PerPage    int
	TotalPages int
}

// NewPage clamps the requested page against the total, because a page number
// out of range comes from a stale link rather than from a missing page.
func NewPage(query Query, total int) Page {
	totalPages := max(1, (total+query.PerPage-1)/query.PerPage)

	return Page{
		Total:      total,
		Page:       max(1, min(query.Page, totalPages)),
		PerPage:    query.PerPage,
		TotalPages: totalPages,
	}
}

// Offset is where the page starts in the result set.
func (p Page) Offset() int { return (p.Page - 1) * p.PerPage }
