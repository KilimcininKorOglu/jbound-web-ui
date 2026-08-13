package audit

import "time"

// Pagination bounds. The source panel offered 50 rows by default and the log
// reads the same way here.
const (
	DefaultPerPage = 50
	MinPerPage     = 10
	MaxPerPage     = 100
)

// Query asks for a page of audit rows.
type Query struct {
	// Search matches the user name, the details and the address.
	Search string

	// Action is an exact match, because the values are constants rather than
	// free text.
	Action string

	// ServerID narrows the listing to one managed server.
	ServerID int64

	Page    int
	PerPage int
}

// Normalise clamps the paging fields.
func (q *Query) Normalise() {
	if q.PerPage == 0 {
		q.PerPage = DefaultPerPage
	}
	q.PerPage = max(MinPerPage, min(MaxPerPage, q.PerPage))
	q.Page = max(1, q.Page)
}

// Row is one audit entry as it is listed.
type Row struct {
	ID       int64
	UID      int
	Username string

	ServerID *int64

	// ServerName is empty when the action targeted no server, and it stays
	// empty when that server has since been deleted.
	ServerName string

	Action    string
	Details   string
	IPAddress string
	CreatedAt time.Time
}

// Page is one page of the audit log.
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

// Actions lists every action the panel writes, in the order the filter offers
// them. A filter built from this list cannot miss an action the panel records.
func Actions() []string {
	return []string{
		ActionLogin, ActionLogout, ActionLoginFailed,
		ActionDNSAdd, ActionDNSEdit, ActionDNSDelete,
		ActionDNSRestart, ActionDNSQuery,
		ActionDiffRepair, ActionCacheRefresh,
		ActionServerCreate, ActionServerUpdate, ActionServerDelete, ActionServerTrust,
		ActionGroupCreate, ActionGroupUpdate, ActionGroupDelete,
		ActionSIEMConfig, ActionSIEMTest,
	}
}
