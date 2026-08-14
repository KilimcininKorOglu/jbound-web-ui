package audit

import (
	"time"

	"jbound/internal/paging"
)

// DefaultPerPage is what a request that names no page size gets. The source
// panel offered 50 rows and the log reads the same way here.
//
// The bounds around it are shared with every other listing, in the paging
// package.
const DefaultPerPage = 50

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
	q.Page, q.PerPage = paging.Clamp(q.Page, q.PerPage, DefaultPerPage)
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
	Rows []Row
	paging.Window
}

// NewPage places the requested page against the total.
func NewPage(query Query, total int) Page {
	return Page{Window: paging.Of(query.Page, query.PerPage, total)}
}

// Actions lists every action the panel writes, in the order the filter offers
// them. A filter built from this list cannot miss an action the panel records.
func Actions() []string {
	return []string{
		ActionLogin, ActionLogout, ActionLoginFailed, ActionSessionRevoke,
		ActionDNSAdd, ActionDNSEdit, ActionDNSDelete,
		ActionDNSRestart, ActionDNSQuery,
		ActionDiffRepair, ActionDiffSync, ActionCacheRefresh, ActionFileRestore,
		ActionServerCreate, ActionServerUpdate, ActionServerDelete, ActionServerTrust,
		ActionServerRotateKey, ActionServerTest,
		ActionGroupCreate, ActionGroupUpdate, ActionGroupDelete,
		ActionSIEMConfig, ActionSIEMTest,
		ActionSettingsUpdate, ActionAuditImport,
	}
}
