package web

import (
	"net/http"
	"slices"
	"strings"

	"unbound-web/internal/audit"
	"unbound-web/internal/i18n"
	"unbound-web/internal/server"
)

// logsPageData feeds the audit log page and its table fragment.
type logsPageData struct {
	Page  audit.Page
	Query audit.Query

	// Servers fills the server filter. A row keeps the name of a server that
	// was deleted, so the filter lists what still exists and the table still
	// shows the rest.
	Servers []server.Server

	Actions []string
	Pages   []pageLink
	Summary string
}

func (a *App) handleLogsPage(w http.ResponseWriter, r *http.Request) {
	data, err := a.logsPageData(r)
	if err != nil {
		a.internalError(w, "cannot load the audit log", err)
		return
	}
	a.Render(w, r, http.StatusOK, "logs", PageData{Title: "nav.audit_logs", Data: data})
}

// handleLogsTable re-renders the table, which is what every filter and page
// swaps back into the page.
func (a *App) handleLogsTable(w http.ResponseWriter, r *http.Request) {
	data, err := a.logsPageData(r)
	if err != nil {
		a.internalError(w, "cannot load the audit log", err)
		return
	}
	a.RenderPartial(w, r, http.StatusOK, "log-table", data)
}

func (a *App) logsPageData(r *http.Request) (logsPageData, error) {
	if err := r.ParseForm(); err != nil {
		return logsPageData{}, err
	}
	query := auditQuery(r.Form)

	page, err := a.Audit.List(r.Context(), query)
	if err != nil {
		return logsPageData{}, err
	}
	servers, err := a.Servers.List(r.Context())
	if err != nil {
		return logsPageData{}, err
	}

	return logsPageData{
		Page:    page,
		Query:   query,
		Servers: servers,
		Actions: audit.Actions(),
		Pages:   logPageWindow(page),
		Summary: logSummary(a.catalog(r), page),
	}, nil
}

// auditQuery reads the log filters.
//
// An unreadable value falls back to the default rather than failing, because
// these are view controls and a stale link is not worth an error page.
func auditQuery(values valueSource) audit.Query {
	query := audit.Query{
		Search:   strings.TrimSpace(values.Get("search")),
		Action:   values.Get("action"),
		ServerID: parseID(values.Get("server_id")),
		Page:     parseInt(values.Get("page")),
		PerPage:  parseInt(values.Get("per_page")),
	}

	// An action nobody writes would filter every row away and read as an empty
	// log rather than as a bad filter.
	if query.Action != "" && !knownAction(query.Action) {
		query.Action = ""
	}

	query.Normalise()
	return query
}

func knownAction(action string) bool {
	return slices.Contains(audit.Actions(), action)
}

// logSummary reads "Showing X of Y entries (Page A/B)".
func logSummary(catalog *i18n.Catalog, page audit.Page) string {
	if page.Total == 0 {
		return catalog.T("summary.no_entries")
	}
	return catalog.Tf("summary.entries",
		len(page.Rows), page.Total, page.Page, page.TotalPages)
}

// logPageWindow builds the page links of the audit log.
func logPageWindow(page audit.Page) []pageLink {
	return pageWindow(pageBounds{Page: page.Page, TotalPages: page.TotalPages})
}
