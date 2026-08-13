package web

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"unbound-web/internal/audit"
	"unbound-web/internal/dnsfile"
	"unbound-web/internal/fleet"
	"unbound-web/internal/server"
	"unbound-web/internal/store"
)

// dnsPageData feeds the records page and its table fragment.
type dnsPageData struct {
	Page  fleet.Page
	Query fleet.Query

	// Servers and Groups fill the target selector.
	Servers []server.Server
	Groups  []server.Group

	// Types fills the filter, so the form and the validator cannot disagree
	// about which types exist.
	Types []string

	// ShowServer hides the server column when the view is scoped to one
	// server, where every row would repeat the same name.
	ShowServer bool

	// Pages is the window of page links around the current page.
	Pages []pageLink

	// Summary reads "Showing X of Y records (Page A/B)".
	Summary string

	// Status drives the Apply Rules bar above the table.
	Status fleet.Status

	// StaleNote names the servers whose cache is old, so the status bar can
	// say what it cannot vouch for.
	StaleNote string
}

// pageLink is one entry of the pagination control.
type pageLink struct {
	Number int
	Gap    bool
}

// recordFormData feeds the add and edit form.
type recordFormData struct {
	Record  dnsfile.Record
	Old     dnsfile.Record
	Query   fleet.Query
	Servers []server.Server
	Groups  []server.Group
	Types   []string
	IsNew   bool
	Problem string
}

// reportData feeds the per server result table.
type reportData struct {
	Report fleet.Report
	Kind   reportKind

	// Problem replaces the result table when the operation was refused before
	// it reached a server.
	Problem string
}

// reportKind is the wording one kind of fleet operation uses.
//
// The table is the same for a record change and a reload. What differs is what
// a failure means to the reader, so the sentences travel with the report
// rather than being decided inside the template.
type reportKind struct {
	Title   string
	OK      string
	Partial string
	None    string

	ToastOK      string
	ToastPartial string
	ToastNone    string
}

var changeReport = reportKind{
	Title:   "Result",
	OK:      "The change reached every server it was meant for.",
	Partial: "Some servers took the change and others did not. The ones that failed still hold the old file.",
	None:    "No server took the change.",

	ToastOK:      "The change reached every server.",
	ToastPartial: "The change reached some servers but not all.",
	ToastNone:    "The change reached no server.",
}

var reloadReport = reportKind{
	Title:   "Apply Rules",
	OK:      "Every server reloaded and now answers from the file it holds.",
	Partial: "Some servers reloaded and others did not. The ones that failed still answer from the file they loaded last.",
	None:    "No server reloaded.",

	ToastOK:      "Every server reloaded.",
	ToastPartial: "Some servers reloaded but not all.",
	ToastNone:    "No server reloaded.",
}

func (a *App) handleDNSPage(w http.ResponseWriter, r *http.Request) {
	data, err := a.dnsPageData(r)
	if err != nil {
		a.dnsError(w, "cannot load the records", err)
		return
	}
	a.Render(w, r, http.StatusOK, "dns", PageData{Title: "DNS Records", Data: data})
}

// handleDNSRecords re-renders the table, which is what every filter, page and
// change swaps back into the page.
//
// The status bar rides along out of band. It reads the same target as the
// table, and a separate request for it could answer about a different one.
func (a *App) handleDNSRecords(w http.ResponseWriter, r *http.Request) {
	data, err := a.dnsPageData(r)
	if err != nil {
		a.dnsError(w, "cannot load the records", err)
		return
	}
	a.RenderPartial(w, http.StatusOK, "record-table-swap", data)
}

func (a *App) dnsPageData(r *http.Request) (dnsPageData, error) {
	// The controls arrive in the query string of a listing and in the body of
	// a refresh, so both are read the same way.
	if err := r.ParseForm(); err != nil {
		return dnsPageData{}, err
	}
	query := listingFrom(r.Form)

	page, err := a.Records.Page(r.Context(), query)
	if err != nil {
		return dnsPageData{}, err
	}

	servers, err := a.Servers.List(r.Context())
	if err != nil {
		return dnsPageData{}, err
	}
	groups, err := a.Servers.ListGroups(r.Context())
	if err != nil {
		return dnsPageData{}, err
	}
	status, err := a.Records.Status(r.Context(), query)
	if err != nil {
		return dnsPageData{}, err
	}

	return dnsPageData{
		Page:       page,
		Query:      query,
		Servers:    servers,
		Groups:     groups,
		Types:      dnsfile.Types,
		ShowServer: query.Scope != fleet.ScopeServer,
		Pages:      pageWindow(pageBounds{page.Page, page.TotalPages}),
		Summary:    summary(page),
		Status:     status,
		StaleNote:  staleNote(status),
	}, nil
}

// staleNote names the servers the status was drawn from too long ago.
func staleNote(status fleet.Status) string {
	stale := status.Stale()
	if len(stale) == 0 {
		return ""
	}
	return "The panel has not read " + strings.Join(stale, ", ") + " recently."
}

// listingFrom reads the listing controls out of a form or a query string.
//
// Anything unreadable falls back to the default rather than failing. These are
// view controls, and a stale link is not worth an error page.
func listingFrom(values valueSource) fleet.Query {
	query := fleet.Query{
		Scope:    values.Get("scope"),
		ServerID: parseID(values.Get("server_id")),
		GroupID:  parseID(values.Get("group_id")),
		Search:   strings.TrimSpace(values.Get("search")),
		Type:     values.Get("type"),
		Page:     parseInt(values.Get("page")),
		PerPage:  parseInt(values.Get("per_page")),
	}

	// The selector offers servers and groups in one list, so it travels as one
	// field and is split here. It wins over the separate fields, which carry
	// the target the page was drawn with.
	if chosen, ok := splitTarget(values.Get("target")); ok {
		if chosen != scopeOf(query) {
			// The selector moved, so the page number points nowhere.
			query.Page = 1
		}
		query.Scope, query.ServerID, query.GroupID =
			chosen.Scope, chosen.ServerID, chosen.GroupID
	}

	// A scope without its identifier would list the whole fleet under a label
	// that says otherwise.
	switch query.Scope {
	case fleet.ScopeServer:
		if query.ServerID == 0 {
			query.Scope = fleet.ScopeAll
		}
	case fleet.ScopeGroup:
		if query.GroupID == 0 {
			query.Scope = fleet.ScopeAll
		}
	default:
		query.Scope = fleet.ScopeAll
	}

	if query.Type != "" && dnsfile.ValidateRecordType(query.Type) != nil {
		query.Type = ""
	}

	query.Normalise()
	return query
}

// summary reads "Showing X of Y records (Page A/B)".
func summary(page fleet.Page) string {
	if page.Total == 0 {
		return "No records found."
	}
	return fmt.Sprintf("Showing %d of %d records (Page %d/%d)",
		len(page.Rows), page.Total, page.Page, page.TotalPages)
}

// pageBounds is what the pagination control needs from any page.
type pageBounds struct {
	Page       int
	TotalPages int
}

// pageWindow builds the page links: the first page, the two neighbours of the
// current one, the last page, and a gap marker where numbers were left out.
func pageWindow(page pageBounds) []pageLink {
	if page.TotalPages <= 1 {
		return nil
	}

	wanted := map[int]bool{1: true, page.TotalPages: true}
	for number := page.Page - 2; number <= page.Page+2; number++ {
		if number >= 1 && number <= page.TotalPages {
			wanted[number] = true
		}
	}

	var links []pageLink
	previous := 0
	for number := 1; number <= page.TotalPages; number++ {
		if !wanted[number] {
			continue
		}
		if previous != 0 && number != previous+1 {
			links = append(links, pageLink{Gap: true})
		}
		links = append(links, pageLink{Number: number})
		previous = number
	}
	return links
}

func (a *App) handleRecordForm(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.dnsError(w, "cannot read the form", err)
		return
	}
	query := listingFrom(r.Form)

	data := recordFormData{
		Query: query,
		Types: dnsfile.Types,
		IsNew: true,
	}

	// An edit arrives with the record it is about, because the file is the
	// source of truth and the panel has no identifier for a line.
	values := r.URL.Query()
	if values.Get("fqdn") != "" {
		data.IsNew = false
		data.Record = recordFromValues(values)
		data.Old = data.Record
	}

	servers, err := a.Servers.List(r.Context())
	if err != nil {
		a.dnsError(w, "cannot load the servers", err)
		return
	}
	groups, err := a.Servers.ListGroups(r.Context())
	if err != nil {
		a.dnsError(w, "cannot load the groups", err)
		return
	}
	data.Servers = servers
	data.Groups = groups

	a.RenderPartial(w, http.StatusOK, "record-form", data)
}

func (a *App) handleRecordCreate(w http.ResponseWriter, r *http.Request) {
	a.applyOperation(w, r, fleet.OpAdd)
}

func (a *App) handleRecordUpdate(w http.ResponseWriter, r *http.Request) {
	a.applyOperation(w, r, fleet.OpEdit)
}

func (a *App) handleRecordDelete(w http.ResponseWriter, r *http.Request) {
	a.applyOperation(w, r, fleet.OpDelete)
}

// applyOperation runs one change and renders the per server result.
func (a *App) applyOperation(w http.ResponseWriter, r *http.Request, kind string) {
	// r.Form rather than r.PostForm: a delete carries its fields in the query
	// string, because that is where htmx puts them for that method.
	if err := r.ParseForm(); err != nil {
		a.recordProblem(w, r, kind, "The form could not be read.", http.StatusBadRequest)
		return
	}

	op := fleet.Operation{Kind: kind, Record: recordFromValues(r.Form)}
	if kind == fleet.OpEdit {
		op.Old = oldRecordFromValues(r.Form)
	}

	target, err := targetFromValues(r.Form)
	if err != nil {
		a.recordProblem(w, r, kind, recordMessage(err), http.StatusBadRequest)
		return
	}

	report, err := a.Records.Apply(r.Context(), a.actor(r), target, op)
	if err != nil {
		a.recordProblem(w, r, kind, recordMessage(err), dnsStatus(err))
		return
	}

	a.renderReport(w, report, changeReport)
}

// handleRecordApply reloads the resolver on every server of the target.
//
// The file and what the resolver answers from are two different things, so
// this is a separate action rather than the tail of every write.
func (a *App) handleRecordApply(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.reportProblem(w, "The form could not be read.", http.StatusBadRequest)
		return
	}

	target, err := targetFromValues(r.Form)
	if err != nil {
		a.reportProblem(w, recordMessage(err), http.StatusBadRequest)
		return
	}

	report, err := a.Records.Reload(r.Context(), a.actor(r), target)
	if err != nil {
		a.reportProblem(w, recordMessage(err), dnsStatus(err))
		return
	}

	a.renderReport(w, report, reloadReport)
}

// renderReport answers with the result table and the status the outcome earns.
func (a *App) renderReport(w http.ResponseWriter, report fleet.Report, kind reportKind) {

	success, failed, _ := report.Counts()

	status := http.StatusOK
	switch {
	case failed == 0:
		SetToast(w, ToastSuccess, kind.ToastOK)
	case success == 0:
		status = http.StatusInternalServerError
		SetToast(w, ToastError, kind.ToastNone)
	default:
		// A partial success is not a success. It gets its own colour, and the
		// result table stays open so the operator can see which server failed.
		status = http.StatusMultiStatus
		SetToast(w, ToastWarning, kind.ToastPartial)
	}

	SetTrigger(w, "records-changed", nil)
	a.RenderPartial(w, status, "record-report", reportData{Report: report, Kind: kind})
}

// reportProblem answers a refused operation that has no form behind it.
//
// Apply Rules is a button rather than a form, so the reason goes where the
// result would have been.
func (a *App) reportProblem(w http.ResponseWriter, problem string, status int) {

	SetToast(w, ToastError, problem)
	a.RenderPartial(w, status, "record-report", reportData{
		Kind:    reloadReport,
		Problem: problem,
	})
}

// queryFormData feeds the query form and its answers.
type queryFormData struct {
	Domain string
	Type   string
	Query  fleet.Query

	Servers []server.Server
	Groups  []server.Group
	Types   []string

	// Report stays empty until a query has run.
	Report  fleet.QueryReport
	Asked   bool
	Problem string
}

// handleQueryForm opens the query panel.
func (a *App) handleQueryForm(w http.ResponseWriter, r *http.Request) {
	data, err := a.queryData(r)
	if err != nil {
		a.dnsError(w, "cannot load the query form", err)
		return
	}
	a.RenderPartial(w, http.StatusOK, "record-query", data)
}

// handleQuery asks the target what it answers for a name.
//
// The query leaves the panel host rather than the remote shell. The name is
// operator input, and a remote shell would turn it into an injection surface.
func (a *App) handleQuery(w http.ResponseWriter, r *http.Request) {
	data, err := a.queryData(r)
	if err != nil {
		a.dnsError(w, "cannot load the query form", err)
		return
	}
	data.Domain = strings.TrimSpace(r.Form.Get("domain"))
	data.Type = strings.TrimSpace(r.Form.Get("query_type"))

	target, err := targetFromValues(r.Form)
	if err != nil {
		// A query reads, so the whole fleet is a fair target here.
		target = fleet.Target{Scope: fleet.ScopeAll}
	}

	report, err := a.Records.Query(r.Context(), a.actor(r), target, data.Domain, data.Type)
	if err != nil {
		data.Problem = recordMessage(err)
		a.RenderPartial(w, dnsStatus(err), "record-query", data)
		return
	}

	data.Report = report
	data.Asked = true
	a.RenderPartial(w, http.StatusOK, "record-query", data)
}

// queryData fills the parts of the query panel that do not depend on an answer.
//
// The controls travel in the body of a query and in the query string of the
// form request, so both are read the same way.
func (a *App) queryData(r *http.Request) (queryFormData, error) {
	if err := r.ParseForm(); err != nil {
		return queryFormData{}, err
	}

	data := queryFormData{
		Query: listingFrom(r.Form),
		Types: dnsfile.Types,
	}

	servers, err := a.Servers.List(r.Context())
	if err != nil {
		return queryFormData{}, err
	}
	groups, err := a.Servers.ListGroups(r.Context())
	if err != nil {
		return queryFormData{}, err
	}
	data.Servers = servers
	data.Groups = groups
	return data, nil
}

// handleRecordRefresh reads every server again.
func (a *App) handleRecordRefresh(w http.ResponseWriter, r *http.Request) {
	results, err := a.Records.Refresh(r.Context())
	if err != nil {
		a.dnsError(w, "cannot refresh the records", err)
		return
	}

	failed := 0
	for _, result := range results {
		if !result.OK() {
			failed++
		}
	}

	// Only a refresh somebody asked for is recorded. The timer runs every few
	// minutes, and a row for each pass would bury the changes the log is for.
	a.auditRefresh(r, len(results)-failed, len(results))

	switch {
	case len(results) == 0:
		SetToast(w, ToastInfo, "There is no enabled server to read.")
	case failed == 0:
		SetToast(w, ToastSuccess, "Every server was read.")
	default:
		SetToast(w, ToastWarning,
			fmt.Sprintf("%d of %d servers could not be read.", failed, len(results)))
	}

	a.handleDNSRecords(w, r)
}

// auditRefresh records a refresh the operator asked for.
func (a *App) auditRefresh(r *http.Request, read, total int) {
	if total == 0 {
		return
	}

	details := fmt.Sprintf("Refreshed the record cache: %d of %d servers read", read, total)
	actor := a.actor(r)

	_ = a.Audit.Write(r.Context(), audit.Entry{
		UID:       actor.UID,
		Username:  actor.Username,
		Action:    audit.ActionCacheRefresh,
		Details:   details,
		IPAddress: actor.IPAddress,
	})
}

// --- Helpers ---------------------------------------------------------------

// valueSource covers both a parsed form and a query string.
type valueSource interface {
	Get(key string) string
}

// recordFromValues reads a record out of a form or a query string.
func recordFromValues(values valueSource) dnsfile.Record {
	return dnsfile.Record{
		FQDN:     strings.TrimSpace(values.Get("fqdn")),
		Type:     strings.TrimSpace(values.Get("type")),
		Value:    strings.TrimSpace(values.Get("value")),
		Priority: parseInt(values.Get("priority")),
	}
}

// oldRecordFromValues reads the record an edit replaces.
func oldRecordFromValues(values valueSource) dnsfile.Record {
	return dnsfile.Record{
		FQDN:     strings.TrimSpace(values.Get("old_fqdn")),
		Type:     strings.TrimSpace(values.Get("old_type")),
		Value:    strings.TrimSpace(values.Get("old_value")),
		Priority: parseInt(values.Get("old_priority")),
	}
}

// splitTarget reads the combined selector value, which is how the interface
// offers servers and groups in one list.
//
// The split happens here rather than in the browser. A script that rewrites
// hidden fields on change races with the request that reads them, and the
// loser of that race is a change aimed at the wrong servers.
func splitTarget(raw string) (fleet.Target, bool) {
	scope, rest, found := strings.Cut(raw, ":")
	if !found {
		return fleet.Target{}, false
	}

	id := parseID(rest)
	switch scope {
	case fleet.ScopeServer:
		return fleet.Target{Scope: scope, ServerID: id}, true
	case fleet.ScopeGroup:
		return fleet.Target{Scope: scope, GroupID: id}, true
	case fleet.ScopeAll:
		return fleet.Target{Scope: scope}, true
	default:
		return fleet.Target{}, false
	}
}

// scopeOf is the target a listing currently covers.
func scopeOf(query fleet.Query) fleet.Target {
	return fleet.Target{
		Scope:    query.Scope,
		ServerID: query.ServerID,
		GroupID:  query.GroupID,
	}
}

// targetFromValues reads which servers a change is meant for.
func targetFromValues(values valueSource) (fleet.Target, error) {
	target := fleet.Target{
		Scope:    values.Get("scope"),
		ServerID: parseID(values.Get("server_id")),
		GroupID:  parseID(values.Get("group_id")),
	}
	if chosen, ok := splitTarget(values.Get("target")); ok {
		target = chosen
	}

	switch target.Scope {
	case fleet.ScopeServer:
		if target.ServerID == 0 {
			return fleet.Target{}, fmt.Errorf("%w: no server was chosen", fleet.ErrScope)
		}
	case fleet.ScopeGroup:
		if target.GroupID == 0 {
			return fleet.Target{}, fmt.Errorf("%w: no group was chosen", fleet.ErrScope)
		}
	default:
		return fleet.Target{}, fmt.Errorf(
			"%w: a change needs a single server or a group", fleet.ErrScope)
	}
	return target, nil
}

// recordProblem sends the form back with the reason it was refused.
func (a *App) recordProblem(w http.ResponseWriter, r *http.Request,
	kind, problem string, status int) {

	data := recordFormData{
		Record:  recordFromValues(r.Form),
		Query:   listingFrom(r.Form),
		Types:   dnsfile.Types,
		IsNew:   kind == fleet.OpAdd,
		Problem: problem,
	}
	if kind == fleet.OpEdit {
		data.Old = oldRecordFromValues(r.Form)
	}

	if servers, err := a.Servers.List(r.Context()); err == nil {
		data.Servers = servers
	}
	if groups, err := a.Servers.ListGroups(r.Context()); err == nil {
		data.Groups = groups
	}

	a.RenderPartial(w, status, "record-form", data)
}

// recordMessage turns a refusal into a sentence the form can show.
//
// A rejected record and a missing target are the operator's to fix, so the
// reason travels as it is rather than as a generic failure.
func recordMessage(err error) string {
	switch {
	case errors.Is(err, dnsfile.ErrInvalid):
		return capitalise(strings.TrimPrefix(err.Error(), dnsfile.ErrInvalid.Error()+": ")) + "."
	case errors.Is(err, fleet.ErrScope):
		return capitalise(strings.TrimPrefix(err.Error(), fleet.ErrScope.Error()+": ")) + "."
	default:
		return userMessage(err)
	}
}

// capitalise makes a reason read as a sentence.
func capitalise(text string) string {
	if text == "" {
		return text
	}
	return strings.ToUpper(text[:1]) + text[1:]
}

// dnsStatus maps a refusal onto the code the form expects.
func dnsStatus(err error) int {
	switch {
	case errors.Is(err, dnsfile.ErrInvalid), errors.Is(err, fleet.ErrScope):
		return http.StatusBadRequest
	case errors.Is(err, server.ErrValidation):
		return http.StatusUnprocessableEntity
	case errors.Is(err, store.ErrNotFound):
		return http.StatusNotFound
	default:
		return http.StatusInternalServerError
	}
}

// dnsError answers a failure that has no form to go back to.
func (a *App) dnsError(w http.ResponseWriter, message string, err error) {
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	a.internalError(w, message, err)
}

func parseID(raw string) int64 {
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id < 0 {
		return 0
	}
	return id
}

func parseInt(raw string) int {
	value, err := strconv.Atoi(raw)
	if err != nil || value < 0 {
		return 0
	}
	return value
}
