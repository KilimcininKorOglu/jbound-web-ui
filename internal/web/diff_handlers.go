package web

import (
	"context"
	"net/http"
	"strings"

	"jbound/internal/fleet"
	"jbound/internal/i18n"
	"jbound/internal/server"
)

// diffPageData feeds the drift page and its table fragment.
type diffPageData struct {
	Diff  fleet.Diff
	Query fleet.Query

	Groups  []server.Group
	Servers []server.Server

	// OnlyMismatches drives the filter, which starts switched on: a fleet in
	// good shape produces rows that all say the same thing, and the few that
	// do not are the point.
	OnlyMismatches bool

	// Summary reads "3 of 42 records differ across 3 servers".
	Summary string

	// StaleNote names the columns drawn from an old cache.
	StaleNote string

	// Columns is how wide the table is, which the empty row has to span.
	Columns int

	// SourceID and SourceName name the server a synchronisation copies from.
	// They stay empty while no source is chosen, which is what the table says
	// instead of offering a button that cannot do anything.
	SourceID   int64
	SourceName string

	// IsAdmin gates the synchronisation, which is an admin route. A button
	// everybody can see and only some can press answers 403 to the rest.
	IsAdmin bool

	// HasDifferences reports whether there is anything to repair, so the batch
	// button is absent on a target that already agrees.
	HasDifferences bool
}

func (a *App) handleDiffPage(w http.ResponseWriter, r *http.Request) {
	data, err := a.diffPageData(r)
	if err != nil {
		a.dnsError(w, r, "cannot compare the servers", err)
		return
	}
	a.Render(w, r, http.StatusOK, "diff", PageData{Title: "nav.record_diff", Data: data})
}

// handleDiffTable re-renders the table, which is what the filter and every
// repair swap back into the page.
func (a *App) handleDiffTable(w http.ResponseWriter, r *http.Request) {
	data, err := a.diffPageData(r)
	if err != nil {
		a.dnsError(w, r, "cannot compare the servers", err)
		return
	}
	a.RenderPartial(w, r, http.StatusOK, "diff-table", data)
}

func (a *App) diffPageData(r *http.Request) (diffPageData, error) {
	catalog := a.catalog(r)

	if err := r.ParseForm(); err != nil {
		return diffPageData{}, err
	}

	query, err := a.listing(r.Context(), r.Form)
	if err != nil {
		return diffPageData{}, err
	}
	only := r.Form.Get("only_mismatches") != ""

	// The page opens on the filter, so a first load with no controls at all
	// still shows the differences rather than every record twice over.
	if _, chosen := r.Form["view"]; !chosen {
		only = true
	}

	groups, err := a.Servers.ListGroups(r.Context())
	if err != nil {
		return diffPageData{}, err
	}
	servers, err := a.Servers.List(r.Context())
	if err != nil {
		return diffPageData{}, err
	}

	// Nothing to compare. The selector is empty as well, so the page says what
	// a comparison is between rather than showing an empty table.
	if query.Scope == "" {
		return diffPageData{
			Query:          query,
			Groups:         groups,
			Servers:        servers,
			OnlyMismatches: only,
			Summary:        catalog.T("diff.no_group"),
			Columns:        4,
		}, nil
	}

	diff, err := a.Records.Diff(r.Context(), query, only)
	if err != nil {
		return diffPageData{}, err
	}

	sourceID, sourceName := a.sourceServer(r.Context(), query)
	session, _ := SessionFrom(r.Context())

	return diffPageData{
		SourceID:       sourceID,
		SourceName:     sourceName,
		IsAdmin:        session.IsAdmin(),
		HasDifferences: diff.Mismatches() > 0,
		Diff:           diff,
		Query:          query,
		Groups:         groups,
		Servers:        servers,
		OnlyMismatches: only,
		Summary:        diffSummary(catalog, diff),
		StaleNote:      diffStaleNote(catalog, diff),
		Columns:        len(diff.Servers) + 4,
	}, nil
}

// diffSummary says how much of the target disagrees.
func diffSummary(catalog *i18n.Catalog, diff fleet.Diff) string {
	switch {
	case len(diff.Servers) < 2:
		return catalog.T("diff.choose_group")
	case len(diff.Rows) == 0 && diff.OnlyMismatches:
		return catalog.T("diff.same")
	case len(diff.Rows) == 0:
		return catalog.T("diff.nothing_cached")
	case diff.OnlyMismatches:
		return catalog.Tf("diff.differ_only",
			plural(catalog, "record", len(diff.Rows)),
			plural(catalog, "server", len(diff.Servers)))
	default:
		return catalog.Tf("diff.differ",
			plural(catalog, "record", diff.Mismatches()),
			plural(catalog, "record", len(diff.Rows)),
			plural(catalog, "server", len(diff.Servers)))
	}
}

// plural writes a count with its noun, so a summary reads as a sentence
// rather than as a number with an s bolted on.
//
// The two forms are separate keys, because a language decides for itself where
// the plural sits and whether it exists at all.
func plural(catalog *i18n.Catalog, noun string, count int) string {
	if count == 1 {
		return catalog.T("diff.count." + noun + ".one")
	}
	return catalog.Tf("diff.count."+noun+".many", count)
}

// diffStaleNote warns that a difference may be read from an old cache.
func diffStaleNote(catalog *i18n.Catalog, diff fleet.Diff) string {
	stale := diff.Stale()
	if len(stale) == 0 {
		return ""
	}
	return catalog.Tf("diff.stale_note_long", strings.Join(stale, ", "))
}

// sourceServer resolves the source of the compared target into an identifier
// and a name.
//
// The reference belongs to the group being compared, so a page showing one
// group never offers to copy another group's records over it. A comparison of
// a single server reads the source of the group that server is in, which is
// what the button would copy from.
func (a *App) sourceServer(ctx context.Context, query fleet.Query) (int64, string) {
	groupID := query.GroupID

	if query.Scope == fleet.ScopeServer {
		record, err := a.Servers.Get(ctx, query.ServerID)
		if err != nil {
			return 0, ""
		}
		groupID = record.GroupID
	}

	source, ok, err := a.Servers.SourceServer(ctx, groupID)
	if err != nil || !ok {
		return 0, ""
	}
	return source.ID, source.Name
}

// handleDiffSync makes every server of the target hold what the source holds.
//
// It deletes as well as adds, which is why it is an admin route: it removes
// records the operator did not name one by one.
func (a *App) handleDiffSync(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.reportProblem(w, r, a.catalog(r).T("error.form_unreadable"), http.StatusBadRequest)
		return
	}

	target, err := targetFromValues(r.Form)
	if err != nil {
		a.reportProblem(w, r, recordMessage(r.Context(), a.catalog(r), err), http.StatusBadRequest)
		return
	}

	report, err := a.Records.Mirror(r.Context(), a.actor(r), target)
	if err != nil {
		a.reportProblem(w, r, recordMessage(r.Context(), a.catalog(r), err), dnsStatus(err))
		return
	}

	a.renderReport(w, r, report, syncReport)
}

var syncReport = reportKind{
	Title:   "report.sync.title",
	OK:      "report.sync.ok",
	Partial: "report.sync.partial",
	None:    "report.sync.none",

	ToastOK:      "report.sync.toast_ok",
	ToastPartial: "report.sync.toast_partial",
	ToastNone:    "report.sync.toast_none",
}

// handleDiffRepair writes one record to every server that lacks it or holds a
// different value.
func (a *App) handleDiffRepair(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.reportProblem(w, r, a.catalog(r).T("error.form_unreadable"), http.StatusBadRequest)
		return
	}

	target, err := targetFromValues(r.Form)
	if err != nil {
		a.reportProblem(w, r, recordMessage(r.Context(), a.catalog(r), err), http.StatusBadRequest)
		return
	}

	want := recordFromValues(r.Form)

	report, err := a.Records.Repair(r.Context(), a.actor(r), target, want)
	if err != nil {
		a.reportProblem(w, r, recordMessage(r.Context(), a.catalog(r), err), dnsStatus(err))
		return
	}

	a.renderReport(w, r, report, repairReport)
}

// handleDiffRepairAll closes every difference of the target in one pass.
//
// It adds and never removes, so it sits with the per record repair rather than
// with the synchronisation: an operator who may write a record may write the
// records their fleet already holds.
func (a *App) handleDiffRepairAll(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.reportProblem(w, r, a.catalog(r).T("error.form_unreadable"), http.StatusBadRequest)
		return
	}

	target, err := targetFromValues(r.Form)
	if err != nil {
		a.reportProblem(w, r, recordMessage(r.Context(), a.catalog(r), err), http.StatusBadRequest)
		return
	}

	report, err := a.Records.RepairAll(r.Context(), a.actor(r), target)
	if err != nil {
		a.reportProblem(w, r, recordMessage(r.Context(), a.catalog(r), err), dnsStatus(err))
		return
	}

	a.renderReport(w, r, report, repairAllReport)
}

var repairAllReport = reportKind{
	Title:   "report.repair_all.title",
	OK:      "report.repair_all.ok",
	Partial: "report.repair_all.partial",
	None:    "report.repair_all.none",

	ToastOK:      "report.repair_all.toast_ok",
	ToastPartial: "report.repair_all.toast_partial",
	ToastNone:    "report.repair_all.toast_none",
}

var repairReport = reportKind{
	Title:   "report.repair.title",
	OK:      "report.repair.ok",
	Partial: "report.repair.partial",
	None:    "report.repair.none",

	ToastOK:      "report.repair.toast_ok",
	ToastPartial: "report.repair.toast_partial",
	ToastNone:    "report.repair.toast_none",
}
