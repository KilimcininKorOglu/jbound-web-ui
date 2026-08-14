package web

import (
	"context"
	"net/http"
	"strings"

	"jbound/internal/fleet"
	"jbound/internal/i18n"
	"jbound/internal/server"
	"jbound/internal/settings"
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

	query := listingFrom(r.Form)
	only := r.Form.Get("only_mismatches") != ""

	// The page opens on the filter, so a first load with no controls at all
	// still shows the differences rather than every record twice over.
	if _, chosen := r.Form["view"]; !chosen {
		only = true
	}

	diff, err := a.Records.Diff(r.Context(), query, only)
	if err != nil {
		return diffPageData{}, err
	}

	groups, err := a.Servers.ListGroups(r.Context())
	if err != nil {
		return diffPageData{}, err
	}
	servers, err := a.Servers.List(r.Context())
	if err != nil {
		return diffPageData{}, err
	}

	sourceID, sourceName := a.sourceServer(r.Context())

	return diffPageData{
		SourceID:       sourceID,
		SourceName:     sourceName,
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

// sourceServer resolves the chosen source into an identifier and a name.
//
// A source that no longer exists reads as none. The setting is cleared when a
// server is deleted or disabled, and this is the second line of that rule.
func (a *App) sourceServer(ctx context.Context) (int64, string) {
	id := a.Settings.Values().Int64(settings.SourceServerID)
	if id <= 0 {
		return 0, ""
	}

	record, err := a.Servers.Get(ctx, id)
	if err != nil || !record.Enabled {
		return 0, ""
	}
	return record.ID, record.Name
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

	sourceID, _ := a.sourceServer(r.Context())
	report, err := a.Records.Mirror(r.Context(), a.actor(r), target, sourceID)
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

var repairReport = reportKind{
	Title:   "report.repair.title",
	OK:      "report.repair.ok",
	Partial: "report.repair.partial",
	None:    "report.repair.none",

	ToastOK:      "report.repair.toast_ok",
	ToastPartial: "report.repair.toast_partial",
	ToastNone:    "report.repair.toast_none",
}
