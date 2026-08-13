package web

import (
	"net/http"
	"strings"

	"unbound-web/internal/dnsfile"
	"unbound-web/internal/fleet"
	"unbound-web/internal/i18n"
	"unbound-web/internal/server"
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
}

func (a *App) handleDiffPage(w http.ResponseWriter, r *http.Request) {
	data, err := a.diffPageData(r)
	if err != nil {
		a.dnsError(w, "cannot compare the servers", err)
		return
	}
	a.Render(w, r, http.StatusOK, "diff", PageData{Title: "nav.record_diff", Data: data})
}

// handleDiffTable re-renders the table, which is what the filter and every
// repair swap back into the page.
func (a *App) handleDiffTable(w http.ResponseWriter, r *http.Request) {
	data, err := a.diffPageData(r)
	if err != nil {
		a.dnsError(w, "cannot compare the servers", err)
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

	return diffPageData{
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

// handleDiffRepair writes one record to every server that lacks it or holds a
// different value.
func (a *App) handleDiffRepair(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.reportProblem(w, r, a.catalog(r).T("error.form_unreadable"), http.StatusBadRequest)
		return
	}

	target, err := targetFromValues(r.Form)
	if err != nil {
		a.reportProblem(w, r, recordMessage(a.catalog(r), err), http.StatusBadRequest)
		return
	}

	want := recordFromValues(r.Form)
	if want.Type == dnsfile.TypeMX && want.Priority == 0 {
		want.Priority = dnsfile.DefaultMXPriority
	}

	report, err := a.Records.Repair(r.Context(), a.actor(r), target, want)
	if err != nil {
		a.reportProblem(w, r, recordMessage(a.catalog(r), err), dnsStatus(err))
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
