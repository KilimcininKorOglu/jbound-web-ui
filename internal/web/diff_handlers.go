package web

import (
	"net/http"
	"strconv"
	"strings"

	"unbound-web/internal/dnsfile"
	"unbound-web/internal/fleet"
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
	a.Render(w, r, http.StatusOK, "diff", PageData{Title: "Record Diff", Data: data})
}

// handleDiffTable re-renders the table, which is what the filter and every
// repair swap back into the page.
func (a *App) handleDiffTable(w http.ResponseWriter, r *http.Request) {
	data, err := a.diffPageData(r)
	if err != nil {
		a.dnsError(w, "cannot compare the servers", err)
		return
	}
	a.RenderPartial(w, http.StatusOK, "diff-table", data)
}

func (a *App) diffPageData(r *http.Request) (diffPageData, error) {
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

	diff, err := a.records.Diff(r.Context(), query, only)
	if err != nil {
		return diffPageData{}, err
	}

	groups, err := a.servers.ListGroups(r.Context())
	if err != nil {
		return diffPageData{}, err
	}
	servers, err := a.servers.List(r.Context())
	if err != nil {
		return diffPageData{}, err
	}

	return diffPageData{
		Diff:           diff,
		Query:          query,
		Groups:         groups,
		Servers:        servers,
		OnlyMismatches: only,
		Summary:        diffSummary(diff),
		StaleNote:      diffStaleNote(diff),
		Columns:        len(diff.Servers) + 4,
	}, nil
}

// diffSummary says how much of the target disagrees.
func diffSummary(diff fleet.Diff) string {
	switch {
	case len(diff.Servers) < 2:
		return "Choose a group to compare its servers."
	case len(diff.Rows) == 0 && diff.OnlyMismatches:
		return "The servers hold the same records."
	case len(diff.Rows) == 0:
		return "There is nothing cached for these servers yet."
	case diff.OnlyMismatches:
		return plural(len(diff.Rows), "record") + " differ across " +
			plural(len(diff.Servers), "server") + "."
	default:
		return plural(diff.Mismatches(), "record") + " of " +
			plural(len(diff.Rows), "record") + " differ across " +
			plural(len(diff.Servers), "server") + "."
	}
}

// plural writes a count with its noun, so a summary reads as a sentence
// rather than as a number with an s bolted on.
func plural(count int, noun string) string {
	if count == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(count) + " " + noun + "s"
}

// diffStaleNote warns that a difference may be read from an old cache.
func diffStaleNote(diff fleet.Diff) string {
	stale := diff.Stale()
	if len(stale) == 0 {
		return ""
	}
	return "The panel has not read " + strings.Join(stale, ", ") +
		" recently, so a difference shown for it may already be gone."
}

// handleDiffRepair writes one record to every server that lacks it or holds a
// different value.
func (a *App) handleDiffRepair(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.reportProblem(w, "The form could not be read.", http.StatusBadRequest)
		return
	}

	target, err := targetFromValues(r.Form)
	if err != nil {
		a.reportProblem(w, recordMessage(err), http.StatusBadRequest)
		return
	}

	want := recordFromValues(r.Form)
	if want.Type == dnsfile.TypeMX && want.Priority == 0 {
		want.Priority = dnsfile.DefaultMXPriority
	}

	report, err := a.records.Repair(r.Context(), a.actor(r), target, want)
	if err != nil {
		a.reportProblem(w, recordMessage(err), dnsStatus(err))
		return
	}

	a.renderReport(w, report, repairReport)
}

var repairReport = reportKind{
	Title:   "Repair",
	OK:      "Every server now holds the record.",
	Partial: "Some servers took the record and others did not. The ones that failed still differ.",
	None:    "No server took the record.",

	ToastOK:      "The servers agree about the record now.",
	ToastPartial: "Some servers still differ.",
	ToastNone:    "The repair reached no server.",
}
