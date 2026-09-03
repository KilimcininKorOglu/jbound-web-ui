package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"jbound/internal/dnsfile"
	"jbound/internal/fleet"
	"jbound/internal/schedule"
	"jbound/internal/store"
)

// --- Pure helpers ----------------------------------------------------------

func TestOperationFromFormBuildsEachKind(t *testing.T) {
	single := url.Values{"fqdn": {"www.example.local"}, "type": {"A"}, "value": {"10.0.0.1"}}
	op, err := operationFromForm(single, schedule.KindAdd)
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if op.Kind != fleet.OpAdd || op.Record.FQDN != "www.example.local" {
		t.Errorf("add built %+v", op)
	}

	many := url.Values{
		"fqdn":  {"a.example.local", "b.example.local"},
		"type":  {"A", "A"},
		"value": {"10.0.0.1", "10.0.0.2"},
	}
	op, err = operationFromForm(many, schedule.KindAdd)
	if err != nil {
		t.Fatalf("add many: %v", err)
	}
	if op.Kind != fleet.OpAddMany || len(op.Records) != 2 {
		t.Errorf("add many built %+v", op)
	}

	edit := url.Values{
		"old_fqdn": {"www.example.local"}, "old_type": {"A"}, "old_value": {"10.0.0.1"},
		"value": {"10.0.0.2"},
	}
	op, err = operationFromForm(edit, schedule.KindEdit)
	if err != nil {
		t.Fatalf("edit: %v", err)
	}
	// The name and the type come from the old record, and only the value changes.
	if op.Kind != fleet.OpEdit || op.Record.FQDN != "www.example.local" ||
		op.Record.Type != "A" || op.Record.Value != "10.0.0.2" || op.Old.Value != "10.0.0.1" {
		t.Errorf("edit built %+v", op)
	}

	del := url.Values{"fqdn": {"gone.example.local"}, "type": {"A"}}
	op, err = operationFromForm(del, schedule.KindDelete)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if op.Kind != fleet.OpDelete || op.Record.FQDN != "gone.example.local" {
		t.Errorf("delete built %+v", op)
	}

	if _, err := operationFromForm(url.Values{}, "sideways"); err == nil {
		t.Error("an unknown kind was accepted")
	}
}

func TestOnConflictFromOnlyOffersOverwriteToAdditions(t *testing.T) {
	add := fleet.Operation{Kind: fleet.OpAdd}
	if got := onConflictFrom(url.Values{"on_conflict": {"1"}}, add); got != schedule.OnConflictOverwrite {
		t.Errorf("add with the box ticked = %q, want overwrite", got)
	}
	if got := onConflictFrom(url.Values{}, add); got != schedule.OnConflictFail {
		t.Errorf("add with no box = %q, want fail", got)
	}

	// An edit or a delete has no name to overwrite, so the box is ignored.
	edit := fleet.Operation{Kind: fleet.OpEdit}
	if got := onConflictFrom(url.Values{"on_conflict": {"1"}}, edit); got != schedule.OnConflictFail {
		t.Errorf("edit with the box ticked = %q, want fail", got)
	}
}

func TestParseRunAtReadsLocalAndRefusesThePast(t *testing.T) {
	if _, err := parseRunAt(""); !errors.Is(err, errRunAtMissing) {
		t.Errorf("empty = %v, want missing", err)
	}
	if _, err := parseRunAt("not-a-time"); !errors.Is(err, errRunAtInvalid) {
		t.Errorf("garbage = %v, want invalid", err)
	}
	past := time.Now().Add(-time.Hour).Format(runAtLayout)
	if _, err := parseRunAt(past); !errors.Is(err, errRunAtPast) {
		t.Errorf("past = %v, want past", err)
	}

	future := time.Now().Add(48 * time.Hour).Format(runAtLayout)
	got, err := parseRunAt(future)
	if err != nil {
		t.Fatalf("future: %v", err)
	}
	if got.Location() != time.UTC {
		t.Errorf("stored zone = %v, want UTC", got.Location())
	}
}

func TestScheduleFormFromJobRoundTripsTheOverwriteChoice(t *testing.T) {
	op := fleet.Operation{Kind: fleet.OpAdd,
		Record: dnsfile.Record{FQDN: "www.example.local", Type: "A", Value: "10.0.0.1"}}
	raw, err := json.Marshal(op)
	if err != nil {
		t.Fatalf("cannot marshal the operation: %v", err)
	}

	overwrite := schedule.Job{Kind: schedule.KindAdd, Operation: raw,
		Scope: "server", ServerID: 1, OnConflict: schedule.OnConflictOverwrite}
	data, err := scheduleFormFromJob(overwrite, nil, nil)
	if err != nil {
		t.Fatalf("overwrite job: %v", err)
	}
	if !data.Overwrite {
		t.Error("an overwrite job did not re-render the box ticked")
	}

	fail := overwrite
	fail.OnConflict = schedule.OnConflictFail
	data, err = scheduleFormFromJob(fail, nil, nil)
	if err != nil {
		t.Fatalf("fail job: %v", err)
	}
	if data.Overwrite {
		t.Error("a fail job re-rendered the box ticked")
	}
}

func TestScheduleSummaryRendersTheStoredChange(t *testing.T) {
	op := fleet.Operation{Kind: fleet.OpAddMany, Records: []dnsfile.Record{
		{FQDN: "www.example.local", Type: "A", Value: "10.0.0.1"},
		{FQDN: "mail.example.local", Type: "A", Value: "10.0.0.2"},
	}}
	raw, err := json.Marshal(op)
	if err != nil {
		t.Fatalf("cannot marshal the operation: %v", err)
	}

	got := scheduleSummary(schedule.Job{Operation: raw})
	if got != "www.example.local A 10.0.0.1 (+1)" {
		t.Errorf("summary = %q", got)
	}
}

// --- Handler flow ----------------------------------------------------------

// wireSchedules gives the application the real schedule store over the test
// database, because newTestEnv builds an application without one.
func (e *testEnv) wireSchedules(t *testing.T) *store.Schedule {
	t.Helper()
	jobs := store.NewSchedule(e.db)
	e.app.Schedules = jobs
	return jobs
}

// futureRunAt is a run time the form accepts, in the layout a datetime-local
// field posts.
func futureRunAt() string {
	return time.Now().Add(48 * time.Hour).Format(runAtLayout)
}

func TestSchedulingAnAdditionStoresItAndListsIt(t *testing.T) {
	env := newTestEnv(t)
	jobs := env.wireSchedules(t)
	cookie := env.login(t, "dnsadmin")
	if code := env.addServer(t, cookie, "dns1").Code; code != http.StatusOK {
		t.Fatalf("cannot create the target server: %d", code)
	}

	recorder := env.adminForm(t, http.MethodPost, "/scheduled", cookie, url.Values{
		"kind":        {schedule.KindAdd},
		"fqdn":        {"www.example.local"},
		"type":        {"A"},
		"value":       {"10.0.0.1"},
		"scope":       {fleet.ScopeServer},
		"server_id":   {"1"},
		"run_at":      {futureRunAt()},
		"on_conflict": {"1"},
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("POST /scheduled = %d\n%s", recorder.Code, recorder.Body)
	}

	stored, err := jobs.List(context.Background())
	if err != nil {
		t.Fatalf("cannot list the jobs: %v", err)
	}
	if len(stored) != 1 {
		t.Fatalf("%d jobs stored, want 1", len(stored))
	}
	if stored[0].OnConflict != schedule.OnConflictOverwrite {
		t.Errorf("on_conflict = %q, want overwrite", stored[0].OnConflict)
	}

	table := env.do(t, httptest.NewRequest(http.MethodGet, "/scheduled/table", nil), cookie)
	if !strings.Contains(table.Body.String(), "www.example.local") {
		t.Errorf("the table does not show the scheduled change:\n%s", table.Body)
	}
}

func TestEditingAScheduledAdditionKeepsItsOverwriteTicked(t *testing.T) {
	env := newTestEnv(t)
	jobs := env.wireSchedules(t)
	cookie := env.login(t, "dnsadmin")
	if code := env.addServer(t, cookie, "dns1").Code; code != http.StatusOK {
		t.Fatalf("cannot create the target server: %d", code)
	}

	if code := env.adminForm(t, http.MethodPost, "/scheduled", cookie, url.Values{
		"kind":        {schedule.KindAdd},
		"fqdn":        {"www.example.local"},
		"type":        {"A"},
		"value":       {"10.0.0.1"},
		"scope":       {fleet.ScopeServer},
		"server_id":   {"1"},
		"run_at":      {futureRunAt()},
		"on_conflict": {"1"},
	}).Code; code != http.StatusOK {
		t.Fatalf("POST /scheduled = %d", code)
	}

	stored, err := jobs.List(context.Background())
	if err != nil || len(stored) != 1 {
		t.Fatalf("jobs = %+v, err = %v", stored, err)
	}

	recorder := env.do(t, httptest.NewRequest(http.MethodGet,
		"/scheduled/"+strconv.FormatInt(stored[0].ID, 10)+"/edit", nil), cookie)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET edit = %d", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), `name="on_conflict" value="1" checked`) {
		t.Errorf("the edit form did not re-render the overwrite box ticked:\n%s", recorder.Body)
	}
}

func TestCancellingAScheduledJobRemovesIt(t *testing.T) {
	env := newTestEnv(t)
	jobs := env.wireSchedules(t)
	cookie := env.login(t, "dnsadmin")
	if code := env.addServer(t, cookie, "dns1").Code; code != http.StatusOK {
		t.Fatalf("cannot create the target server: %d", code)
	}

	if code := env.adminForm(t, http.MethodPost, "/scheduled", cookie, url.Values{
		"kind":      {schedule.KindAdd},
		"fqdn":      {"www.example.local"},
		"type":      {"A"},
		"value":     {"10.0.0.1"},
		"scope":     {fleet.ScopeServer},
		"server_id": {"1"},
		"run_at":    {futureRunAt()},
	}).Code; code != http.StatusOK {
		t.Fatalf("POST /scheduled = %d", code)
	}

	stored, _ := jobs.List(context.Background())
	if len(stored) != 1 {
		t.Fatalf("%d jobs stored, want 1", len(stored))
	}

	recorder := env.adminForm(t, http.MethodDelete,
		"/scheduled/"+strconv.FormatInt(stored[0].ID, 10), cookie, url.Values{})
	if recorder.Code != http.StatusOK {
		t.Fatalf("DELETE = %d", recorder.Code)
	}

	after, _ := jobs.List(context.Background())
	if len(after) != 0 {
		t.Errorf("%d jobs left after the cancel, want none", len(after))
	}
}

func TestSchedulingARunTimeInThePastIsRefused(t *testing.T) {
	env := newTestEnv(t)
	env.wireSchedules(t)
	cookie := env.login(t, "dnsadmin")

	recorder := env.adminForm(t, http.MethodPost, "/scheduled", cookie, url.Values{
		"kind":      {schedule.KindAdd},
		"fqdn":      {"www.example.local"},
		"type":      {"A"},
		"value":     {"10.0.0.1"},
		"scope":     {fleet.ScopeServer},
		"server_id": {"1"},
		"run_at":    {time.Now().Add(-time.Hour).Format(runAtLayout)},
	})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("POST with a past run time = %d, want 400", recorder.Code)
	}
}
