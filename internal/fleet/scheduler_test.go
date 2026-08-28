package fleet

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"jbound/internal/audit"
	"jbound/internal/dnsfile"
	"jbound/internal/schedule"
	"jbound/internal/server"
)

// applyCall records one call to the fake applier.
type applyCall struct {
	actor  server.Actor
	target Target
	op     Operation
}

// fakeApplier records the operations it is handed and answers with a fixed
// report, so a test can watch what the scheduler builds without a fleet.
type fakeApplier struct {
	calls  []applyCall
	report Report
	err    error
}

func (f *fakeApplier) Apply(_ context.Context, actor server.Actor,
	target Target, op Operation) (Report, error) {
	f.calls = append(f.calls, applyCall{actor: actor, target: target, op: op})
	return f.report, f.err
}

// finishCall records one call to Finish.
type finishCall struct {
	id     int64
	status string
	result string
}

// fakeStore hands out a fixed set of due jobs and records how they finished.
type fakeStore struct {
	due      []schedule.Job
	finished []finishCall
}

func (f *fakeStore) Due(context.Context, time.Time) ([]schedule.Job, error) {
	return f.due, nil
}

func (f *fakeStore) Finish(_ context.Context, id int64, status, result string, _ time.Time) error {
	f.finished = append(f.finished, finishCall{id: id, status: status, result: result})
	return nil
}

// silentAudit accepts every entry and keeps none, so a test needs no database.
type silentAudit struct{}

func (silentAudit) Write(context.Context, audit.Entry, time.Time) error { return nil }
func (silentAudit) List(context.Context, audit.Query) (audit.Page, error) {
	return audit.Page{}, nil
}

// jobFor builds a pending job carrying op as its stored operation.
func jobFor(t *testing.T, kind, onConflict string, op Operation) schedule.Job {
	t.Helper()
	raw, err := json.Marshal(op)
	if err != nil {
		t.Fatalf("cannot marshal the operation: %v", err)
	}
	return schedule.Job{
		ID:                7,
		Kind:              kind,
		Operation:         raw,
		Scope:             ScopeServer,
		ServerID:          3,
		OnConflict:        onConflict,
		RunAt:             time.Now().UTC(),
		RequestedUID:      1001,
		RequestedUsername: "dnsadmin",
	}
}

func addOp() Operation {
	return Operation{Kind: OpAdd, Record: dnsfile.Record{
		FQDN: "www.example.local", Type: "A", Value: "10.0.0.1"}}
}

func newScheduler(store *fakeStore, applier *fakeApplier) *Scheduler {
	return NewScheduler(store, applier, audit.NewLogger(silentAudit{}))
}

func okReport(names ...string) Report {
	report := Report{}
	for i, name := range names {
		report.Results = append(report.Results, ServerResult{
			ServerID: int64(i + 1), ServerName: name, Status: StatusSuccess})
	}
	return report
}

func TestADueJobRunsAndIsMarkedDone(t *testing.T) {
	store := &fakeStore{due: []schedule.Job{jobFor(t, schedule.KindAdd, schedule.OnConflictFail, addOp())}}
	applier := &fakeApplier{report: okReport("dns1")}

	newScheduler(store, applier).runDue(context.Background())

	if len(applier.calls) != 1 {
		t.Fatalf("applier was called %d times, want 1", len(applier.calls))
	}
	if applier.calls[0].op.Kind != OpAdd {
		t.Errorf("op kind = %q, want add without the overwrite flag", applier.calls[0].op.Kind)
	}
	if applier.calls[0].actor.UID != 1001 || applier.calls[0].actor.Username != "dnsadmin" {
		t.Errorf("actor = %+v, want the account that scheduled the job", applier.calls[0].actor)
	}
	if len(store.finished) != 1 || store.finished[0].status != schedule.StatusDone {
		t.Errorf("finished = %+v, want one done", store.finished)
	}
}

func TestAnApplyErrorFailsTheJob(t *testing.T) {
	store := &fakeStore{due: []schedule.Job{jobFor(t, schedule.KindAdd, schedule.OnConflictFail, addOp())}}
	applier := &fakeApplier{err: context.DeadlineExceeded}

	newScheduler(store, applier).runDue(context.Background())

	if len(store.finished) != 1 || store.finished[0].status != schedule.StatusFailed {
		t.Errorf("finished = %+v, want one failed", store.finished)
	}
}

func TestEveryServerFailingFailsTheJob(t *testing.T) {
	store := &fakeStore{due: []schedule.Job{jobFor(t, schedule.KindAdd, schedule.OnConflictFail, addOp())}}
	report := Report{Results: []ServerResult{
		{ServerID: 1, Status: StatusFailed}, {ServerID: 2, Status: StatusFailed}}}
	applier := &fakeApplier{report: report}

	newScheduler(store, applier).runDue(context.Background())

	if store.finished[0].status != schedule.StatusFailed {
		t.Errorf("status = %q, want failed when no server succeeded", store.finished[0].status)
	}
}

func TestPartialSuccessIsDone(t *testing.T) {
	// The job did run. One server was unreachable, which the summary carries,
	// but a run with a success is not a failed job.
	store := &fakeStore{due: []schedule.Job{jobFor(t, schedule.KindAdd, schedule.OnConflictFail, addOp())}}
	report := Report{Results: []ServerResult{
		{ServerID: 1, Status: StatusSuccess}, {ServerID: 2, Status: StatusFailed}}}
	applier := &fakeApplier{report: report}

	newScheduler(store, applier).runDue(context.Background())

	if store.finished[0].status != schedule.StatusDone {
		t.Errorf("status = %q, want done on a partial success", store.finished[0].status)
	}
}

func TestOverwriteTurnsAdditionIntoSet(t *testing.T) {
	store := &fakeStore{due: []schedule.Job{jobFor(t, schedule.KindAdd, schedule.OnConflictOverwrite, addOp())}}
	applier := &fakeApplier{report: okReport("dns1")}

	newScheduler(store, applier).runDue(context.Background())

	if len(applier.calls) != 1 || applier.calls[0].op.Kind != OpSet {
		t.Errorf("overwrite did not turn the addition into a set: %+v", applier.calls)
	}
}

func TestOverwriteBatchSetsEachRecord(t *testing.T) {
	batch := Operation{Kind: OpAddMany, Records: []dnsfile.Record{
		{FQDN: "a.example.local", Type: "A", Value: "10.0.0.1"},
		{FQDN: "b.example.local", Type: "A", Value: "10.0.0.2"}}}
	store := &fakeStore{due: []schedule.Job{jobFor(t, schedule.KindAdd, schedule.OnConflictOverwrite, batch)}}
	applier := &fakeApplier{report: okReport("dns1")}

	newScheduler(store, applier).runDue(context.Background())

	if len(applier.calls) != 2 {
		t.Fatalf("applier was called %d times, want one set per record", len(applier.calls))
	}
	for i, call := range applier.calls {
		if call.op.Kind != OpSet {
			t.Errorf("call %d kind = %q, want set", i, call.op.Kind)
		}
	}
	if store.finished[0].status != schedule.StatusDone {
		t.Errorf("status = %q, want done", store.finished[0].status)
	}
}

func TestAStoredOperationThatCannotBeReadFailsWithoutApply(t *testing.T) {
	job := jobFor(t, schedule.KindAdd, schedule.OnConflictFail, addOp())
	job.Operation = []byte("{ not json")
	store := &fakeStore{due: []schedule.Job{job}}
	applier := &fakeApplier{}

	newScheduler(store, applier).runDue(context.Background())

	if len(applier.calls) != 0 {
		t.Errorf("a job that could not be read still reached a server: %+v", applier.calls)
	}
	if store.finished[0].status != schedule.StatusFailed {
		t.Errorf("status = %q, want failed", store.finished[0].status)
	}
}
