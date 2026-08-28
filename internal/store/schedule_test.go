package store_test

import (
	"context"
	"testing"
	"time"

	"jbound/internal/schedule"
	"jbound/internal/server"
	"jbound/internal/store"
)

// sampleJob is a pending server scoped addition due at a fixed time.
func sampleJob(serverID int64, runAt time.Time) schedule.Job {
	return schedule.Job{
		Kind:              schedule.KindAdd,
		Operation:         []byte(`{"Kind":"add","Record":{"FQDN":"www.example.local","Type":"A","Value":"10.0.0.1"}}`),
		Scope:             "server",
		ServerID:          serverID,
		OnConflict:        schedule.OnConflictFail,
		RunAt:             runAt,
		RequestedUID:      1001,
		RequestedUsername: "dnsadmin",
	}
}

func TestAScheduledJobRoundTrips(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	jobs := store.NewSchedule(f.db)
	record := f.mustCreate(t, "dns1")

	runAt := time.Date(2026, 9, 1, 3, 30, 0, 0, time.UTC)
	created, err := jobs.Create(ctx, sampleJob(record.ID, runAt))
	if err != nil {
		t.Fatalf("cannot create the job: %v", err)
	}

	got, err := jobs.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("cannot read the job: %v", err)
	}
	if got.Kind != schedule.KindAdd || got.Scope != "server" || got.ServerID != record.ID {
		t.Errorf("the job did not round trip: %+v", got)
	}
	if string(got.Operation) != string(sampleJob(record.ID, runAt).Operation) {
		t.Errorf("operation = %q, want it stored verbatim", got.Operation)
	}
	if !got.RunAt.Equal(runAt) {
		t.Errorf("run_at = %v, want %v", got.RunAt, runAt)
	}
	if got.Status != schedule.StatusPending {
		t.Errorf("status = %q, want pending", got.Status)
	}
	if got.RequestedUID != 1001 || got.RequestedUsername != "dnsadmin" {
		t.Errorf("requester = %d/%q, want the account that scheduled it",
			got.RequestedUID, got.RequestedUsername)
	}
	if !got.RanAt.IsZero() {
		t.Errorf("ran_at = %v, want zero on a job that has not run", got.RanAt)
	}
}

func TestOnlyPendingJobsPastTheirTimeAreDue(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	jobs := store.NewSchedule(f.db)
	record := f.mustCreate(t, "dns1")

	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	duePast, err := jobs.Create(ctx, sampleJob(record.ID, past))
	if err != nil {
		t.Fatalf("cannot create the past job: %v", err)
	}
	if _, err := jobs.Create(ctx, sampleJob(record.ID, future)); err != nil {
		t.Fatalf("cannot create the future job: %v", err)
	}

	due, err := jobs.Due(ctx, now)
	if err != nil {
		t.Fatalf("cannot read the due jobs: %v", err)
	}
	if len(due) != 1 || due[0].ID != duePast.ID {
		t.Fatalf("due = %+v, want only the past job", due)
	}

	// A job that has run is no longer due, even though its time has passed.
	if err := jobs.Finish(ctx, duePast.ID, schedule.StatusDone, "1 server updated", now); err != nil {
		t.Fatalf("cannot finish the job: %v", err)
	}
	due, err = jobs.Due(ctx, now)
	if err != nil {
		t.Fatalf("cannot read the due jobs again: %v", err)
	}
	if len(due) != 0 {
		t.Errorf("due = %+v, want none after the job finished", due)
	}
}

func TestFinishRecordsTheOutcomeOnce(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	jobs := store.NewSchedule(f.db)
	record := f.mustCreate(t, "dns1")

	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	created, err := jobs.Create(ctx, sampleJob(record.ID, now))
	if err != nil {
		t.Fatalf("cannot create the job: %v", err)
	}

	if err := jobs.Finish(ctx, created.ID, schedule.StatusFailed, "connection refused", now); err != nil {
		t.Fatalf("cannot finish the job: %v", err)
	}

	got, err := jobs.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("cannot read the job: %v", err)
	}
	if got.Status != schedule.StatusFailed || got.Result != "connection refused" {
		t.Errorf("outcome not recorded: %+v", got)
	}
	if !got.RanAt.Equal(now) {
		t.Errorf("ran_at = %v, want %v", got.RanAt, now)
	}

	// Finishing a closed job changes nothing, because the guard matches only a
	// pending row.
	if err := jobs.Finish(ctx, created.ID, schedule.StatusDone, "second", now); err == nil {
		t.Error("a finished job was finished a second time")
	}
}

func TestCancellingAScheduledJobRemovesIt(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	jobs := store.NewSchedule(f.db)
	record := f.mustCreate(t, "dns1")

	created, err := jobs.Create(ctx, sampleJob(record.ID, time.Now().UTC()))
	if err != nil {
		t.Fatalf("cannot create the job: %v", err)
	}
	if err := jobs.Delete(ctx, created.ID); err != nil {
		t.Fatalf("cannot delete the job: %v", err)
	}
	if _, err := jobs.Get(ctx, created.ID); err == nil {
		t.Error("the deleted job still answers")
	}
	if err := jobs.Delete(ctx, created.ID); err == nil {
		t.Error("deleting a job that is gone was accepted")
	}
}

func TestDeletingTheTargetTakesItsJobs(t *testing.T) {
	// A job with no target has nowhere to run, so the foreign key removes it
	// with the server it points at.
	f := newFixture(t)
	ctx := context.Background()
	jobs := store.NewSchedule(f.db)

	group, err := f.groups.Create(ctx, server.Group{Name: "resolvers"})
	if err != nil {
		t.Fatalf("cannot create the group: %v", err)
	}
	member := f.mustCreateIn(t, "dns1", group.ID)

	onServer, err := jobs.Create(ctx, sampleJob(member.ID, time.Now().UTC()))
	if err != nil {
		t.Fatalf("cannot create the server job: %v", err)
	}

	groupJob := sampleJob(0, time.Now().UTC())
	groupJob.Scope = "group"
	groupJob.GroupID = group.ID
	onGroup, err := jobs.Create(ctx, groupJob)
	if err != nil {
		t.Fatalf("cannot create the group job: %v", err)
	}

	if err := f.servers.Delete(ctx, member.ID); err != nil {
		t.Fatalf("cannot delete the server: %v", err)
	}
	if _, err := jobs.Get(ctx, onServer.ID); err == nil {
		t.Error("the server job outlived its server")
	}

	if err := f.groups.Delete(ctx, group.ID); err != nil {
		t.Fatalf("cannot delete the group: %v", err)
	}
	if _, err := jobs.Get(ctx, onGroup.ID); err == nil {
		t.Error("the group job outlived its group")
	}
}
