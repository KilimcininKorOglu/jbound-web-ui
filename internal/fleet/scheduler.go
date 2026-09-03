package fleet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"jbound/internal/audit"
	"jbound/internal/dnsfile"
	"jbound/internal/schedule"
	"jbound/internal/server"
)

// ScheduleStore is the persistence the scheduler reads and closes jobs through.
type ScheduleStore interface {
	Due(ctx context.Context, now time.Time) ([]schedule.Job, error)
	Claim(ctx context.Context, id int64) (bool, error)
	Finish(ctx context.Context, id int64, status, result string, ranAt time.Time) error
	ResetRunning(ctx context.Context) error
}

// Applier runs one record change across a target. fleet.Service satisfies it,
// so a scheduled write follows the same path as an immediate one.
type Applier interface {
	Apply(ctx context.Context, actor server.Actor, target Target, op Operation) (Report, error)
}

// Scheduler runs the DNS changes an operator left for a later time.
//
// It owns no write path of its own. Each due job is unmarshalled back into the
// operation the web layer built and handed to Apply, which reads the files,
// checks the config and refreshes the cache exactly as a live request does.
type Scheduler struct {
	store ScheduleStore
	apply Applier
	audit *audit.Logger
	now   func() time.Time
}

// NewScheduler builds the scheduler.
func NewScheduler(store ScheduleStore, apply Applier, auditLog *audit.Logger) *Scheduler {
	return &Scheduler{store: store, apply: apply, audit: auditLog, now: time.Now}
}

// Start runs due jobs on a timer until the context is cancelled.
//
// The first pass runs straight away, so a job whose time passed while the panel
// was down runs as soon as the panel is up rather than waiting for the
// interval. A timer rather than a ticker, because the interval is read again
// before every wait.
func (s *Scheduler) Start(ctx context.Context, interval func() time.Duration) {
	go func() {
		// A job left running is one a crash interrupted mid-apply, because the
		// panel is one process. Return those to pending before the first pass so
		// the missed-work catch-up runs them again.
		if err := s.store.ResetRunning(ctx); err != nil {
			slog.Error("cannot reset running scheduled jobs", "error", err)
		}

		s.runDue(ctx)

		timer := time.NewTimer(interval())
		defer timer.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				s.runDue(ctx)
				timer.Reset(interval())
			}
		}
	}()
}

// runDue applies every job whose time has come, oldest first.
func (s *Scheduler) runDue(ctx context.Context) {
	jobs, err := s.store.Due(ctx, s.now())
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			slog.Error("cannot read the due scheduled jobs", "error", err)
		}
		return
	}

	for _, job := range jobs {
		if ctx.Err() != nil {
			return
		}
		s.run(ctx, job)
	}
}

// run applies one job and records its outcome.
//
// It claims the job first, so a cancel or an edit that raced the timer wins or
// loses cleanly: a claimed job can no longer be cancelled or edited, and a job
// already moved off pending is not run.
func (s *Scheduler) run(ctx context.Context, job schedule.Job) {
	claimed, err := s.store.Claim(ctx, job.ID)
	if err != nil {
		slog.Error("cannot claim a scheduled job", "job", job.ID, "error", err)
		return
	}
	if !claimed {
		return
	}

	var op Operation
	if err := json.Unmarshal(job.Operation, &op); err != nil {
		s.finish(ctx, job, schedule.StatusFailed, "the stored operation could not be read")
		return
	}

	target := Target{Scope: job.Scope, ServerID: job.ServerID, GroupID: job.GroupID}
	actor := server.Actor{UID: job.RequestedUID, Username: job.RequestedUsername}

	report, err := s.applyJob(ctx, actor, target, op, job.OnConflict)
	status, summary := outcome(report, err)
	s.finish(ctx, job, status, summary)
}

// applyJob runs the operation, turning an addition into a set when the job asks
// to overwrite a name that already answers.
//
// A single add becomes one set. A batch becomes one set per record, because a
// set carries one name and its reports are folded back into one row per server.
// An edit or a deletion ignores the flag, since neither adds a name.
func (s *Scheduler) applyJob(ctx context.Context, actor server.Actor,
	target Target, op Operation, onConflict string) (Report, error) {

	if onConflict != schedule.OnConflictOverwrite {
		return s.apply.Apply(ctx, actor, target, op)
	}

	switch op.Kind {
	case OpAdd:
		op.Kind = OpSet
		return s.apply.Apply(ctx, actor, target, op)
	case OpAddMany:
		return s.overwriteEach(ctx, actor, target, op.Records)
	default:
		return s.apply.Apply(ctx, actor, target, op)
	}
}

// overwriteEach sets every record of a batch and folds the reports into one.
func (s *Scheduler) overwriteEach(ctx context.Context, actor server.Actor,
	target Target, records []dnsfile.Record) (Report, error) {

	var reports []Report
	for _, record := range records {
		report, err := s.apply.Apply(ctx, actor, target, Operation{Kind: OpSet, Record: record})
		if err != nil {
			return Report{}, err
		}
		reports = append(reports, report)
	}
	return mergeReports(reports), nil
}

// finish stores the outcome and writes the run to the audit trail.
func (s *Scheduler) finish(ctx context.Context, job schedule.Job, status, summary string) {
	if err := s.store.Finish(ctx, job.ID, status, summary, s.now()); err != nil {
		slog.Error("cannot record a scheduled job outcome",
			"job", job.ID, "status", status, "error", err)
	}

	entry := audit.Entry{
		UID:       job.RequestedUID,
		Username:  job.RequestedUsername,
		Action:    audit.ActionScheduleRun,
		Details:   fmt.Sprintf("Scheduled job #%d (%s): %s", job.ID, job.Kind, summary),
		IPAddress: scheduledSource,
	}
	if err := s.audit.Write(ctx, entry); err != nil {
		slog.Error("cannot audit a scheduled job run", "job", job.ID, "error", err)
	}
}

// scheduledSource names where a scheduled change came from, in place of the
// address a live request would carry. The operator scheduled it earlier; the
// address they used then is not where the change is applied from.
const scheduledSource = "scheduler"

// outcome turns a report into a stored status and a one line English summary.
//
// A job that reached no server, or whose every server failed, is failed.
// A job with at least one success is done, even when a server was unreachable,
// because the job did run and the summary carries what happened to each server.
func outcome(report Report, err error) (string, string) {
	if err != nil {
		return schedule.StatusFailed, failureMessage(err)
	}

	success, failed, skipped := report.Counts()
	summary := fmt.Sprintf("%d succeeded, %d failed, %d skipped", success, failed, skipped)
	if success == 0 && failed > 0 {
		return schedule.StatusFailed, summary
	}
	return schedule.StatusDone, summary
}

// severity ranks a per-server status so the worst of several set reports wins
// when they are folded together.
func severity(status string) int {
	switch status {
	case StatusFailed:
		return 2
	case StatusSkipped:
		return 1
	default:
		return 0
	}
}

// mergeReports folds several set reports into one outcome per server. A server
// that failed any record is failed; otherwise its best result stands.
func mergeReports(reports []Report) Report {
	var order []int64
	worst := map[int64]ServerResult{}
	var groupName string

	for _, report := range reports {
		if report.GroupName != "" {
			groupName = report.GroupName
		}
		for _, result := range report.Results {
			previous, seen := worst[result.ServerID]
			if !seen {
				order = append(order, result.ServerID)
				worst[result.ServerID] = result
				continue
			}
			if severity(result.Status) > severity(previous.Status) {
				worst[result.ServerID] = result
			}
		}
	}

	merged := Report{GroupName: groupName}
	for _, id := range order {
		merged.Results = append(merged.Results, worst[id])
	}
	return merged
}
