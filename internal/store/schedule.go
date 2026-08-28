package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"jbound/internal/schedule"
)

// Schedule stores the DNS changes an operator has left for a later time.
//
// The operation is kept as opaque JSON. This store neither builds it nor reads
// it, so the record format stays owned by the fleet layer and this file holds
// SQL only.
type Schedule struct {
	db *sql.DB
}

// NewSchedule builds the schedule store.
func NewSchedule(db *sql.DB) *Schedule { return &Schedule{db: db} }

// scheduleColumns names what a job row carries, so the readers below cannot
// drift apart.
const scheduleColumns = `id, kind, operation, scope, server_id, group_id, ` +
	`on_conflict, run_at, status, requested_uid, requested_username, ` +
	`result, created_at, ran_at`

// Create inserts a pending job and returns it as stored.
func (s *Schedule) Create(ctx context.Context, job schedule.Job) (schedule.Job, error) {
	result, err := s.db.ExecContext(ctx, `
INSERT INTO scheduled_jobs
    (kind, operation, scope, server_id, group_id, on_conflict, run_at,
     status, requested_uid, requested_username)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		job.Kind, string(job.Operation), job.Scope,
		nullableID(job.ServerID), nullableID(job.GroupID),
		job.OnConflict, formatTime(job.RunAt), schedule.StatusPending,
		job.RequestedUID, job.RequestedUsername)
	if err != nil {
		return schedule.Job{}, fmt.Errorf("cannot insert the scheduled job: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return schedule.Job{}, fmt.Errorf("cannot read the new job id: %w", err)
	}
	return s.Get(ctx, id)
}

// Get reads one job.
func (s *Schedule) Get(ctx context.Context, id int64) (schedule.Job, error) {
	row := s.db.QueryRowContext(ctx,
		"SELECT "+scheduleColumns+" FROM scheduled_jobs WHERE id = ?", id)

	job, err := scanJob(row)
	if errors.Is(err, sql.ErrNoRows) {
		return schedule.Job{}, fmt.Errorf("scheduled job %d: %w", id, ErrNotFound)
	}
	if err != nil {
		return schedule.Job{}, fmt.Errorf("cannot read the scheduled job: %w", err)
	}
	return job, nil
}

// List returns every job, the ones due soonest and the most recent runs first.
func (s *Schedule) List(ctx context.Context) ([]schedule.Job, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT "+scheduleColumns+" FROM scheduled_jobs ORDER BY run_at DESC, id DESC")
	if err != nil {
		return nil, fmt.Errorf("cannot list the scheduled jobs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	return scanJobs(rows)
}

// Due returns the pending jobs whose time has come, oldest first.
func (s *Schedule) Due(ctx context.Context, now time.Time) ([]schedule.Job, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT "+scheduleColumns+" FROM scheduled_jobs "+
			"WHERE status = ? AND run_at <= ? ORDER BY run_at, id",
		schedule.StatusPending, formatTime(now))
	if err != nil {
		return nil, fmt.Errorf("cannot read the due jobs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	return scanJobs(rows)
}

// Delete removes a job. It is how an operator cancels one that has not run yet.
func (s *Schedule) Delete(ctx context.Context, id int64) error {
	result, err := s.db.ExecContext(ctx, "DELETE FROM scheduled_jobs WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("cannot delete the scheduled job: %w", err)
	}
	return requireOneRow(result, "scheduled job", fmt.Sprint(id))
}

// Finish records the outcome of a run and closes the job.
//
// It moves a job out of pending only, so a job that already ran is left as it
// stands rather than run and recorded twice.
func (s *Schedule) Finish(
	ctx context.Context, id int64, status, result string, ranAt time.Time,
) error {
	res, err := s.db.ExecContext(ctx, `
UPDATE scheduled_jobs
   SET status = ?, result = ?, ran_at = ?
 WHERE id = ? AND status = ?`,
		status, result, formatTime(ranAt), id, schedule.StatusPending)
	if err != nil {
		return fmt.Errorf("cannot finish the scheduled job: %w", err)
	}
	return requireOneRow(res, "scheduled job", fmt.Sprint(id))
}

// scanJobs reads every row of a query into jobs.
func scanJobs(rows *sql.Rows) ([]schedule.Job, error) {
	var jobs []schedule.Job
	for rows.Next() {
		job, err := scanJob(rows)
		if err != nil {
			return nil, fmt.Errorf("cannot read a scheduled job row: %w", err)
		}
		jobs = append(jobs, job)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cannot read the scheduled job rows: %w", err)
	}
	return jobs, nil
}

// scanJob reads one job row from a query or a single row.
func scanJob(row scanner) (schedule.Job, error) {
	var (
		job       schedule.Job
		operation string
		serverID  sql.NullInt64
		groupID   sql.NullInt64
		runAt     string
		created   string
		ranAt     sql.NullString
	)

	if err := row.Scan(&job.ID, &job.Kind, &operation, &job.Scope,
		&serverID, &groupID, &job.OnConflict, &runAt, &job.Status,
		&job.RequestedUID, &job.RequestedUsername, &job.Result,
		&created, &ranAt); err != nil {
		return schedule.Job{}, err
	}

	job.Operation = []byte(operation)
	job.ServerID = serverID.Int64
	job.GroupID = groupID.Int64

	var err error
	if job.RunAt, err = parseTime(runAt); err != nil {
		return schedule.Job{}, err
	}
	if job.CreatedAt, err = parseTime(created); err != nil {
		return schedule.Job{}, err
	}
	if ranAt.Valid {
		if job.RanAt, err = parseTime(ranAt.String); err != nil {
			return schedule.Job{}, err
		}
	}
	return job, nil
}
