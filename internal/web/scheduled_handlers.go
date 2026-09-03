package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"jbound/internal/audit"
	"jbound/internal/dnsfile"
	"jbound/internal/fleet"
	"jbound/internal/logging"
	"jbound/internal/schedule"
	"jbound/internal/server"
)

// ScheduleStore is the persistence the scheduled pages read and write.
type ScheduleStore interface {
	List(ctx context.Context) ([]schedule.Job, error)
	Create(ctx context.Context, job schedule.Job) (schedule.Job, error)
	Get(ctx context.Context, id int64) (schedule.Job, error)
	Update(ctx context.Context, job schedule.Job) error
	Delete(ctx context.Context, id int64) error
}

// scheduledPageData feeds the scheduled page and its table fragment.
type scheduledPageData struct {
	Jobs []scheduleRow
}

// scheduleRow is one scheduled change as the table shows it.
//
// Kind and Status are the stored words, which the template turns into the
// reader's language. The operation is summarised to one line, because the table
// shows what will change rather than the whole record.
type scheduleRow struct {
	ID      int64
	Kind    string
	Summary string
	Target  string
	RunAt   time.Time
	Status  string
	Result  string

	// Pending marks a job that has not run, which is the only kind an operator
	// can still cancel.
	Pending bool
}

// scheduleFormData feeds the create form. One form serves the three kinds; the
// kind decides which fields it draws.
type scheduleFormData struct {
	// JobID is zero for a new job and the job's id when the form edits a pending
	// one. It decides whether the form posts or puts, and whether it reads as a
	// creation or an edit.
	JobID int64

	Kind    string
	Record  dnsfile.Record
	Old     dnsfile.Record
	Rows    []recordRow
	RunAt   string
	Query   fleet.Query
	Servers []server.Server
	Groups  []server.Group
	Types   []string
	Problem string
}

func (a *App) handleScheduledPage(w http.ResponseWriter, r *http.Request) {
	data, err := a.scheduledData(r)
	if err != nil {
		a.internalError(w, r, "cannot load the scheduled jobs", err)
		return
	}
	a.Render(w, r, http.StatusOK, "scheduled", PageData{Title: "nav.scheduled", Data: data})
}

// handleScheduledTable re-renders the table after a job is created or cancelled.
func (a *App) handleScheduledTable(w http.ResponseWriter, r *http.Request) {
	data, err := a.scheduledData(r)
	if err != nil {
		a.internalError(w, r, "cannot load the scheduled jobs", err)
		return
	}
	a.RenderPartial(w, r, http.StatusOK, "scheduled-table", data)
}

// handleScheduledForm renders the create form for one kind of change.
func (a *App) handleScheduledForm(w http.ResponseWriter, r *http.Request) {
	kind := formKind(r.URL.Query().Get("kind"))

	servers, groups, err := a.serversAndGroups(r.Context())
	if err != nil {
		a.internalError(w, r, "cannot load the targets", err)
		return
	}

	data := scheduleFormData{
		Kind:    kind,
		Types:   dnsfile.Types,
		Servers: servers,
		Groups:  groups,
	}
	data.Record.Priority = dnsfile.DefaultMXPriority
	data.Rows = []recordRow{{Record: data.Record, Types: dnsfile.Types}}

	a.RenderPartial(w, r, http.StatusOK, "scheduled-form", data)
}

// handleScheduledEdit loads a pending job back into its form.
func (a *App) handleScheduledEdit(w http.ResponseWriter, r *http.Request) {
	id := parseID(r.PathValue("id"))
	if id == 0 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	job, err := a.Schedules.Get(r.Context(), id)
	if err != nil {
		a.notFoundOrError(w, r, "cannot read the scheduled job", err)
		return
	}
	servers, groups, err := a.serversAndGroups(r.Context())
	if err != nil {
		a.internalError(w, r, "cannot load the targets", err)
		return
	}

	data, err := scheduleFormFromJob(job, servers, groups)
	if err != nil {
		a.notFoundOrError(w, r, "cannot read the scheduled job", err)
		return
	}
	a.RenderPartial(w, r, http.StatusOK, "scheduled-form", data)
}

// scheduleFormFromJob fills the form with the stored change so an operator
// edits it rather than typing it again.
func scheduleFormFromJob(job schedule.Job,
	servers []server.Server, groups []server.Group) (scheduleFormData, error) {

	var op fleet.Operation
	if err := json.Unmarshal(job.Operation, &op); err != nil {
		return scheduleFormData{}, err
	}

	data := scheduleFormData{
		JobID:   job.ID,
		Kind:    job.Kind,
		Types:   dnsfile.Types,
		Servers: servers,
		Groups:  groups,
		RunAt:   job.RunAt.Local().Format(runAtLayout),
		Query:   fleet.Query{Scope: job.Scope, ServerID: job.ServerID, GroupID: job.GroupID},
	}
	switch job.Kind {
	case schedule.KindAdd:
		data.Rows = rowsFromOperation(op)
	case schedule.KindEdit:
		data.Old = op.Old
		data.Record = op.Record
	default:
		data.Record = op.Record
	}
	return data, nil
}

// rowsFromOperation turns a stored addition back into form rows.
func rowsFromOperation(op fleet.Operation) []recordRow {
	records := op.Records
	if len(records) == 0 {
		records = []dnsfile.Record{op.Record}
	}
	rows := make([]recordRow, 0, len(records))
	for _, record := range records {
		rows = append(rows, recordRow{Record: record, Types: dnsfile.Types})
	}
	return rows
}

// handleScheduledCreate stores one change for its chosen time.
func (a *App) handleScheduledCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.scheduledProblem(w, r, schedule.KindAdd, "The form could not be read.", http.StatusBadRequest)
		return
	}

	kind, op, target, runAt, problem, status, ok := a.jobFromForm(r)
	if !ok {
		a.scheduledProblem(w, r, kind, problem, status)
		return
	}

	if err := a.storeJob(r, kind, op, target, runAt); err != nil {
		a.internalError(w, r, "cannot store the scheduled job", err)
		return
	}

	SetToast(w, ToastSuccess, a.catalog(r).T("toast.scheduled_created"))
	a.closeScheduledPanel(w)
}

// handleScheduledUpdate rewrites a pending job from the edit form.
func (a *App) handleScheduledUpdate(w http.ResponseWriter, r *http.Request) {
	id := parseID(r.PathValue("id"))
	if id == 0 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := r.ParseForm(); err != nil {
		a.scheduledProblem(w, r, schedule.KindAdd, "The form could not be read.", http.StatusBadRequest)
		return
	}

	existing, err := a.Schedules.Get(r.Context(), id)
	if err != nil {
		a.notFoundOrError(w, r, "cannot read the scheduled job", err)
		return
	}

	kind, op, target, runAt, problem, status, ok := a.jobFromForm(r)
	if !ok {
		a.scheduledProblem(w, r, kind, problem, status)
		return
	}
	if existing.Status != schedule.StatusPending {
		a.scheduledProblem(w, r, kind, a.catalog(r).T("scheduled.not_pending"), http.StatusConflict)
		return
	}

	if err := a.updateJob(r, id, kind, op, target, runAt); err != nil {
		a.notFoundOrError(w, r, "cannot update the scheduled job", err)
		return
	}

	SetToast(w, ToastSuccess, a.catalog(r).T("toast.scheduled_updated"))
	a.closeScheduledPanel(w)
}

// jobFromForm reads the change, the target and the run time a create or an
// update posts, or the reason and status to refuse the form with.
func (a *App) jobFromForm(r *http.Request) (
	kind string, op fleet.Operation, target fleet.Target,
	runAt time.Time, problem string, status int, ok bool) {

	catalog := a.catalog(r)
	kind = formKind(r.Form.Get("kind"))

	op, err := operationFromForm(r.Form, kind)
	if err != nil {
		return kind, op, target, runAt, recordMessage(r.Context(), catalog, err), http.StatusBadRequest, false
	}
	if err := op.Validate(); err != nil {
		return kind, op, target, runAt, recordMessage(r.Context(), catalog, err), http.StatusUnprocessableEntity, false
	}
	target, err = targetFromValues(r.Form)
	if err != nil {
		return kind, op, target, runAt, recordMessage(r.Context(), catalog, err), http.StatusBadRequest, false
	}
	runAt, err = parseRunAt(r.Form.Get("run_at"))
	if err != nil {
		return kind, op, target, runAt, a.runAtMessage(r, err), http.StatusBadRequest, false
	}
	return kind, op, target, runAt, "", 0, true
}

// closeScheduledPanel empties the form panel and reloads the table on the
// event, so the handler does not swap the table into the panel the form filled.
func (a *App) closeScheduledPanel(w http.ResponseWriter) {
	SetTrigger(w, "scheduled-changed", nil)
	w.WriteHeader(http.StatusOK)
}

// storeJob writes the job and records that it was scheduled.
func (a *App) storeJob(r *http.Request, kind string,
	op fleet.Operation, target fleet.Target, runAt time.Time) error {

	raw, err := json.Marshal(op)
	if err != nil {
		return err
	}

	session, _ := SessionFrom(r.Context())
	created, err := a.Schedules.Create(r.Context(), schedule.Job{
		Kind:              kind,
		Operation:         raw,
		Scope:             target.Scope,
		ServerID:          target.ServerID,
		GroupID:           target.GroupID,
		OnConflict:        onConflictFrom(r.Form, op),
		RunAt:             runAt,
		RequestedUID:      session.UID,
		RequestedUsername: session.Username,
	})
	if err != nil {
		return err
	}

	a.auditSchedule(r, audit.ActionScheduleCreate, fmt.Sprintf(
		"Scheduled %s (%s) for %s", created.Kind, scheduleSummary(created),
		created.RunAt.Format(time.RFC3339)))
	return nil
}

// updateJob rewrites the job and records that it was rescheduled.
func (a *App) updateJob(r *http.Request, id int64, kind string,
	op fleet.Operation, target fleet.Target, runAt time.Time) error {

	raw, err := json.Marshal(op)
	if err != nil {
		return err
	}

	session, _ := SessionFrom(r.Context())
	err = a.Schedules.Update(r.Context(), schedule.Job{
		ID:                id,
		Kind:              kind,
		Operation:         raw,
		Scope:             target.Scope,
		ServerID:          target.ServerID,
		GroupID:           target.GroupID,
		OnConflict:        onConflictFrom(r.Form, op),
		RunAt:             runAt,
		RequestedUID:      session.UID,
		RequestedUsername: session.Username,
	})
	if err != nil {
		return err
	}

	a.auditSchedule(r, audit.ActionScheduleUpdate, fmt.Sprintf(
		"Rescheduled job #%d (%s: %s) for %s", id, kind, operationSummary(op),
		runAt.UTC().Format(time.RFC3339)))
	return nil
}

// handleScheduledCancel removes a scheduled job.
func (a *App) handleScheduledCancel(w http.ResponseWriter, r *http.Request) {
	id := parseID(r.PathValue("id"))
	if id == 0 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	job, err := a.Schedules.Get(r.Context(), id)
	if err != nil {
		a.notFoundOrError(w, r, "cannot read the scheduled job", err)
		return
	}
	if err := a.Schedules.Delete(r.Context(), id); err != nil {
		a.notFoundOrError(w, r, "cannot cancel the scheduled job", err)
		return
	}

	a.auditSchedule(r, audit.ActionScheduleCancel, fmt.Sprintf(
		"Cancelled scheduled job #%d (%s %s)", id, job.Kind, scheduleSummary(job)))
	SetToast(w, ToastSuccess, a.catalog(r).T("toast.scheduled_cancelled"))
	a.closeScheduledPanel(w)
}

// scheduledData builds the table rows from the stored jobs.
func (a *App) scheduledData(r *http.Request) (scheduledPageData, error) {
	jobs, err := a.Schedules.List(r.Context())
	if err != nil {
		return scheduledPageData{}, err
	}
	servers, groups, err := a.serversAndGroups(r.Context())
	if err != nil {
		return scheduledPageData{}, err
	}

	serverNames := make(map[int64]string, len(servers))
	for _, record := range servers {
		serverNames[record.ID] = record.Name
	}
	groupNames := make(map[int64]string, len(groups))
	for _, group := range groups {
		groupNames[group.ID] = group.Name
	}

	data := scheduledPageData{Jobs: make([]scheduleRow, 0, len(jobs))}
	for _, job := range jobs {
		data.Jobs = append(data.Jobs, scheduleRowFrom(job, serverNames, groupNames))
	}
	return data, nil
}

// serversAndGroups reads both target lists in one place.
func (a *App) serversAndGroups(ctx context.Context) ([]server.Server, []server.Group, error) {
	servers, err := a.Servers.List(ctx)
	if err != nil {
		return nil, nil, err
	}
	groups, err := a.Servers.ListGroups(ctx)
	if err != nil {
		return nil, nil, err
	}
	return servers, groups, nil
}

// scheduleRowFrom turns a stored job into a table row.
func scheduleRowFrom(job schedule.Job, serverNames, groupNames map[int64]string) scheduleRow {
	target := serverNames[job.ServerID]
	if job.Scope == fleet.ScopeGroup {
		target = groupNames[job.GroupID]
	}

	return scheduleRow{
		ID:      job.ID,
		Kind:    job.Kind,
		Summary: scheduleSummary(job),
		Target:  target,
		RunAt:   job.RunAt,
		Status:  job.Status,
		Result:  job.Result,
		Pending: job.Status == schedule.StatusPending,
	}
}

// scheduleSummary renders the change of a stored job to one line.
func scheduleSummary(job schedule.Job) string {
	var op fleet.Operation
	if err := json.Unmarshal(job.Operation, &op); err != nil {
		return ""
	}
	return operationSummary(op)
}

// operationSummary renders one operation to one line for the table and the
// audit trail.
func operationSummary(op fleet.Operation) string {
	record := op.Record
	if op.Kind == fleet.OpAddMany && len(op.Records) > 0 {
		record = op.Records[0]
	}

	summary := strings.TrimSpace(record.FQDN + " " + record.Type + " " + record.Value)
	if op.Kind == fleet.OpAddMany && len(op.Records) > 1 {
		summary += fmt.Sprintf(" (+%d)", len(op.Records)-1)
	}
	return summary
}

// operationFromForm builds the fleet operation the job stores, from the kind
// the operator chose.
func operationFromForm(form url.Values, kind string) (fleet.Operation, error) {
	switch kind {
	case schedule.KindAdd:
		op := fleet.Operation{Kind: fleet.OpAdd, Record: recordFromValues(form)}
		if rows := rowsFrom(form); len(rows) > 1 {
			op.Kind = fleet.OpAddMany
			op.Records = make([]dnsfile.Record, 0, len(rows))
			for _, row := range rows {
				op.Records = append(op.Records, row.Record)
			}
		}
		return op, nil
	case schedule.KindEdit:
		// The edit form identifies the record by its old fields and asks only
		// for the new value. The name and the type do not change, so the new
		// record carries the old ones rather than a second pair of inputs.
		old := oldRecordFromValues(form)
		updated := recordFromValues(form)
		updated.FQDN = old.FQDN
		updated.Type = old.Type
		return fleet.Operation{Kind: fleet.OpEdit, Record: updated, Old: old}, nil
	case schedule.KindDelete:
		return fleet.Operation{Kind: fleet.OpDelete, Record: recordFromValues(form)}, nil
	default:
		return fleet.Operation{}, fmt.Errorf("%w: unknown change %q", dnsfile.ErrInvalid, kind)
	}
}

// onConflictFrom reads the overwrite choice, which an addition alone offers.
func onConflictFrom(form url.Values, op fleet.Operation) string {
	if op.Kind != fleet.OpAdd && op.Kind != fleet.OpAddMany {
		return schedule.OnConflictFail
	}
	if form.Get("on_conflict") != "" {
		return schedule.OnConflictOverwrite
	}
	return schedule.OnConflictFail
}

// formKind narrows the kind to the three the form serves, defaulting to add.
func formKind(kind string) string {
	switch kind {
	case schedule.KindEdit, schedule.KindDelete:
		return kind
	default:
		return schedule.KindAdd
	}
}

// The reasons a run time is refused. They are sentinels so the handler can
// answer each in the reader's language.
var (
	errRunAtMissing = errors.New("no run time was given")
	errRunAtInvalid = errors.New("the run time could not be read")
	errRunAtPast    = errors.New("the run time is in the past")
)

// runAtLayout is what a datetime-local field posts: local time, no zone.
const runAtLayout = "2006-01-02T15:04"

// parseRunAt reads the chosen time as local and returns it in UTC.
//
// A datetime-local field carries no zone, so the value is read in the panel's
// zone and stored as UTC like every other timestamp. A time already past is
// refused here, because a scheduled change is a change meant for later; a job
// whose stored time has passed because the panel was down is a separate case
// the scheduler runs on its next pass.
func parseRunAt(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, errRunAtMissing
	}
	local, err := time.ParseInLocation(runAtLayout, raw, time.Local)
	if err != nil {
		return time.Time{}, errRunAtInvalid
	}
	if !local.After(time.Now()) {
		return time.Time{}, errRunAtPast
	}
	return local.UTC(), nil
}

// runAtMessage turns a run time refusal into a sentence for the form.
func (a *App) runAtMessage(r *http.Request, err error) string {
	catalog := a.catalog(r)
	switch {
	case errors.Is(err, errRunAtPast):
		return catalog.T("scheduled.run_at_past")
	case errors.Is(err, errRunAtMissing):
		return catalog.T("scheduled.run_at_missing")
	default:
		return catalog.T("scheduled.run_at_invalid")
	}
}

// scheduledProblem sends the form back with the reason it was refused.
func (a *App) scheduledProblem(w http.ResponseWriter, r *http.Request,
	kind, problem string, status int) {

	servers, groups, err := a.serversAndGroups(r.Context())
	if err != nil {
		a.internalError(w, r, "cannot load the targets", err)
		return
	}

	data := scheduleFormData{
		// On the update route the path carries the id, so a refused edit posts
		// back to the same job rather than creating a second one; on the create
		// route the path has none and this is zero.
		JobID:   parseID(r.PathValue("id")),
		Kind:    kind,
		Record:  recordFromValues(r.Form),
		Query:   listingFrom(r.Form),
		RunAt:   r.Form.Get("run_at"),
		Types:   dnsfile.Types,
		Servers: servers,
		Groups:  groups,
		Problem: problem,
	}
	switch kind {
	case schedule.KindAdd:
		data.Rows = rowsFrom(r.Form)
	case schedule.KindEdit:
		data.Old = oldRecordFromValues(r.Form)
	}

	a.RenderPartial(w, r, status, "scheduled-form", data)
}

// auditSchedule records a scheduling action against the operator who took it.
func (a *App) auditSchedule(r *http.Request, action, details string) {
	actor := a.actor(r)

	err := a.Audit.Write(r.Context(), audit.Entry{
		UID:       actor.UID,
		Username:  actor.Username,
		Action:    action,
		Details:   details,
		IPAddress: actor.IPAddress,
	})
	if err != nil {
		logging.From(r.Context()).Error("cannot record a scheduling action", "error", err)
	}
}
