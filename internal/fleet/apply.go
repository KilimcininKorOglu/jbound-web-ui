package fleet

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"jbound/internal/audit"
	"jbound/internal/dnsfile"
	"jbound/internal/logging"
	"jbound/internal/server"
	"jbound/internal/transport"
)

// Operation kinds. A record change is one of exactly three things.
const (
	OpAdd    = "add"
	OpEdit   = "edit"
	OpDelete = "delete"

	// OpAddMany writes several records in one pass. The whole batch reaches
	// the file in one write, so a group of records either arrives together or
	// not at all, and one reload follows all of them.
	OpAddMany = "add_many"
)

// maxBatch bounds one submission. It is generous enough for the list an
// operator pastes in and small enough that a rejected batch is still a message
// somebody can read.
const maxBatch = 100

// Outcome of one server in a fleet operation.
const (
	StatusSuccess = "success"
	StatusFailed  = "failed"
	StatusSkipped = "skipped"
)

// ErrScope marks a scope a write may not use.
var ErrScope = errors.New("invalid scope")

// Target names which servers an operation covers.
type Target struct {
	Scope    string
	ServerID int64
	GroupID  int64
}

// Operation is one change to apply across the target.
type Operation struct {
	Kind   string
	Record dnsfile.Record

	// Old carries the record being replaced. It is only read for an edit.
	Old dnsfile.Record

	// Records carries the batch of an OpAddMany.
	Records []dnsfile.Record
}

// Validate reports every problem before any server is touched.
//
// It runs before the target is resolved, so an invalid request cannot reach a
// single server.
func (o Operation) Validate() error {
	switch o.Kind {
	case OpAdd:
		return o.Record.Validate()
	case OpAddMany:
		return o.validateBatch()
	case OpDelete:
		// A record on the way out is judged more leniently, so a line an
		// earlier panel wrote with the wrong address family can still be
		// taken off the server through the panel.
		return o.Record.ValidateForRemoval()
	case OpEdit:
		if err := o.Old.ValidateForRemoval(); err != nil {
			return fmt.Errorf("the record being replaced is not valid: %w", err)
		}
		return o.Record.Validate()
	default:
		return fmt.Errorf("%w: unknown operation %q", dnsfile.ErrInvalid, o.Kind)
	}
}

// validateBatch reports the first row that cannot be written.
//
// The row is named, because a message about a batch of twenty that does not
// say which one is wrong leaves the operator to find it themselves. A duplicate
// inside the batch is caught here as well: the file would refuse the second
// copy halfway through, after the first records were already in the content.
func (o Operation) validateBatch() error {
	if len(o.Records) == 0 {
		return fmt.Errorf("%w: no record was given", dnsfile.ErrInvalid)
	}
	if len(o.Records) > maxBatch {
		return fmt.Errorf("%w: %d records at once, the limit is %d",
			dnsfile.ErrInvalid, len(o.Records), maxBatch)
	}

	seen := make(map[dnsfile.Record]int, len(o.Records))
	for i, record := range o.Records {
		if err := record.Validate(); err != nil {
			return fmt.Errorf("row %d: %w", i+1, err)
		}
		if first, ok := seen[record]; ok {
			return fmt.Errorf("%w: row %d repeats row %d",
				dnsfile.ErrDuplicate, i+1, first)
		}
		seen[record] = i + 1
	}
	return nil
}

// apply changes the file content.
func (o Operation) apply(content []byte) ([]byte, error) {
	switch o.Kind {
	case OpAdd:
		updated, err := dnsfile.Add(content, o.Record)
		if err != nil {
			return nil, err
		}
		return checked(declareZone(updated, o.Record))
	case OpAddMany:
		// Every record goes into the content before anything is written, so a
		// row the file refuses leaves the server as it was rather than half
		// way through the batch.
		updated := content
		for i, record := range o.Records {
			next, err := dnsfile.Add(updated, record)
			if err != nil {
				return nil, fmt.Errorf("row %d: %w", i+1, err)
			}
			updated = declareZone(next, record)
		}
		return checked(updated)
	case OpEdit:
		updated, err := dnsfile.Edit(content, o.Old, o.Record)
		if err != nil {
			return nil, err
		}
		// An edit may move the record to another name, and the new name may
		// sit under a zone the file does not declare yet.
		return checked(declareZone(updated, o.Record))
	case OpDelete:
		// The zone line stays. A transparent zone with no local data of its
		// own changes no answer, and removing it would reach every other name
		// under it.
		return dnsfile.Delete(content, o.Record)
	default:
		return nil, fmt.Errorf("%w: unknown operation %q", dnsfile.ErrInvalid, o.Kind)
	}
}

// declareZone adds the parent zone a record needs.
//
// A blocked name brings its own zone line, so there is nothing to declare for
// it. Declaring the parent anyway would be a second decision about every other
// name under that parent, which is not what blocking one name asks for.
func declareZone(content []byte, record dnsfile.Record) []byte {
	if dnsfile.IsPolicy(record.Type) {
		return content
	}
	return dnsfile.EnsureZone(content, record.FQDN)
}

// checked refuses a result the resolver would answer differently from the file.
//
// It reads the content rather than the change, so an addition, a batch, an
// edit, a repair and a mirror are all covered by the one rule. The restore path
// does not come through here, the same way it skips the configuration check:
// it puts back a file the resolver was already running.
func checked(content []byte) ([]byte, error) {
	if err := dnsfile.CheckConsistency(content); err != nil {
		return nil, err
	}
	return content, nil
}

// auditAction names the action written for one server.
func (o Operation) auditAction() string {
	switch o.Kind {
	case OpAdd, OpAddMany:
		return audit.ActionDNSAdd
	case OpEdit:
		return audit.ActionDNSEdit
	default:
		return audit.ActionDNSDelete
	}
}

// auditDetails describes the change for a person reading the log.
func (o Operation) auditDetails() string {
	// A block is not a record, and a trail that called it one would read as
	// though a name had been given an address.
	if dnsfile.IsPolicy(o.Record.Type) && o.Kind != OpAddMany {
		switch o.Kind {
		case OpAdd:
			return fmt.Sprintf("Blocked %s with %s", o.Record.FQDN, o.Record.Type)
		case OpEdit:
			return fmt.Sprintf("Changed the block on %s: %s -> %s",
				o.Old.FQDN, o.Old.Type, o.Record.Type)
		case OpDelete:
			return fmt.Sprintf("Removed the %s block on %s", o.Record.Type, o.Record.FQDN)
		}
	}

	switch o.Kind {
	case OpAdd:
		return fmt.Sprintf("Added %s record: %s -> %s",
			o.Record.Type, o.Record.FQDN, o.Record.Value)
	case OpAddMany:
		return fmt.Sprintf("Added %d records: %s",
			len(o.Records), foldOutput(recordList(o.Records), maxBatchDetails))
	case OpEdit:
		return fmt.Sprintf("Edited: %s (%s %s) -> %s (%s %s)",
			o.Old.FQDN, o.Old.Type, o.Old.Value,
			o.Record.FQDN, o.Record.Type, o.Record.Value)
	default:
		return fmt.Sprintf("Deleted %s record: %s -> %s",
			o.Record.Type, o.Record.FQDN, o.Record.Value)
	}
}

// message describes the change for the result table.
func (o Operation) message() string {
	if dnsfile.IsPolicy(o.Record.Type) && o.Kind != OpAddMany {
		switch o.Kind {
		case OpAdd:
			return "Name blocked"
		case OpEdit:
			return "Block changed"
		case OpDelete:
			return "Block removed"
		}
	}

	switch o.Kind {
	case OpAdd:
		return "Record added"
	case OpAddMany:
		return fmt.Sprintf("%d records added", len(o.Records))
	case OpEdit:
		return "Record updated"
	default:
		return "Record deleted"
	}
}

// maxBatchDetails bounds how much of a batch reaches one audit row. The names
// are what makes the row worth reading; a hundred of them are not.
const maxBatchDetails = 400

// recordList names the records of a batch for a person reading the trail.
func recordList(records []dnsfile.Record) string {
	names := make([]string, 0, len(records))
	for _, record := range records {
		// A block has no value, and an arrow pointing at nothing reads as a
		// record whose address went missing.
		if dnsfile.IsPolicy(record.Type) {
			names = append(names, record.Type+" "+record.FQDN)
			continue
		}
		names = append(names, record.Type+" "+record.FQDN+" -> "+record.Value)
	}
	return strings.Join(names, ", ")
}

// Where a failure came from.
//
// The same table shows a change the panel refused, a server it could not
// reach and a resolver that said no, and the three call for three different
// moves from the operator. The message says what happened; this says who said
// it.
const (
	SourcePanel      = "panel"
	SourceConnection = "connection"
	SourceResolver   = "resolver"
)

// ServerResult is what one server did.
type ServerResult struct {
	ServerID   int64
	ServerName string
	Status     string
	Message    string

	// Source stays empty unless the server failed.
	Source string
}

// fail marks a result with what went wrong and who said it.
func (r *ServerResult) fail(err error) {
	r.Status = StatusFailed
	r.Message = failureMessage(err)
	r.Source = failureSource(err)
}

// Report is the outcome of one fleet operation.
type Report struct {
	Results []ServerResult

	// GroupName is empty unless the operation targeted a group. It travels to
	// the audit rows, so a change reads the same way the operator made it.
	GroupName string
}

// Counts returns how many servers ended in each state.
func (r Report) Counts() (success, failed, skipped int) {
	for _, result := range r.Results {
		switch result.Status {
		case StatusSuccess:
			success++
		case StatusFailed:
			failed++
		default:
			skipped++
		}
	}
	return success, failed, skipped
}

// SuccessCount, FailedCount and SkippedCount feed the summary line of the
// report, so a reader sees the shape of the outcome before reading the rows.
func (r Report) SuccessCount() int { success, _, _ := r.Counts(); return success }
func (r Report) FailedCount() int  { _, failed, _ := r.Counts(); return failed }
func (r Report) SkippedCount() int { _, _, skipped := r.Counts(); return skipped }

// OK reports whether every server that was reached succeeded.
func (r Report) OK() bool {
	_, failed, _ := r.Counts()
	return failed == 0
}

// Partial reports whether some servers succeeded and others did not.
func (r Report) Partial() bool {
	success, failed, _ := r.Counts()
	return success > 0 && failed > 0
}

// Writer applies record changes across a target.
type Writer struct {
	servers  ServerSource
	groups   GroupSource
	pool     Connector
	refresh  *Refresher
	audit    *audit.Logger
	backups  BackupStore
	dataDir  string
	timeouts func() server.Timeouts

	concurrent func() int

	// restartSettle is how long a restarted resolver is given to come back.
	// It is a field rather than a constant so the tests do not have to wait
	// out a real one.
	restartSettle time.Duration
}

// GroupSource resolves a group into its members.
//
// Targets refuses a group with no member, so an operation that would reach
// nothing never becomes a report full of nothing.
type GroupSource interface {
	GetGroup(ctx context.Context, id int64) (server.Group, error)
	Targets(ctx context.Context, groupID int64) ([]server.Server, error)

	// SourceServer answers with the member a mirror copies from, and whether
	// there is one at all. A reference that has left the group or gone out of
	// reach reads as none.
	SourceServer(ctx context.Context, groupID int64) (server.Server, bool, error)
}

// NewWriter builds the writer.
func NewWriter(servers ServerSource, groups GroupSource, pool Connector,
	refresh *Refresher, auditLog *audit.Logger, backups BackupStore,
	dataDir string, timeouts func() server.Timeouts, concurrent func() int) *Writer {

	return &Writer{
		servers:    servers,
		groups:     groups,
		pool:       pool,
		refresh:    refresh,
		audit:      auditLog,
		backups:    backups,
		dataDir:    dataDir,
		timeouts:   timeouts,
		concurrent: concurrent,

		restartSettle: restartAttempts * restartWait,
	}
}

// transportConfig builds the connection settings of one server.
//
// The timeouts are read here rather than held, so an operation that starts
// after a settings change uses the values the operator just saved.
func (w *Writer) transportConfig(record server.Server) transport.Config {
	timeouts := w.timeouts()
	return record.TransportConfig(w.dataDir, timeouts.Connect, timeouts.Command)
}

// Targets resolves a target into the servers an operation will reach.
//
// A disabled server stays in the list. It produces a skipped result, so the
// operator sees that it was left out rather than wondering why the count is
// short.
func (w *Writer) Targets(ctx context.Context, target Target) ([]server.Server, string, error) {
	if target.Scope == ScopeAll {
		// A change to every server at once is not something an operator asks
		// for by accident, so it has to be a group they built on purpose.
		return nil, "", fmt.Errorf("%w: a write needs a server or a group", ErrScope)
	}
	return w.Members(ctx, target)
}

// Members resolves a target into the servers it covers.
//
// It answers for every scope, including the whole fleet, because a listing may
// span what a write may not.
func (w *Writer) Members(ctx context.Context, target Target) ([]server.Server, string, error) {
	switch target.Scope {
	case ScopeServer:
		record, err := w.servers.Get(ctx, target.ServerID)
		if err != nil {
			return nil, "", err
		}
		return []server.Server{record}, "", nil

	case ScopeGroup:
		group, err := w.groups.GetGroup(ctx, target.GroupID)
		if err != nil {
			return nil, "", err
		}
		members, err := w.groups.Targets(ctx, target.GroupID)
		if err != nil {
			return nil, "", err
		}
		return members, group.Name, nil

	case ScopeAll:
		members, err := w.servers.ListEnabled(ctx)
		if err != nil {
			return nil, "", err
		}
		return members, "", nil

	default:
		return nil, "", fmt.Errorf("%w: %q", ErrScope, target.Scope)
	}
}

// Apply runs one operation across the target.
//
// Validation comes first and covers the whole request, so an invalid record
// never reaches a server. After that each server is independent: one failure
// is reported next to the others rather than stopping them.
func (w *Writer) Apply(ctx context.Context, actor server.Actor,
	target Target, op Operation) (Report, error) {

	if err := op.Validate(); err != nil {
		return Report{}, err
	}

	targets, groupName, err := w.Targets(ctx, target)
	if err != nil {
		return Report{}, err
	}

	results := w.fanOut(ctx, targets, func(ctx context.Context, record server.Server) ServerResult {
		return w.applyOne(ctx, actor, record, op, groupName)
	})

	return Report{Results: results, GroupName: groupName}, nil
}

// fanOut runs one job per server, bounded by the configured concurrency.
//
// The results keep the order of the targets, so the table reads the same way
// twice regardless of which server answered first.
func (w *Writer) fanOut(ctx context.Context, targets []server.Server,
	job func(context.Context, server.Server) ServerResult) []ServerResult {

	return fanOut(ctx, targets, w.concurrent, job)
}

// fanOut runs one job per server under the configured limit.
//
// It is a function rather than a method so every path that talks to several
// servers at once can reach it. A loop written out by hand is a loop that can
// be written without the limiter, which is how the DNS query fan-out came to
// ignore `fleet_max_concurrent` entirely.
func fanOut[T any](ctx context.Context, targets []server.Server,
	concurrent func() int, job func(context.Context, server.Server) T) []T {

	results := make([]T, len(targets))
	slots := make(chan struct{}, max(1, concurrent()))

	var wait sync.WaitGroup
	for i, record := range targets {
		wait.Go(func() {
			slots <- struct{}{}
			defer func() { <-slots }()

			results[i] = job(ctx, record)
		})
	}
	wait.Wait()

	return results
}

// applyOne reads, changes and writes the file of one server.
func (w *Writer) applyOne(ctx context.Context, actor server.Actor,
	record server.Server, op Operation, groupName string) ServerResult {

	if refusal, ok := refuse(record); ok {
		return refusal
	}
	result := ServerResult{ServerID: record.ID, ServerName: record.Name}

	lock := w.lockFor(record.ID)
	lock.Lock()
	defer lock.Unlock()

	if err := w.write(ctx, actor, record, op); err != nil {
		// The response table is the only other place this appears, and it
		// lives exactly as long as the page it was rendered into.
		logging.From(ctx).Error("cannot write a record to a server",
			"server", record.Name, "operation", op.Kind,
			"fqdn", op.Record.FQDN, "type", op.Record.Type, "error", err)

		result.fail(err)
		return result
	}

	// The file changed, so what the panel shows for this server is now stale.
	// A refresh that fails does not undo the write, and saying the change
	// failed would be worse than showing it late.
	refillCtx, cancelRefill := afterChange(ctx)
	defer cancelRefill()

	if _, refreshErr := w.refresh.oneHeld(refillCtx, record.ID); refreshErr != nil {
		logging.From(ctx).Error("cannot refresh the cache after a write",
			"server", record.Name, "error", refreshErr)
		result.Message = op.message() + ", but the cache could not be refreshed"
	} else {
		result.Message = op.message()
	}
	result.Status = StatusSuccess

	w.writeAudit(ctx, actor, record, op, groupName)
	return result
}

// refillTimeout bounds the cache refill that follows a change.
//
// Every remote command inside it carries ssh_command_timeout of its own, so
// this is the backstop that keeps a detached refill from outliving the process.
const refillTimeout = 2 * time.Minute

// afterChange returns the context for work that follows a change the panel has
// already made on a server.
//
// The remote file is written first, so a client that disconnects mid request
// would otherwise leave the panel describing a file it has just changed until
// the next timer pass, up to cache_refresh_interval later. htmx aborts an in
// flight request whenever the same element fires another, so this is ordinary
// interface use rather than a network failure. The values of the request are
// kept, so the log line still names it.
func afterChange(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), refillTimeout)
}

// refuse reports the servers no operation may reach, and why.
//
// A disabled server is skipped rather than failed, because leaving it out is
// what the operator asked for. A server whose host key nobody approved is a
// failure, because the operator meant to reach it and did not.
func refuse(record server.Server) (ServerResult, bool) {
	result := ServerResult{ServerID: record.ID, ServerName: record.Name}

	switch {
	case !record.Enabled:
		result.Status = StatusSkipped
		result.Message = "Server disabled"
	case !record.Trusted():
		result.Status = StatusFailed
		result.Message = "The host key has not been approved yet"
		// Nothing was dialled, and what is missing is the approval that would
		// let the panel dial at all.
		result.Source = SourceConnection
	default:
		return ServerResult{}, false
	}
	return result, true
}

// failureMessage turns one server's failure into the line the report shows.
//
// The deadline of the whole operation reads as "context deadline exceeded",
// which tells the operator nothing about what happened or what to do. Every
// other failure keeps its own text.
func failureMessage(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "The operation ran out of time before this server was finished"
	case errors.Is(err, context.Canceled):
		return "The operation was stopped before this server was finished"
	default:
		return err.Error()
	}
}

// failureSource names who refused, so the row says where to look.
//
// A change the panel refused is the operator's to correct and would fail the
// same way on every server. A server the panel could not reach is a matter for
// that host. A resolver that read the file and said no is a third thing again,
// and the previous file is already back on it.
func failureSource(err error) string {
	switch {
	case errors.Is(err, dnsfile.ErrInvalid), errors.Is(err, dnsfile.ErrDuplicate),
		errors.Is(err, dnsfile.ErrNotFound), errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, context.Canceled):
		return SourcePanel
	case errors.Is(err, ErrConfigRefused), errors.Is(err, transport.ErrCommandFailed),
		errors.Is(err, transport.ErrConflict), errors.Is(err, transport.ErrRemoteOutput):
		return SourceResolver
	default:
		// Everything the transport raises before a command runs: unreachable,
		// an unknown or changed host key, a refused credential.
		return SourceConnection
	}
}

// write performs the read, change and write of one server.
func (w *Writer) write(ctx context.Context, actor server.Actor,
	record server.Server, op Operation) error {

	client, err := w.pool.Get(w.transportConfig(record))
	if err != nil {
		return err
	}

	w.ensureInclude(ctx, client, actor, record)

	content, digest, err := client.ReadRecords(ctx)
	if err != nil {
		return err
	}

	updated, err := op.apply(content)
	if err != nil {
		return err
	}

	// The file is replaced in one move, so this is the last moment the content
	// it holds exists anywhere the panel can reach.
	w.keepPrevious(ctx, record.ID, content, digest)

	// The digest travels back with the write, so a file that changed on the
	// target between the read and the write is refused rather than replaced.
	if err := writeRecords(ctx, client, updated, digest); err != nil {
		return err
	}
	return w.checkConfig(ctx, client, record, content)
}

// writeAudit records one server's share of the change.
func (w *Writer) writeAudit(ctx context.Context, actor server.Actor,
	record server.Server, op Operation, groupName string) {

	details := op.auditDetails() + " on " + record.Name
	if groupName != "" {
		details += " (group " + groupName + ")"
	}

	serverID := record.ID
	_ = w.audit.Write(ctx, audit.Entry{
		UID:        actor.UID,
		Username:   actor.Username,
		ServerID:   &serverID,
		ServerName: record.Name,
		Action:     op.auditAction(),
		Details:    details,
		IPAddress:  actor.IPAddress,
	})
}

// lockFor returns the mutex of one server.
//
// The optimistic digest already refuses a lost update, but two panel users
// editing the same server would otherwise turn one of the two into a conflict
// error instead of a change that lands.
//
// The map itself belongs to the refresher, so a background pass takes the same
// mutex a write does rather than a second one that guards nothing.
func (w *Writer) lockFor(serverID int64) *sync.Mutex {
	return w.refresh.lockFor(serverID)
}
