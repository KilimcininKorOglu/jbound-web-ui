package fleet

import (
	"context"
	"errors"
	"fmt"
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
)

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
}

// Validate reports every problem before any server is touched.
//
// It runs before the target is resolved, so an invalid request cannot reach a
// single server.
func (o Operation) Validate() error {
	switch o.Kind {
	case OpAdd:
		return o.Record.Validate()
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

// apply changes the file content.
func (o Operation) apply(content []byte) ([]byte, error) {
	switch o.Kind {
	case OpAdd:
		updated, err := dnsfile.Add(content, o.Record)
		if err != nil {
			return nil, err
		}
		return dnsfile.EnsureZone(updated, o.Record.FQDN), nil
	case OpEdit:
		updated, err := dnsfile.Edit(content, o.Old, o.Record)
		if err != nil {
			return nil, err
		}
		// An edit may move the record to another name, and the new name may
		// sit under a zone the file does not declare yet.
		return dnsfile.EnsureZone(updated, o.Record.FQDN), nil
	case OpDelete:
		// The zone line stays. A transparent zone with no local data of its
		// own changes no answer, and removing it would reach every other name
		// under it.
		return dnsfile.Delete(content, o.Record)
	default:
		return nil, fmt.Errorf("%w: unknown operation %q", dnsfile.ErrInvalid, o.Kind)
	}
}

// auditAction names the action written for one server.
func (o Operation) auditAction() string {
	switch o.Kind {
	case OpAdd:
		return audit.ActionDNSAdd
	case OpEdit:
		return audit.ActionDNSEdit
	default:
		return audit.ActionDNSDelete
	}
}

// auditDetails describes the change for a person reading the log.
func (o Operation) auditDetails() string {
	switch o.Kind {
	case OpAdd:
		return fmt.Sprintf("Added %s record: %s -> %s",
			o.Record.Type, o.Record.FQDN, o.Record.Value)
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
	switch o.Kind {
	case OpAdd:
		return "Record added"
	case OpEdit:
		return "Record updated"
	default:
		return "Record deleted"
	}
}

// ServerResult is what one server did.
type ServerResult struct {
	ServerID   int64
	ServerName string
	Status     string
	Message    string
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

	if err := w.write(ctx, record, op); err != nil {
		// The response table is the only other place this appears, and it
		// lives exactly as long as the page it was rendered into.
		logging.From(ctx).Error("cannot write a record to a server",
			"server", record.Name, "operation", op.Kind,
			"fqdn", op.Record.FQDN, "type", op.Record.Type, "error", err)

		result.Status = StatusFailed
		result.Message = failureMessage(err)
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

// write performs the read, change and write of one server.
func (w *Writer) write(ctx context.Context, record server.Server, op Operation) error {
	client, err := w.pool.Get(w.transportConfig(record))
	if err != nil {
		return err
	}

	content, digest, err := client.ReadHostEntries(ctx)
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
	if err := client.WriteHostEntries(ctx, updated, digest); err != nil {
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
