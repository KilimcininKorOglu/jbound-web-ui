package fleet

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"unbound-web/internal/dnsfile"
	"unbound-web/internal/logging"
	"unbound-web/internal/server"
	"unbound-web/internal/transport"
)

// RecordStore holds the cached records of every server.
type RecordStore interface {
	Replace(ctx context.Context, serverID int64, records []dnsfile.Record) error
}

// StateStore holds what the panel knows about each server's file.
type StateStore interface {
	SetFetched(ctx context.Context, state State) error
	SetUnreachable(ctx context.Context, serverID int64, failure string) error
	SetApplied(ctx context.Context, serverID int64, digest string) error
	Get(ctx context.Context, serverID int64) (State, error)
	List(ctx context.Context) (map[int64]State, error)
}

// ServerSource lists the servers a refresh covers.
type ServerSource interface {
	ListEnabled(ctx context.Context) ([]server.Server, error)
	Get(ctx context.Context, id int64) (server.Server, error)
}

// Connector opens a transport for one server.
type Connector interface {
	Get(cfg transport.Config) (transport.Transport, error)
}

// Refresher fills the record cache from the managed servers.
type Refresher struct {
	servers  ServerSource
	records  RecordStore
	states   StateStore
	pool     Connector
	dataDir  string
	timeouts func() server.Timeouts

	// concurrent bounds how many servers are read at once. A fleet larger than
	// the panel host can hold connections for would otherwise take it down
	// rather than take longer.
	concurrent func() int

	now func() time.Time

	// locks serialise the read, change and write cycle of one server. They live
	// here rather than on the writer because a refresh is the other half of
	// that cycle: a pass that read the file before a write must not store its
	// snapshot after it, or the cache would describe a file that is gone.
	mu    sync.Mutex
	locks map[int64]*sync.Mutex
}

// NewRefresher builds the refresher.
//
// The timeouts and the concurrency arrive as accessors, so a pass that starts
// after a settings change reads the new values without a restart.
func NewRefresher(servers ServerSource, records RecordStore, states StateStore,
	pool Connector, dataDir string, timeouts func() server.Timeouts,
	concurrent func() int) *Refresher {

	return &Refresher{
		servers:    servers,
		records:    records,
		states:     states,
		pool:       pool,
		dataDir:    dataDir,
		timeouts:   timeouts,
		concurrent: concurrent,
		now:        time.Now,
		locks:      map[int64]*sync.Mutex{},
	}
}

// lockFor returns the mutex of one server, creating it on first use.
func (r *Refresher) lockFor(serverID int64) *sync.Mutex {
	r.mu.Lock()
	defer r.mu.Unlock()

	lock, ok := r.locks[serverID]
	if !ok {
		lock = &sync.Mutex{}
		r.locks[serverID] = lock
	}
	return lock
}

// Result is the outcome of refreshing one server.
type Result struct {
	ServerID   int64
	ServerName string

	// Records is how many the file held. It stays zero when the read failed.
	Records int

	// Digest is the SHA-256 of the file as it was just read. A reload records
	// it as the applied digest, which is how the panel knows afterwards that
	// the resolver holds what the file says.
	Digest string

	// Err carries the reason a server could not be read. The cache of that
	// server is left as it was.
	Err error
}

// OK reports whether the server was read.
func (r Result) OK() bool { return r.Err == nil }

// One refreshes a single server.
func (r *Refresher) One(ctx context.Context, serverID int64) (Result, error) {
	lock := r.lockFor(serverID)
	lock.Lock()
	defer lock.Unlock()

	return r.oneHeld(ctx, serverID)
}

// oneHeld refreshes a server whose lock the caller already holds.
//
// Every path that changes a file takes the lock, writes, and refills the cache
// inside the same critical section, so it cannot take the lock a second time.
func (r *Refresher) oneHeld(ctx context.Context, serverID int64) (Result, error) {
	record, err := r.servers.Get(ctx, serverID)
	if err != nil {
		return Result{}, err
	}
	return r.refresh(ctx, record), nil
}

// All refreshes every enabled server.
//
// A server that cannot be read does not stop the others. The panel manages a
// fleet, and one unreachable host must not blank the whole view.
func (r *Refresher) All(ctx context.Context) ([]Result, error) {
	servers, err := r.servers.ListEnabled(ctx)
	if err != nil {
		return nil, err
	}

	results := make([]Result, len(servers))
	slots := make(chan struct{}, max(1, r.concurrent()))

	var wait sync.WaitGroup
	for i, record := range servers {
		wait.Go(func() {
			slots <- struct{}{}
			defer func() { <-slots }()

			lock := r.lockFor(record.ID)
			lock.Lock()
			defer lock.Unlock()

			results[i] = r.refresh(ctx, record)
		})
	}
	wait.Wait()

	return results, nil
}

// refresh reads one server and writes what it found into the cache.
func (r *Refresher) refresh(ctx context.Context, record server.Server) Result {
	result := Result{ServerID: record.ID, ServerName: record.Name}

	if !record.Trusted() {
		// Reaching out would fail on the host key anyway, and the message
		// would point at the network instead of at the missing approval.
		result.Err = fmt.Errorf("%w: the host key has not been approved", transport.ErrHostKeyUnknown)
		r.markUnreachable(ctx, record.ID, result.Err)
		return result
	}

	timeouts := r.timeouts()
	client, err := r.pool.Get(record.TransportConfig(
		r.dataDir, timeouts.Connect, timeouts.Command))
	if err != nil {
		result.Err = err
		r.markUnreachable(ctx, record.ID, err)
		return result
	}

	content, digest, err := client.ReadHostEntries(ctx)
	if err != nil {
		result.Err = err
		r.markUnreachable(ctx, record.ID, err)
		return result
	}

	records := dnsfile.Parse(content)
	if err := r.records.Replace(ctx, record.ID, records); err != nil {
		// On the timer path nobody is waiting for this error, and the state row
		// keeps saying the server was read, so the panel would serve stale
		// records with nothing anywhere to explain them.
		logging.From(ctx).Error("cannot store the records of a server",
			"server", record.Name, "error", err)
		result.Err = err
		return result
	}

	// The resolver state is worth knowing but not worth failing the refresh
	// over. A server whose file was read is reachable either way.
	active, _, statusErr := client.ServiceStatus(ctx)
	if statusErr != nil {
		active = false
		logging.From(ctx).Warn("cannot read the resolver status",
			"server", record.Name, "error", statusErr)
	}

	fetched := r.now().UTC()
	state := State{
		ServerID:      record.ID,
		FileSHA256:    digest,
		FetchedAt:     &fetched,
		Reachable:     true,
		UnboundActive: active,
		RecordCount:   len(records),
	}
	if err := r.states.SetFetched(ctx, state); err != nil {
		logging.From(ctx).Error("cannot store the state of a server",
			"server", record.Name, "error", err)
		result.Err = err
		return result
	}

	result.Records = len(records)
	result.Digest = digest
	return result
}

// markApplied records the digest the resolver has loaded.
func (r *Refresher) markApplied(ctx context.Context, serverID int64, digest string) error {
	return r.states.SetApplied(ctx, serverID, digest)
}

// markUnreachable records why a server could not be read.
//
// Only the failure class is stored, because the text of a transport error
// names the remote command, its paths and its stderr, and the row it lands in
// is read by every signed in account. The cause itself goes to the log.
//
// The cached records stay. Old records with a warning next to them say more
// than an empty page, which is what dropping them would leave behind.
func (r *Refresher) markUnreachable(ctx context.Context, serverID int64, cause error) {
	code := transport.FailureCode(cause)
	logging.From(ctx).Error("cannot read a server",
		"server", serverID, "code", code, "error", cause)

	if err := r.states.SetUnreachable(ctx, serverID, code); err != nil {
		logging.From(ctx).Error("cannot record that a server is unreachable",
			"server", serverID, "error", err)
	}
}

// Start refreshes the fleet on a timer until the context is cancelled.
//
// The first pass runs straight away, because the panel is more useful with a
// filled cache than with an empty one and the first page load should not have
// to wait for the interval.
//
// A timer rather than a ticker, because the interval is read again before
// every wait. An operator who shortens it on the settings page waits out the
// current round and no longer.
func (r *Refresher) Start(ctx context.Context, interval func() time.Duration) {
	go func() {
		r.run(ctx)

		timer := time.NewTimer(interval())
		defer timer.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				r.run(ctx)
				timer.Reset(interval())
			}
		}
	}()
}

// run performs one pass and reports what it could not do.
func (r *Refresher) run(ctx context.Context) {
	results, err := r.All(ctx)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			slog.Error("cannot refresh the fleet", "error", err)
		}
		return
	}

	failed := 0
	for _, result := range results {
		if result.OK() {
			continue
		}
		failed++
		// A count on its own cannot tell one flapping host from a fleet wide
		// outage, and the panel is the wrong place to look it up when the panel
		// is the thing in trouble.
		slog.Warn("a server could not be refreshed",
			"server", result.ServerName, "error", result.Err)
	}
	slog.Info("fleet refreshed", "servers", len(results), "failed", failed)
}
