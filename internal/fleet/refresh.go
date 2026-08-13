package fleet

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"unbound-web/internal/dnsfile"
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
	timeouts server.Timeouts

	// concurrent bounds how many servers are read at once. A fleet larger than
	// the panel host can hold connections for would otherwise take it down
	// rather than take longer.
	concurrent int

	now func() time.Time
}

// NewRefresher builds the refresher.
func NewRefresher(servers ServerSource, records RecordStore, states StateStore,
	pool Connector, dataDir string, timeouts server.Timeouts, concurrent int) *Refresher {

	return &Refresher{
		servers:    servers,
		records:    records,
		states:     states,
		pool:       pool,
		dataDir:    dataDir,
		timeouts:   timeouts,
		concurrent: max(1, concurrent),
		now:        time.Now,
	}
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
	slots := make(chan struct{}, r.concurrent)

	var wait sync.WaitGroup
	for i, record := range servers {
		wait.Add(1)
		go func() {
			defer wait.Done()

			slots <- struct{}{}
			defer func() { <-slots }()

			results[i] = r.refresh(ctx, record)
		}()
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

	client, err := r.pool.Get(record.TransportConfig(
		r.dataDir, r.timeouts.Connect, r.timeouts.Command))
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
		result.Err = err
		return result
	}

	// The resolver state is worth knowing but not worth failing the refresh
	// over. A server whose file was read is reachable either way.
	active, _, statusErr := client.ServiceStatus(ctx)
	if statusErr != nil {
		active = false
		slog.Warn("cannot read the resolver status",
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
// The cached records stay. Old records with a warning next to them say more
// than an empty page, which is what dropping them would leave behind.
func (r *Refresher) markUnreachable(ctx context.Context, serverID int64, cause error) {
	if err := r.states.SetUnreachable(ctx, serverID, cause.Error()); err != nil {
		slog.Error("cannot record that a server is unreachable",
			"server", serverID, "error", err)
	}
}

// Start refreshes the fleet on a timer until the context is cancelled.
//
// The first pass runs straight away, because the panel is more useful with a
// filled cache than with an empty one and the first page load should not have
// to wait for the interval.
func (r *Refresher) Start(ctx context.Context, interval time.Duration) {
	go func() {
		r.run(ctx)

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				r.run(ctx)
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
		if !result.OK() {
			failed++
		}
	}
	slog.Info("fleet refreshed", "servers", len(results), "failed", failed)
}
