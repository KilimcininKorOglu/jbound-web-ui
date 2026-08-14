package fleet

import (
	"context"
	"slices"
	"time"

	"unbound-web/internal/audit"
	"unbound-web/internal/dnsfile"
	"unbound-web/internal/server"
)

// RecordLister reads the cached records.
//
// A page feeds the record table. The whole set feeds the diff, which compares
// files rather than pages of them.
type RecordLister interface {
	List(ctx context.Context, query Query) (Page, error)
	ByServer(ctx context.Context, query Query) (map[int64][]dnsfile.Record, error)
}

// Service is what the HTTP layer talks to.
//
// It composes the three things a record page needs: the cached view, the
// writer that changes the files, and the refresher that fills the cache again.
type Service struct {
	records RecordLister
	states  StateStore
	writer  *Writer
	refresh *Refresher
	queries NameQuerier
	audit   *audit.Logger

	staleAfter func() time.Duration
	now        func() time.Time
}

// NewService builds the record service.
func NewService(records RecordLister, states StateStore, writer *Writer,
	refresh *Refresher, queries NameQuerier, auditLog *audit.Logger,
	staleAfter func() time.Duration) *Service {

	return &Service{
		records:    records,
		states:     states,
		writer:     writer,
		refresh:    refresh,
		queries:    queries,
		audit:      auditLog,
		staleAfter: staleAfter,
		now:        time.Now,
	}
}

// Page returns one page of records with the stale rows marked.
//
// A stale row is shown rather than hidden. An empty page would say less than
// old records with a warning next to them.
//
// The page also carries how many servers the target covers, because a row
// reports the servers that hold it and that count is the denominator.
func (s *Service) Page(ctx context.Context, query Query) (Page, error) {
	// The scope is read here as well as in the store, so an empty query counts
	// the whole fleet rather than reaching Members with no scope at all.
	query.Normalise()

	page, err := s.records.List(ctx, query)
	if err != nil {
		return Page{}, err
	}

	states, err := s.states.List(ctx)
	if err != nil {
		return Page{}, err
	}

	members, _, err := s.writer.Members(ctx,
		Target{Scope: query.Scope, ServerID: query.ServerID, GroupID: query.GroupID})
	if err != nil {
		return Page{}, err
	}
	// A disabled server is left out of every operation, so counting it would
	// make a record every working server holds read as incomplete.
	enabled := make(map[int64]string, len(members))
	for _, record := range members {
		if record.Enabled {
			enabled[record.ID] = record.Name
			page.TargetServers++
		}
	}

	now := s.now()
	for i := range page.Rows {
		// The holders and the denominator have to describe the same set of
		// servers. A disabled server keeps its cached rows for ever, because
		// a refresh pass only reads the enabled ones, so a record it still
		// holds would otherwise fill the place of an enabled server that
		// lacks it and hide the drift behind a complete looking count.
		keepEnabledHolders(&page.Rows[i], enabled)

		for _, id := range page.Rows[i].Holders {
			if states[id].Stale(now, s.staleAfter()) {
				page.Rows[i].Stale = true
				break
			}
		}
	}
	return page, nil
}

// keepEnabledHolders drops the holders that are not part of the target.
//
// The names are taken from the server records rather than from the cache row,
// which is the same source the target list is built from, and the two slices
// are rebuilt together so they cannot drift apart.
func keepEnabledHolders(row *Row, enabled map[int64]string) {
	holders := make([]int64, 0, len(row.Holders))
	names := make([]string, 0, len(row.Holders))

	for _, id := range row.Holders {
		name, ok := enabled[id]
		if !ok {
			continue
		}
		holders = append(holders, id)
		names = append(names, name)
	}
	slices.Sort(names)

	row.Holders = holders
	row.HolderNames = names
}

// Stale reports which of the given servers hold a cache the panel no longer
// trusts, so a page can name them once instead of per row.
func (s *Service) Stale(ctx context.Context) (map[int64]bool, error) {
	states, err := s.states.List(ctx)
	if err != nil {
		return nil, err
	}

	now := s.now()
	stale := map[int64]bool{}
	for id, state := range states {
		stale[id] = state.Stale(now, s.staleAfter())
	}
	return stale, nil
}

// States returns what the panel last saw on every server it has read.
//
// The servers page lists disabled servers as well, which a target based status
// leaves out, so it reads the states directly.
func (s *Service) States(ctx context.Context) (map[int64]State, error) {
	return s.states.List(ctx)
}

// Status reports where the servers of one target stand.
//
// It answers for the whole fleet as well, because the records page keeps its
// status bar next to a listing that may cover every server.
func (s *Service) Status(ctx context.Context, query Query) (Status, error) {
	target := Target{Scope: query.Scope, ServerID: query.ServerID, GroupID: query.GroupID}

	members, groupName, err := s.writer.Members(ctx, target)
	if err != nil {
		return Status{}, err
	}

	states, err := s.states.List(ctx)
	if err != nil {
		return Status{}, err
	}

	now := s.now()
	status := Status{
		GroupName: groupName,
		CanApply:  query.Scope != ScopeAll,
		Servers:   make([]ServerStatus, 0, len(members)),
	}

	for _, record := range members {
		state := states[record.ID]
		status.Servers = append(status.Servers, ServerStatus{
			ServerID:      record.ID,
			Name:          record.Name,
			Enabled:       record.Enabled,
			Pending:       state.Pending(),
			Stale:         state.Stale(now, s.staleAfter()),
			Reachable:     state.Reachable,
			UnboundActive: state.UnboundActive,
			LastError:     state.LastError,
		})
	}
	return status, nil
}

// Reload asks the resolvers of one target to re-read their files.
func (s *Service) Reload(ctx context.Context, actor server.Actor,
	target Target) (Report, error) {

	return s.writer.Reload(ctx, actor, target)
}

// Apply runs one record change across a target.
func (s *Service) Apply(ctx context.Context, actor server.Actor,
	target Target, op Operation) (Report, error) {

	return s.writer.Apply(ctx, actor, target, op)
}

// Refresh fills the cache of every enabled server.
func (s *Service) Refresh(ctx context.Context) ([]Result, error) {
	return s.refresh.All(ctx)
}

// RefreshOne fills the cache of a single server.
func (s *Service) RefreshOne(ctx context.Context, serverID int64) (Result, error) {
	return s.refresh.One(ctx, serverID)
}
