package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"unbound-web/internal/dnsfile"
	"unbound-web/internal/fleet"
)

// Records stores the cached view of every server's host entries file.
type Records struct {
	db *sql.DB
}

// NewRecords builds the record cache store.
func NewRecords(db *sql.DB) *Records { return &Records{db: db} }

// Replace swaps the cached records of one server.
//
// The whole set is replaced in one transaction rather than merged. The file is
// authoritative, so anything the panel still holds afterwards would be a row
// the server no longer has.
func (r *Records) Replace(ctx context.Context, serverID int64, records []dnsfile.Record) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("cannot start the transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx,
		"DELETE FROM record_cache WHERE server_id = ?", serverID); err != nil {
		return fmt.Errorf("cannot clear the cached records: %w", err)
	}

	const insert = `
INSERT INTO record_cache (server_id, line, fqdn, type, value, priority, raw)
VALUES (?, ?, ?, ?, ?, ?, ?)`

	for _, record := range records {
		_, err := tx.ExecContext(ctx, insert, serverID, record.Line,
			record.FQDN, record.Type, record.Value, record.Priority, record.Raw)
		if err != nil {
			return fmt.Errorf("cannot cache the record on line %d: %w", record.Line, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("cannot commit the cached records: %w", err)
	}
	return nil
}

// Clear drops the cached records of one server.
func (r *Records) Clear(ctx context.Context, serverID int64) error {
	if _, err := r.db.ExecContext(ctx,
		"DELETE FROM record_cache WHERE server_id = ?", serverID); err != nil {
		return fmt.Errorf("cannot clear the cached records: %w", err)
	}
	return nil
}

// List returns one page of cached records.
//
// The order is by server, name and type. The order of a file says nothing
// once several servers are shown at once.
func (r *Records) List(ctx context.Context, query fleet.Query) (fleet.Page, error) {
	query.Normalise()

	where, args := recordFilter(query)

	var total int
	if err := r.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM record_cache c JOIN servers s ON s.id = c.server_id"+where,
		args...).Scan(&total); err != nil {
		return fleet.Page{}, fmt.Errorf("cannot count the cached records: %w", err)
	}

	page := fleet.NewPage(query, total)
	if total == 0 {
		return page, nil
	}

	rows, err := r.db.QueryContext(ctx, `
SELECT c.server_id, s.name, c.line, c.fqdn, c.type, c.value, c.priority, c.raw
  FROM record_cache c
  JOIN servers s ON s.id = c.server_id`+where+`
 ORDER BY s.name, c.fqdn, c.type, c.value
 LIMIT ? OFFSET ?`, append(args, page.PerPage, page.Offset())...)
	if err != nil {
		return fleet.Page{}, fmt.Errorf("cannot read the cached records: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var row fleet.Row
		err := rows.Scan(&row.ServerID, &row.ServerName, &row.Line,
			&row.FQDN, &row.Type, &row.Value, &row.Priority, &row.Raw)
		if err != nil {
			return fleet.Page{}, fmt.Errorf("cannot read a cached record: %w", err)
		}
		page.Rows = append(page.Rows, row)
	}
	if err := rows.Err(); err != nil {
		return fleet.Page{}, fmt.Errorf("cannot read the cached record rows: %w", err)
	}
	return page, nil
}

// ByServer returns every cached record of a target, keyed by server.
//
// The diff compares whole files rather than a page of them, so this one has no
// limit. It is bounded by the target instead: a diff runs against a group.
func (r *Records) ByServer(ctx context.Context, query fleet.Query) (map[int64][]dnsfile.Record, error) {
	query.Normalise()
	where, args := recordFilter(query)

	rows, err := r.db.QueryContext(ctx, `
SELECT c.server_id, c.line, c.fqdn, c.type, c.value, c.priority, c.raw
  FROM record_cache c
  JOIN servers s ON s.id = c.server_id`+where+`
 ORDER BY c.fqdn, c.type, c.value`, args...)
	if err != nil {
		return nil, fmt.Errorf("cannot read the cached records: %w", err)
	}
	defer rows.Close()

	byServer := map[int64][]dnsfile.Record{}
	for rows.Next() {
		var (
			serverID int64
			record   dnsfile.Record
		)
		err := rows.Scan(&serverID, &record.Line, &record.FQDN,
			&record.Type, &record.Value, &record.Priority, &record.Raw)
		if err != nil {
			return nil, fmt.Errorf("cannot read a cached record: %w", err)
		}
		byServer[serverID] = append(byServer[serverID], record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cannot read the cached record rows: %w", err)
	}
	return byServer, nil
}

// recordFilter builds the shared WHERE clause of the count and the page, so
// the two can never disagree about which rows the page is counted from.
func recordFilter(query fleet.Query) (string, []any) {
	var (
		clauses []string
		args    []any
	)

	switch query.Scope {
	case fleet.ScopeServer:
		clauses = append(clauses, "c.server_id = ?")
		args = append(args, query.ServerID)
	case fleet.ScopeGroup:
		clauses = append(clauses,
			"c.server_id IN (SELECT server_id FROM server_group_members WHERE group_id = ?)")
		args = append(args, query.GroupID)
	}

	if search := strings.TrimSpace(query.Search); search != "" {
		// The search is a substring match on either column.
		pattern := "%" + escapeLike(strings.ToLower(search)) + "%"
		clauses = append(clauses,
			`(LOWER(c.fqdn) LIKE ? ESCAPE '\' OR LOWER(c.value) LIKE ? ESCAPE '\')`)
		args = append(args, pattern, pattern)
	}

	if query.Type != "" {
		clauses = append(clauses, "c.type = ?")
		args = append(args, query.Type)
	}

	if len(clauses) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

// escapeLike neutralises the wildcards of a LIKE pattern.
//
// Without it, a search for "a_b" would match "axb" and a search for "%" would
// match everything, which reads as a broken filter rather than as a search.
func escapeLike(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`)
	return replacer.Replace(value)
}

// States stores what the panel knows about each server's file.
type States struct {
	db *sql.DB
}

// NewStates builds the per server state store.
func NewStates(db *sql.DB) *States { return &States{db: db} }

const stateColumns = `
    server_id, file_sha256, applied_sha256, fetched_at,
    reachable, unbound_active, record_count, last_error`

// SetFetched records a successful read.
func (s *States) SetFetched(ctx context.Context, state fleet.State) error {
	const query = `
INSERT INTO server_state
    (server_id, file_sha256, fetched_at, reachable, unbound_active, record_count, last_error)
VALUES (?, ?, ?, 1, ?, ?, '')
ON CONFLICT (server_id) DO UPDATE SET
    file_sha256    = excluded.file_sha256,
    fetched_at     = excluded.fetched_at,
    reachable      = 1,
    unbound_active = excluded.unbound_active,
    record_count   = excluded.record_count,
    last_error     = ''`

	var fetched any
	if state.FetchedAt != nil {
		fetched = formatTime(*state.FetchedAt)
	}

	_, err := s.db.ExecContext(ctx, query, state.ServerID, state.FileSHA256,
		fetched, boolToInt(state.UnboundActive), state.RecordCount)
	if err != nil {
		return fmt.Errorf("cannot record the server state: %w", err)
	}
	return nil
}

// SetUnreachable records a failed read.
//
// The cached records and the digests are left alone. Old records with a
// warning next to them say more than an empty page, and the digest is still
// what the panel last saw on that server.
func (s *States) SetUnreachable(ctx context.Context, serverID int64, failure string) error {
	const query = `
INSERT INTO server_state (server_id, reachable, unbound_active, last_error)
VALUES (?, 0, 0, ?)
ON CONFLICT (server_id) DO UPDATE SET
    reachable      = 0,
    unbound_active = 0,
    last_error     = excluded.last_error`

	if _, err := s.db.ExecContext(ctx, query, serverID, failure); err != nil {
		return fmt.Errorf("cannot record the server state: %w", err)
	}
	return nil
}

// SetApplied records the digest the resolver has loaded.
func (s *States) SetApplied(ctx context.Context, serverID int64, digest string) error {
	const query = `
INSERT INTO server_state (server_id, applied_sha256)
VALUES (?, ?)
ON CONFLICT (server_id) DO UPDATE SET applied_sha256 = excluded.applied_sha256`

	if _, err := s.db.ExecContext(ctx, query, serverID, digest); err != nil {
		return fmt.Errorf("cannot record the applied digest: %w", err)
	}
	return nil
}

// Get reads the state of one server.
func (s *States) Get(ctx context.Context, serverID int64) (fleet.State, error) {
	row := s.db.QueryRowContext(ctx,
		"SELECT"+stateColumns+" FROM server_state WHERE server_id = ?", serverID)

	state, err := scanState(row)
	if errors.Is(err, sql.ErrNoRows) {
		// A server nobody has read yet has no row. That is a state in its own
		// right rather than a missing record, so it reads as never fetched.
		return fleet.State{ServerID: serverID}, nil
	}
	if err != nil {
		return fleet.State{}, fmt.Errorf("cannot read the server state: %w", err)
	}
	return state, nil
}

// List returns the state of every server that has one, keyed by server.
func (s *States) List(ctx context.Context) (map[int64]fleet.State, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT"+stateColumns+" FROM server_state")
	if err != nil {
		return nil, fmt.Errorf("cannot list the server states: %w", err)
	}
	defer rows.Close()

	states := map[int64]fleet.State{}
	for rows.Next() {
		state, err := scanState(rows)
		if err != nil {
			return nil, fmt.Errorf("cannot read a server state: %w", err)
		}
		states[state.ServerID] = state
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cannot read the server state rows: %w", err)
	}
	return states, nil
}

func scanState(row scanner) (fleet.State, error) {
	var (
		state             fleet.State
		reachable, active int
		fetched           sql.NullString
		parsedFetched     time.Time
		errFetch, errScan error
	)

	errScan = row.Scan(&state.ServerID, &state.FileSHA256, &state.AppliedSHA256,
		&fetched, &reachable, &active, &state.RecordCount, &state.LastError)
	if errScan != nil {
		return fleet.State{}, errScan
	}

	state.Reachable = reachable == 1
	state.UnboundActive = active == 1

	if fetched.Valid && fetched.String != "" {
		if parsedFetched, errFetch = parseTime(fetched.String); errFetch != nil {
			return fleet.State{}, errFetch
		}
		state.FetchedAt = &parsedFetched
	}
	return state, nil
}
