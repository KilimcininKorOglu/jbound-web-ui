package fleet

import (
	"cmp"
	"context"
	"slices"

	"unbound-web/internal/audit"
	"unbound-web/internal/dnsfile"
	"unbound-web/internal/server"
)

// What one server holds for one record.
const (
	// CellPresent means the server holds exactly this record.
	CellPresent = "present"

	// CellMissing means the server holds nothing for this name and type.
	CellMissing = "missing"

	// CellDifferent means the server holds this name and type with another
	// value. It is the worst of the three: the two servers both answer, and
	// they answer differently.
	CellDifferent = "different"
)

// DiffServer is one column of the drift table.
type DiffServer struct {
	ID      int64
	Name    string
	Enabled bool

	// Stale marks a column drawn from a cache nobody refreshed recently. A
	// difference read from an old cache may already be gone, so the column
	// says as much rather than letting the reader assume otherwise.
	Stale bool
}

// DiffCell is what one server holds for one record.
type DiffCell struct {
	ServerID int64
	State    string

	// Value is what that server holds instead, filled for a difference only.
	Value string
}

// DiffRow is one record and what every server does with it.
type DiffRow struct {
	dnsfile.Record
	Cells []DiffCell
}

// Match reports whether every server holds this record.
func (r DiffRow) Match() bool {
	for _, cell := range r.Cells {
		if cell.State != CellPresent {
			return false
		}
	}
	return true
}

// Diff is the drift across the servers of one group.
type Diff struct {
	GroupName string
	Servers   []DiffServer
	Rows      []DiffRow

	// OnlyMismatches records which view produced these rows, so the control
	// and the table cannot disagree about what is being shown.
	OnlyMismatches bool
}

// Mismatches counts the records at least one server disagrees about.
func (d Diff) Mismatches() int {
	count := 0
	for _, row := range d.Rows {
		if !row.Match() {
			count++
		}
	}
	return count
}

// Stale names the columns drawn from an old cache.
func (d Diff) Stale() []string {
	var names []string
	for _, entry := range d.Servers {
		if entry.Stale {
			names = append(names, entry.Name)
		}
	}
	return names
}

// recordKey identifies one record across servers.
type recordKey struct {
	fqdn     string
	kind     string
	value    string
	priority int
}

// nameKey identifies a name and a type, which is what a difference is about.
type nameKey struct {
	fqdn string
	kind string
}

// BuildDiff merges what every server holds into one table.
//
// Each distinct record becomes a row. A server that holds the same name and
// type with another value is marked as different rather than missing, because
// the two cases need different repairs and read differently to an operator.
func BuildDiff(servers []DiffServer, byServer map[int64][]dnsfile.Record) Diff {
	rows := map[recordKey]dnsfile.Record{}

	// held answers "does this server have this exact record", and byName
	// answers "what does it hold for this name and type instead".
	held := map[int64]map[recordKey]bool{}
	byName := map[int64]map[nameKey]dnsfile.Record{}

	for _, entry := range servers {
		held[entry.ID] = map[recordKey]bool{}
		byName[entry.ID] = map[nameKey]dnsfile.Record{}

		for _, record := range byServer[entry.ID] {
			key := keyOf(record)
			rows[key] = record
			held[entry.ID][key] = true

			// The first entry wins. A file holding the same name and type
			// twice is drift of its own, and the row for the second value
			// still shows this server as different.
			name := nameKey{record.FQDN, record.Type}
			if _, seen := byName[entry.ID][name]; !seen {
				byName[entry.ID][name] = record
			}
		}
	}

	diff := Diff{Servers: servers, Rows: make([]DiffRow, 0, len(rows))}
	for key, record := range rows {
		row := DiffRow{Record: record, Cells: make([]DiffCell, 0, len(servers))}

		for _, entry := range servers {
			cell := DiffCell{ServerID: entry.ID, State: CellMissing}

			switch other, has := byName[entry.ID][nameKey{key.fqdn, key.kind}]; {
			case held[entry.ID][key]:
				cell.State = CellPresent
			case has:
				cell.State = CellDifferent
				cell.Value = other.Value
			}
			row.Cells = append(row.Cells, cell)
		}
		diff.Rows = append(diff.Rows, row)
	}

	// The map gave no order, and a table that reorders itself between two
	// loads is unreadable.
	slices.SortFunc(diff.Rows, func(a, b DiffRow) int {
		return cmp.Or(
			cmp.Compare(a.FQDN, b.FQDN),
			cmp.Compare(a.Type, b.Type),
			cmp.Compare(a.Value, b.Value),
			cmp.Compare(a.Priority, b.Priority),
		)
	})
	return diff
}

func keyOf(record dnsfile.Record) recordKey {
	return recordKey{record.FQDN, record.Type, record.Value, record.Priority}
}

// OnlyMismatches drops the records every server agrees about.
//
// It is the default view. A fleet in good shape produces a page of rows that
// all say the same thing, and the few that do not are the point.
func (d Diff) FilterMismatches() Diff {
	filtered := make([]DiffRow, 0, len(d.Rows))
	for _, row := range d.Rows {
		if !row.Match() {
			filtered = append(filtered, row)
		}
	}

	d.Rows = filtered
	d.OnlyMismatches = true
	return d
}

// Diff builds the drift table of one target.
func (s *Service) Diff(ctx context.Context, query Query, onlyMismatches bool) (Diff, error) {
	target := Target{Scope: query.Scope, ServerID: query.ServerID, GroupID: query.GroupID}

	members, groupName, err := s.writer.Members(ctx, target)
	if err != nil {
		return Diff{}, err
	}

	byServer, err := s.records.ByServer(ctx, query)
	if err != nil {
		return Diff{}, err
	}

	states, err := s.states.List(ctx)
	if err != nil {
		return Diff{}, err
	}

	now := s.now()
	columns := make([]DiffServer, 0, len(members))
	for _, record := range members {
		state := states[record.ID]
		columns = append(columns, DiffServer{
			ID:      record.ID,
			Name:    record.Name,
			Enabled: record.Enabled,
			Stale:   state.Stale(now, s.staleAfter()),
		})
	}

	diff := BuildDiff(columns, byServer)
	diff.GroupName = groupName
	if onlyMismatches {
		diff = diff.FilterMismatches()
	}
	return diff, nil
}

// Repair writes one record to every server that lacks it or holds it with
// another value.
func (s *Service) Repair(ctx context.Context, actor server.Actor, target Target,
	record dnsfile.Record) (Report, error) {

	return s.writer.Repair(ctx, actor, target, record)
}

// Repair brings one record into line across a target.
//
// Nothing happens on its own. The operator starts a repair for one record, and
// the panel never syncs a fleet behind their back.
func (w *Writer) Repair(ctx context.Context, actor server.Actor, target Target,
	want dnsfile.Record) (Report, error) {

	if err := want.Validate(); err != nil {
		return Report{}, err
	}

	targets, groupName, err := w.Targets(ctx, target)
	if err != nil {
		return Report{}, err
	}

	results := w.fanOut(ctx, targets, func(ctx context.Context, record server.Server) ServerResult {
		return w.repairOne(ctx, actor, record, want, groupName)
	})

	return Report{Results: results, GroupName: groupName}, nil
}

// repairOne decides what one server needs and does it.
//
// The decision comes from the file rather than from the cache. The cache is
// what showed the operator the difference, and by now it may be older than the
// server it describes.
func (w *Writer) repairOne(ctx context.Context, actor server.Actor,
	record server.Server, want dnsfile.Record, groupName string) ServerResult {

	if refusal, ok := refuse(record); ok {
		return refusal
	}
	result := ServerResult{ServerID: record.ID, ServerName: record.Name}

	lock := w.lockFor(record.ID)
	lock.Lock()
	defer lock.Unlock()

	client, err := w.pool.Get(w.transportConfig(record))
	if err != nil {
		result.Status = StatusFailed
		result.Message = err.Error()
		return result
	}

	content, digest, err := client.ReadHostEntries(ctx)
	if err != nil {
		result.Status = StatusFailed
		result.Message = err.Error()
		return result
	}

	op, needed := repairOperation(dnsfile.Parse(content), want)
	if !needed {
		result.Status = StatusSkipped
		result.Message = "Already in place"
		return result
	}

	updated, err := op.apply(content)
	if err != nil {
		result.Status = StatusFailed
		result.Message = err.Error()
		return result
	}
	if err := client.WriteHostEntries(ctx, updated, digest); err != nil {
		result.Status = StatusFailed
		result.Message = err.Error()
		return result
	}

	result.Status = StatusSuccess
	if op.Kind == OpAdd {
		result.Message = "Record added"
	} else {
		result.Message = "Value corrected"
	}
	if _, refreshErr := w.refresh.One(ctx, record.ID); refreshErr != nil {
		result.Message += ", but the cache could not be refreshed"
	}

	w.writeRepairAudit(ctx, actor, record, want, groupName)
	return result
}

// repairOperation works out what a server needs to hold the record.
func repairOperation(current []dnsfile.Record, want dnsfile.Record) (Operation, bool) {
	for _, record := range current {
		if record.FQDN != want.FQDN || record.Type != want.Type {
			continue
		}
		if record.Value == want.Value && record.Priority == want.Priority {
			return Operation{}, false
		}
		return Operation{Kind: OpEdit, Old: record, Record: want}, true
	}
	return Operation{Kind: OpAdd, Record: want}, true
}

// writeRepairAudit records one server's repair.
func (w *Writer) writeRepairAudit(ctx context.Context, actor server.Actor,
	record server.Server, want dnsfile.Record, groupName string) {

	details := "Repaired " + want.Type + " " + want.FQDN + " -> " + want.Value +
		" on " + record.Name
	if groupName != "" {
		details += " (group " + groupName + ")"
	}

	serverID := record.ID
	_ = w.audit.Write(ctx, audit.Entry{
		UID:        actor.UID,
		Username:   actor.Username,
		ServerID:   &serverID,
		ServerName: record.Name,
		Action:     audit.ActionDiffRepair,
		Details:    details,
		IPAddress:  actor.IPAddress,
	})
}
