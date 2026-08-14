package fleet

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"

	"jbound/internal/audit"
	"jbound/internal/dnsfile"
	"jbound/internal/logging"
	"jbound/internal/server"
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
		result.Message = failureMessage(err)
		return result
	}

	content, digest, err := client.ReadHostEntries(ctx)
	if err != nil {
		result.Status = StatusFailed
		result.Message = failureMessage(err)
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
		result.Message = failureMessage(err)
		return result
	}
	w.keepPrevious(ctx, record.ID, content, digest)

	if err := client.WriteHostEntries(ctx, updated, digest); err != nil {
		result.Status = StatusFailed
		result.Message = failureMessage(err)
		return result
	}

	result.Status = StatusSuccess
	result.Message = "Record added"
	refillCtx, cancelRefill := afterChange(ctx)
	defer cancelRefill()

	if _, refreshErr := w.refresh.oneHeld(refillCtx, record.ID); refreshErr != nil {
		result.Message += ", but the cache could not be refreshed"
	}

	w.writeRepairAudit(ctx, actor, record, want, groupName)
	return result
}

// repairOperation works out what a server needs to hold the record.
//
// A server either holds the exact record or it does not, and the whole file is
// searched before it is called missing. No edit is produced: one name may
// legitimately hold several values, and an edit keyed on the name and the type
// would rewrite one of the others into this one and lose it.
//
// A value the row does not name is left alone. It is a row of its own in the
// same diff, with its own button, and the operator decides what happens to it.
func repairOperation(current []dnsfile.Record, want dnsfile.Record) (Operation, bool) {
	for _, record := range current {
		if keyOf(record) == keyOf(want) {
			return Operation{}, false
		}
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

// ErrNoSource marks a synchronisation with no usable source server.
var ErrNoSource = errors.New("no source server is chosen")

// ErrEmptySource marks a source whose file holds no record at all.
//
// Mirroring it would empty every other server of the target, and a source that
// reads as empty is far more often a broken read than a deliberate one.
var ErrEmptySource = errors.New("the source server holds no record")

// Mirror makes every server of the target hold what the source holds.
func (s *Service) Mirror(ctx context.Context, actor server.Actor, target Target,
	sourceID int64) (Report, error) {

	return s.writer.Mirror(ctx, actor, target, sourceID)
}

// Mirror copies the records of one server onto the rest of the target.
//
// It deletes as well as adds, so a target server ends up holding exactly what
// the source holds. Nothing happens on its own: the operator names the source
// on the settings page and starts the synchronisation by hand.
func (w *Writer) Mirror(ctx context.Context, actor server.Actor, target Target,
	sourceID int64) (Report, error) {

	if sourceID <= 0 {
		return Report{}, ErrNoSource
	}

	source, err := w.servers.Get(ctx, sourceID)
	if err != nil {
		return Report{}, err
	}
	if !source.Enabled || !source.Trusted() {
		return Report{}, ErrNoSource
	}

	// The source is read from the file rather than from the cache, for the
	// same reason a repair is: the cache is what showed the operator the
	// difference and by now it may be older than the server it describes.
	want, err := w.readSource(ctx, source)
	if err != nil {
		return Report{}, err
	}
	if len(want) == 0 {
		return Report{}, ErrEmptySource
	}

	targets, groupName, err := w.Targets(ctx, target)
	if err != nil {
		return Report{}, err
	}
	others := slices.DeleteFunc(targets, func(record server.Server) bool {
		return record.ID == source.ID
	})

	results := w.fanOut(ctx, others, func(ctx context.Context, record server.Server) ServerResult {
		return w.mirrorOne(ctx, actor, record, source, want, groupName)
	})

	return Report{Results: results, GroupName: groupName}, nil
}

// readSource reads the records of the server the mirror copies from.
func (w *Writer) readSource(ctx context.Context, source server.Server) ([]dnsfile.Record, error) {
	lock := w.lockFor(source.ID)
	lock.Lock()
	defer lock.Unlock()

	client, err := w.pool.Get(w.transportConfig(source))
	if err != nil {
		return nil, err
	}
	content, _, err := client.ReadHostEntries(ctx)
	if err != nil {
		return nil, err
	}
	return dnsfile.Parse(content), nil
}

// mirrorOne brings one server in line with the source.
func (w *Writer) mirrorOne(ctx context.Context, actor server.Actor,
	record, source server.Server, want []dnsfile.Record, groupName string) ServerResult {

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
		result.Message = failureMessage(err)
		return result
	}

	content, digest, err := client.ReadHostEntries(ctx)
	if err != nil {
		result.Status = StatusFailed
		result.Message = failureMessage(err)
		return result
	}

	added, removed := mirrorOperations(dnsfile.Parse(content), want)
	if len(added)+len(removed) == 0 {
		result.Status = StatusSkipped
		result.Message = "Already in line with " + source.Name
		return result
	}

	// Every change is applied in memory first. A server whose file the panel
	// cannot rewrite completely is left exactly as it was.
	updated := content
	for _, op := range slices.Concat(removed, added) {
		updated, err = op.apply(updated)
		if err != nil {
			logging.From(ctx).Error("cannot mirror a record",
				"server", record.Name, "source", source.Name,
				"operation", op.Kind, "fqdn", op.Record.FQDN, "error", err)

			result.Status = StatusFailed
			result.Message = failureMessage(err)
			return result
		}
	}

	// A mirror is the widest change the panel makes: it deletes as well as
	// adds, so the copy is what a target that was synchronised from the wrong
	// source is brought back with.
	w.keepPrevious(ctx, record.ID, content, digest)

	if err := client.WriteHostEntries(ctx, updated, digest); err != nil {
		logging.From(ctx).Error("cannot write a mirrored file",
			"server", record.Name, "source", source.Name, "error", err)

		result.Status = StatusFailed
		result.Message = failureMessage(err)
		return result
	}

	result.Status = StatusSuccess
	result.Message = fmt.Sprintf("%d added, %d removed", len(added), len(removed))
	refillCtx, cancelRefill := afterChange(ctx)
	defer cancelRefill()

	if _, refreshErr := w.refresh.oneHeld(refillCtx, record.ID); refreshErr != nil {
		logging.From(ctx).Error("cannot refresh the cache after a mirror",
			"server", record.Name, "error", refreshErr)
		result.Message += ", but the cache could not be refreshed"
	}

	w.writeMirrorAudit(ctx, actor, record, source, len(added), len(removed), groupName)
	return result
}

// mirrorOperations works out what one server needs to hold what the source
// holds, and nothing else.
//
// Removals come back separately from additions, because they have to run
// first: a name that changes value is a removal and an addition, and running
// them the other way round would leave the file holding both for a moment.
//
// No edit is produced. A delete followed by an add reaches the same file and
// behaves correctly for a name that legitimately holds several values, which
// an edit keyed on the name alone does not.
func mirrorOperations(current, want []dnsfile.Record) (added, removed []Operation) {
	wanted := map[recordKey]bool{}
	for _, record := range want {
		wanted[keyOf(record)] = true
	}

	held := map[recordKey]bool{}
	for _, record := range current {
		key := keyOf(record)
		if held[key] {
			// The file holds the same line twice. One delete removes every
			// matching line, so a second would find nothing.
			continue
		}
		held[key] = true

		if !wanted[key] {
			removed = append(removed, Operation{Kind: OpDelete, Record: record})
		}
	}

	seen := map[recordKey]bool{}
	for _, record := range want {
		key := keyOf(record)
		if held[key] || seen[key] {
			continue
		}
		seen[key] = true
		added = append(added, Operation{Kind: OpAdd, Record: record})
	}
	return added, removed
}

// writeMirrorAudit records one server's synchronisation.
func (w *Writer) writeMirrorAudit(ctx context.Context, actor server.Actor,
	record, source server.Server, added, removed int, groupName string) {

	details := fmt.Sprintf("Synchronised from %s: %d added, %d removed",
		source.Name, added, removed)
	if groupName != "" {
		details += " (group " + groupName + ")"
	}

	_ = w.audit.Write(ctx, audit.Entry{
		UID:        actor.UID,
		Username:   actor.Username,
		Action:     audit.ActionDiffSync,
		ServerID:   &record.ID,
		ServerName: record.Name,
		Details:    details,
		IPAddress:  actor.IPAddress,
	})
}
