package fleet

import (
	"context"
	"errors"
	"strings"
	"testing"

	"jbound/internal/audit"
	"jbound/internal/dnsfile"
	"jbound/internal/transport"
)

func record(fqdn, kind, value string) dnsfile.Record {
	return dnsfile.Record{FQDN: fqdn, Type: kind, Value: value}
}

func columns(names ...string) []DiffServer {
	servers := make([]DiffServer, 0, len(names))
	for i, name := range names {
		servers = append(servers, DiffServer{ID: int64(i + 1), Name: name, Enabled: true})
	}
	return servers
}

// cell returns what one server does with one row.
func cell(t *testing.T, diff Diff, fqdn string, serverID int64) DiffCell {
	t.Helper()

	for _, row := range diff.Rows {
		if row.FQDN != fqdn {
			continue
		}
		for _, entry := range row.Cells {
			if entry.ServerID == serverID {
				return entry
			}
		}
	}
	t.Fatalf("no cell for %s on server %d", fqdn, serverID)
	return DiffCell{}
}

func TestARecordEveryServerHoldsIsAMatch(t *testing.T) {
	diff := BuildDiff(columns("dns1", "dns2"), map[int64][]dnsfile.Record{
		1: {record("www.example.net", "A", "192.0.2.10")},
		2: {record("www.example.net", "A", "192.0.2.10")},
	})

	if len(diff.Rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(diff.Rows))
	}
	if !diff.Rows[0].Match() {
		t.Errorf("got %+v", diff.Rows[0].Cells)
	}
	if diff.Mismatches() != 0 {
		t.Errorf("mismatches = %d", diff.Mismatches())
	}
}

func TestARecordOneServerLacksIsAMismatch(t *testing.T) {
	diff := BuildDiff(columns("dns1", "dns2"), map[int64][]dnsfile.Record{
		1: {record("www.example.net", "A", "192.0.2.10")},
		2: {},
	})

	if diff.Mismatches() != 1 {
		t.Fatalf("mismatches = %d, want 1", diff.Mismatches())
	}
	if state := cell(t, diff, "www.example.net", 2).State; state != CellMissing {
		t.Errorf("state = %q, want missing", state)
	}
}

func TestTheSameNameWithAnotherValueReadsAsDifferent(t *testing.T) {
	// This is the worst of the three. Both servers answer, and they answer
	// differently, so a client gets one or the other.
	diff := BuildDiff(columns("dns1", "dns2"), map[int64][]dnsfile.Record{
		1: {record("www.example.net", "A", "192.0.2.10")},
		2: {record("www.example.net", "A", "192.0.2.99")},
	})

	entry := cell(t, diff, "www.example.net", 2)
	if entry.State != CellDifferent {
		t.Fatalf("state = %q, want different", entry.State)
	}
	if entry.Value != "192.0.2.99" {
		t.Errorf("the cell does not carry what that server holds: %q", entry.Value)
	}
}

func TestADifferentTypeIsItsOwnRecord(t *testing.T) {
	// A name with an A record on one server and an AAAA on the other is two
	// records, not one difference.
	diff := BuildDiff(columns("dns1", "dns2"), map[int64][]dnsfile.Record{
		1: {record("www.example.net", "A", "192.0.2.10")},
		2: {record("www.example.net", "AAAA", "2001:db8::1")},
	})

	if len(diff.Rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(diff.Rows))
	}
	for _, row := range diff.Rows {
		for _, entry := range row.Cells {
			if entry.State == CellDifferent {
				t.Errorf("%s on server %d reads as a difference", row.Type, entry.ServerID)
			}
		}
	}
}

func TestTheMismatchFilterDropsWhatEverybodyAgreesAbout(t *testing.T) {
	diff := BuildDiff(columns("dns1", "dns2"), map[int64][]dnsfile.Record{
		1: {record("www.example.net", "A", "192.0.2.10"), record("odd.example.net", "A", "192.0.2.11")},
		2: {record("www.example.net", "A", "192.0.2.10")},
	})

	filtered := diff.FilterMismatches()
	if len(filtered.Rows) != 1 || filtered.Rows[0].FQDN != "odd.example.net" {
		t.Fatalf("got %+v", filtered.Rows)
	}
	if !filtered.OnlyMismatches {
		t.Error("the filtered diff does not say which view produced it")
	}
}

func TestTheRowsKeepTheirOrder(t *testing.T) {
	// The rows come out of a map, and a table that reorders itself between two
	// loads cannot be read.
	first := BuildDiff(columns("dns1"), map[int64][]dnsfile.Record{
		1: {
			record("c.example.net", "A", "192.0.2.3"),
			record("a.example.net", "A", "192.0.2.1"),
			record("b.example.net", "A", "192.0.2.2"),
		},
	})

	want := []string{"a.example.net", "b.example.net", "c.example.net"}
	for i, row := range first.Rows {
		if row.FQDN != want[i] {
			t.Fatalf("row %d is %s, want %s", i, row.FQDN, want[i])
		}
	}
}

func TestTheDiffNamesTheColumnsItCannotVouchFor(t *testing.T) {
	servers := columns("dns1", "dns2")
	servers[1].Stale = true

	diff := BuildDiff(servers, map[int64][]dnsfile.Record{})
	stale := diff.Stale()
	if len(stale) != 1 || stale[0] != "dns2" {
		t.Errorf("stale = %v", stale)
	}
}

// --- Repair ----------------------------------------------------------------

func TestARepairAddsTheRecordWhereItIsMissing(t *testing.T) {
	h := newWriteHarness(t, 3)
	h.targets["dns2"].content = []byte("# empty on purpose\n")

	want := record("www.example.net", "A", "192.0.2.10")
	report, err := h.writer.Repair(context.Background(), testActor(), groupTarget(), want)
	if err != nil {
		t.Fatalf("Repair returned an error: %v", err)
	}

	success, failed, skipped := report.Counts()
	if success != 1 || failed != 0 || skipped != 2 {
		t.Fatalf("counts = %d/%d/%d, want one repair and two servers left alone",
			success, failed, skipped)
	}
	if !strings.Contains(h.targets["dns2"].file(), "192.0.2.10") {
		t.Errorf("the record was not written:\n%s", h.targets["dns2"].file())
	}
}

func TestARepairKeepsEveryOtherValueOfTheSameName(t *testing.T) {
	// The row names one exact record. A second value of the same name is a row
	// of its own, so a repair that rewrote it would destroy a live record the
	// operator never named.
	h := newWriteHarness(t, 2)
	h.targets["dns2"].content = []byte(
		"local-data: \"www.example.net. A 192.0.2.99\"\n")

	want := record("www.example.net", "A", "192.0.2.10")
	if _, err := h.writer.Repair(context.Background(), testActor(), groupTarget(), want); err != nil {
		t.Fatalf("Repair returned an error: %v", err)
	}

	file := h.targets["dns2"].file()
	if !strings.Contains(file, "192.0.2.99") {
		t.Errorf("the other value of the name was lost:\n%s", file)
	}
	if !strings.Contains(file, "192.0.2.10") {
		t.Errorf("the missing record was not added:\n%s", file)
	}
}

func TestARepairSkipsAServerThatHoldsTheRecordBehindAnotherValue(t *testing.T) {
	// The wanted record is the second line. A search that stops at the first
	// name and type match would call it missing and rewrite the first line.
	h := newWriteHarness(t, 1)
	h.targets["dns1"].content = []byte(
		"local-data: \"www.example.net. A 192.0.2.99\"\n" +
			"local-data: \"www.example.net. A 192.0.2.10\"\n")

	want := record("www.example.net", "A", "192.0.2.10")
	report, err := h.writer.Repair(context.Background(), testActor(), groupTarget(), want)
	if err != nil {
		t.Fatalf("Repair returned an error: %v", err)
	}

	if report.Results[0].Status != StatusSkipped {
		t.Fatalf("got %+v, want the server left alone", report.Results[0])
	}
	if len(h.targets["dns1"].expectations) != 0 {
		t.Errorf("a server that already held the record was written to:\n%s",
			h.targets["dns1"].file())
	}
}

func TestARepairLeavesAServerThatAlreadyAgrees(t *testing.T) {
	h := newWriteHarness(t, 1)

	want := record("www.example.net", "A", "192.0.2.10")
	report, err := h.writer.Repair(context.Background(), testActor(), groupTarget(), want)
	if err != nil {
		t.Fatalf("Repair returned an error: %v", err)
	}
	if report.Results[0].Status != StatusSkipped {
		t.Fatalf("got %+v", report.Results[0])
	}
	if len(h.targets["dns1"].expectations) != 0 {
		t.Error("a server that already agreed was written to")
	}
}

func TestARepairDecidesFromTheFileRatherThanTheCache(t *testing.T) {
	// The cache is what showed the operator the difference. By the time they
	// press repair it may be older than the server it describes.
	h := newWriteHarness(t, 1)

	// The cache holds nothing for this server while the file already holds the
	// record, so a repair that trusted the cache would write it a second time.
	want := record("www.example.net", "A", "192.0.2.10")
	report, err := h.writer.Repair(context.Background(), testActor(), groupTarget(), want)
	if err != nil {
		t.Fatalf("Repair returned an error: %v", err)
	}

	if report.Results[0].Status != StatusSkipped {
		t.Fatalf("got %+v, want the server left alone", report.Results[0])
	}
	file := h.targets["dns1"].file()
	if strings.Count(file, "192.0.2.10") != 1 {
		t.Errorf("the repair wrote a record the file already held:\n%s", file)
	}
}

func TestAnInvalidRecordIsNotRepairedAnywhere(t *testing.T) {
	h := newWriteHarness(t, 2)

	_, err := h.writer.Repair(context.Background(), testActor(), groupTarget(),
		record("not a name", "A", "192.0.2.10"))
	if err == nil {
		t.Fatal("an invalid record was accepted for repair")
	}
	for name, target := range h.targets {
		if len(target.expectations) != 0 {
			t.Errorf("%s was written to for a refused record", name)
		}
	}
}

func TestARepairIsAuditedPerServer(t *testing.T) {
	h := newWriteHarness(t, 2)
	h.targets["dns2"].content = []byte("# empty on purpose\n")

	want := record("www.example.net", "A", "192.0.2.10")
	if _, err := h.writer.Repair(context.Background(), testActor(), groupTarget(), want); err != nil {
		t.Fatalf("Repair returned an error: %v", err)
	}

	entries := h.audit.all()
	if len(entries) != 1 {
		t.Fatalf("got %d audit rows, want one per server that changed", len(entries))
	}
	if entries[0].Action != audit.ActionDiffRepair {
		t.Errorf("action = %q", entries[0].Action)
	}
	if !strings.HasPrefix(entries[0].Details, "Repaired A www.example.net -> 192.0.2.10 on dns2") {
		t.Errorf("details = %q", entries[0].Details)
	}
}

func TestMirrorOperationsRemoveBeforeTheyAdd(t *testing.T) {
	// A name whose value changed is a removal and an addition. Running them
	// the other way round would leave the file holding both for a moment.
	current := []dnsfile.Record{
		{FQDN: "www.example.net", Type: "A", Value: "192.0.2.10"},
		{FQDN: "old.example.net", Type: "A", Value: "192.0.2.99"},
	}
	want := []dnsfile.Record{
		{FQDN: "www.example.net", Type: "A", Value: "192.0.2.10"},
		{FQDN: "new.example.net", Type: "A", Value: "192.0.2.11"},
	}

	added, removed := mirrorOperations(current, want)

	if len(removed) != 1 || removed[0].Record.FQDN != "old.example.net" {
		t.Errorf("removals = %+v, want the record the source does not hold", removed)
	}
	if len(added) != 1 || added[0].Record.FQDN != "new.example.net" {
		t.Errorf("additions = %+v, want the record the source holds", added)
	}
}

func TestMirrorOperationsLeaveAnIdenticalFileAlone(t *testing.T) {
	records := []dnsfile.Record{
		{FQDN: "www.example.net", Type: "A", Value: "192.0.2.10"},
		{FQDN: "mail.example.net", Type: "MX", Value: "mx1.example.net", Priority: 20},
	}

	added, removed := mirrorOperations(records, records)
	if len(added) != 0 || len(removed) != 0 {
		t.Errorf("got %d additions and %d removals, want none", len(added), len(removed))
	}
}

func TestMirrorOperationsKeepEveryValueOfOneName(t *testing.T) {
	// A round robin name holds several values. Matching on the name alone
	// would call the second value a difference and destroy it.
	current := []dnsfile.Record{
		{FQDN: "rr.example.net", Type: "A", Value: "192.0.2.1"},
	}
	want := []dnsfile.Record{
		{FQDN: "rr.example.net", Type: "A", Value: "192.0.2.1"},
		{FQDN: "rr.example.net", Type: "A", Value: "192.0.2.2"},
	}

	added, removed := mirrorOperations(current, want)
	if len(removed) != 0 {
		t.Errorf("removals = %+v, want none", removed)
	}
	if len(added) != 1 || added[0].Record.Value != "192.0.2.2" {
		t.Errorf("additions = %+v, want the missing second value", added)
	}
}

func TestMirrorOperationsDeleteADuplicateLineOnce(t *testing.T) {
	// One delete removes every matching line, so a second would find nothing
	// and fail the whole synchronisation of that server.
	duplicated := dnsfile.Record{FQDN: "old.example.net", Type: "A", Value: "192.0.2.99"}
	current := []dnsfile.Record{duplicated, duplicated}

	added, removed := mirrorOperations(current, nil)
	if len(added) != 0 {
		t.Errorf("additions = %+v, want none", added)
	}
	if len(removed) != 1 {
		t.Errorf("removals = %+v, want exactly one", removed)
	}
}

func TestAMirrorMakesEveryServerHoldWhatTheSourceHolds(t *testing.T) {
	h := newWriteHarness(t, 3)

	// dns1 is the source. dns2 is missing a record and dns3 holds one the
	// source does not.
	h.targets["dns1"].content = []byte(seeded +
		"local-data: \"extra.example.net. A 192.0.2.50\"\n")
	h.targets["dns3"].content = []byte(seeded +
		"local-data: \"stray.example.net. A 192.0.2.77\"\n")

	report, err := h.writer.Mirror(context.Background(), testActor(), groupTarget(), 1)
	if err != nil {
		t.Fatalf("Mirror returned an error: %v", err)
	}

	success, failed, skipped := report.Counts()
	if failed != 0 {
		t.Fatalf("counts = %d/%d/%d, want no failure", success, failed, skipped)
	}
	if len(report.Results) != 2 {
		t.Fatalf("%d server(s) were touched, want the two that are not the source",
			len(report.Results))
	}

	for _, name := range []string{"dns2", "dns3"} {
		file := h.targets[name].file()
		if !strings.Contains(file, "extra.example.net") {
			t.Errorf("%s did not receive the record the source holds:\n%s", name, file)
		}
		if strings.Contains(file, "stray.example.net") {
			t.Errorf("%s kept a record the source does not hold:\n%s", name, file)
		}
	}
}

func TestAMirrorLeavesTheSourceAlone(t *testing.T) {
	h := newWriteHarness(t, 3)
	h.targets["dns1"].content = []byte(seeded +
		"local-data: \"extra.example.net. A 192.0.2.50\"\n")
	before := h.targets["dns1"].file()

	out, err := h.writer.Mirror(context.Background(), testActor(), groupTarget(), 1)
	if err != nil {
		t.Fatalf("Mirror returned an error: %v", err)
	}

	if after := h.targets["dns1"].file(); after != before {
		t.Errorf("the source was written to:\n%s", after)
	}
	for _, result := range out.Results {
		if result.ServerName == "dns1" {
			t.Error("the source appeared in its own report")
		}
	}
}

func TestAMirrorRefusesASourceThatHoldsNothing(t *testing.T) {
	// A source that reads as empty is far more often a broken read than a
	// deliberate one, and mirroring it would empty the whole target.
	h := newWriteHarness(t, 3)
	h.targets["dns1"].content = []byte("# nothing here\n")
	before := h.targets["dns2"].file()

	_, err := h.writer.Mirror(context.Background(), testActor(), groupTarget(), 1)
	if !errors.Is(err, ErrEmptySource) {
		t.Fatalf("got %v, want ErrEmptySource", err)
	}
	if after := h.targets["dns2"].file(); after != before {
		t.Errorf("a server was changed by a refused mirror:\n%s", after)
	}
}

func TestAMirrorNeedsASource(t *testing.T) {
	h := newWriteHarness(t, 3)

	if _, err := h.writer.Mirror(context.Background(), testActor(), groupTarget(), 0); !errors.Is(err, ErrNoSource) {
		t.Errorf("got %v, want ErrNoSource", err)
	}
}

func TestAMirrorRefusesADisabledSource(t *testing.T) {
	h := newWriteHarness(t, 3)

	record := h.servers.records[1]
	record.Enabled = false
	h.servers.records[1] = record

	if _, err := h.writer.Mirror(context.Background(), testActor(), groupTarget(), 1); !errors.Is(err, ErrNoSource) {
		t.Errorf("got %v, want ErrNoSource", err)
	}
}

func TestAMirrorIsAudited(t *testing.T) {
	h := newWriteHarness(t, 3)
	h.targets["dns1"].content = []byte(seeded +
		"local-data: \"extra.example.net. A 192.0.2.50\"\n")

	if _, err := h.writer.Mirror(context.Background(), testActor(), groupTarget(), 1); err != nil {
		t.Fatalf("Mirror returned an error: %v", err)
	}

	entries := h.audit.all()
	if len(entries) != 2 {
		t.Fatalf("%d audit row(s), want one per changed server", len(entries))
	}
	for _, entry := range entries {
		if entry.Action != audit.ActionDiffSync {
			t.Errorf("action = %q, want %q", entry.Action, audit.ActionDiffSync)
		}
		if !strings.Contains(entry.Details, "dns1") {
			t.Errorf("the entry does not name the source: %q", entry.Details)
		}
	}
}

// --- Repairing every difference at once ------------------------------------

func TestRepairAllGivesEveryServerWhatTheOthersHold(t *testing.T) {
	// The batch of the per record repair. An operator with forty differing
	// rows presses one button rather than forty.
	h := newWriteHarness(t, 3)
	h.targets["dns2"].content = []byte(`server:
local-data: "only-on-dns2.example.net. A 192.0.2.50"
`)
	h.targets["dns3"].content = []byte(`server:
local-data: "only-on-dns3.example.net. A 192.0.2.51"
`)

	report, err := h.writer.RepairAll(context.Background(), testActor(), groupTarget())
	if err != nil {
		t.Fatalf("RepairAll returned an error: %v", err)
	}
	if !report.OK() {
		t.Fatalf("got %+v", report.Results)
	}

	for name, target := range h.targets {
		for _, want := range []string{
			"www.example.net", "only-on-dns2.example.net", "only-on-dns3.example.net",
		} {
			if !strings.Contains(target.file(), want) {
				t.Errorf("%s does not hold %s:\n%s", name, want, target.file())
			}
		}
	}
}

func TestRepairAllDeletesNothing(t *testing.T) {
	// This is the whole difference between it and a synchronisation.
	//
	// While every server answers, the union is a superset of all of them and
	// nothing could be dropped whatever the rule. The case that can drop a
	// record is a server the panel failed to read while the union was
	// collected and reached a moment later: its records are missing from the
	// union, and a mirror would take them away on the write that follows.
	h := newWriteHarness(t, 2)
	h.targets["dns2"].content = []byte(`server:
local-data: "kept.example.net. A 192.0.2.60"
`)
	h.targets["dns2"].firstReadErr = transport.ErrUnreachable

	if _, err := h.writer.RepairAll(context.Background(), testActor(), groupTarget()); err != nil {
		t.Fatalf("RepairAll returned an error: %v", err)
	}

	held := h.targets["dns2"].file()
	if !strings.Contains(held, "kept.example.net") {
		t.Errorf("the record dns2 held outside the union was removed:\n%s", held)
	}
	if !strings.Contains(held, "www.example.net") {
		t.Errorf("dns2 was not repaired:\n%s", held)
	}
}

func TestRepairAllWritesEachServerOnce(t *testing.T) {
	// One write per server whatever the number of differing rows, so a large
	// diff costs one reload rather than one per row.
	h := newWriteHarness(t, 2)
	h.targets["dns2"].content = []byte(`server:
local-data: "one.example.net. A 192.0.2.71"
local-data: "two.example.net. A 192.0.2.72"
local-data: "three.example.net. A 192.0.2.73"
`)

	if _, err := h.writer.RepairAll(context.Background(), testActor(), groupTarget()); err != nil {
		t.Fatalf("RepairAll returned an error: %v", err)
	}

	writes := 0
	for _, call := range h.targets["dns1"].callOrder() {
		if call == "write" {
			writes++
		}
	}
	if writes != 1 {
		t.Errorf("dns1 was written %d times, want one", writes)
	}
}

func TestRepairAllSkipsAServerThatLacksNothing(t *testing.T) {
	h := newWriteHarness(t, 2)

	report, err := h.writer.RepairAll(context.Background(), testActor(), groupTarget())
	if err != nil {
		t.Fatalf("RepairAll returned an error: %v", err)
	}

	for _, result := range report.Results {
		if result.Status != StatusSkipped {
			t.Errorf("%s = %q %q, want a skip", result.ServerName, result.Status, result.Message)
		}
	}
}

func TestAnUnreadableServerDoesNotStopTheRepair(t *testing.T) {
	// Nothing is deleted, so a server left out of the union loses nothing by
	// it, and a fleet with one host down can still be brought into line.
	h := newWriteHarness(t, 3)
	h.targets["dns2"].content = []byte(`server:
local-data: "only-on-dns2.example.net. A 192.0.2.50"
`)
	h.targets["dns3"].readErr = transport.ErrUnreachable

	report, err := h.writer.RepairAll(context.Background(), testActor(), groupTarget())
	if err != nil {
		t.Fatalf("RepairAll returned an error: %v", err)
	}
	if report.OK() {
		t.Fatalf("the unreachable server was reported as fine: %+v", report.Results)
	}

	if !strings.Contains(h.targets["dns1"].file(), "only-on-dns2.example.net") {
		t.Errorf("dns1 was not repaired while dns3 was down:\n%s", h.targets["dns1"].file())
	}
}
