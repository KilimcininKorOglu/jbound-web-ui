package fleet

import (
	"context"
	"strings"
	"testing"

	"unbound-web/internal/audit"
	"unbound-web/internal/dnsfile"
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

func TestARepairCorrectsAValueThatDrifted(t *testing.T) {
	h := newWriteHarness(t, 2)
	h.targets["dns2"].content = []byte(
		"local-data: \"www.example.net. A 192.0.2.99\"\n")

	want := record("www.example.net", "A", "192.0.2.10")
	if _, err := h.writer.Repair(context.Background(), testActor(), groupTarget(), want); err != nil {
		t.Fatalf("Repair returned an error: %v", err)
	}

	file := h.targets["dns2"].file()
	if strings.Contains(file, "192.0.2.99") || !strings.Contains(file, "192.0.2.10") {
		t.Errorf("the value was not corrected:\n%s", file)
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
	h.targets["dns1"].content = []byte(
		"local-data: \"www.example.net. A 192.0.2.55\"\n")

	want := record("www.example.net", "A", "192.0.2.10")
	if _, err := h.writer.Repair(context.Background(), testActor(), groupTarget(), want); err != nil {
		t.Fatalf("Repair returned an error: %v", err)
	}

	file := h.targets["dns1"].file()
	if strings.Count(file, "www.example.net") != 1 {
		t.Errorf("the repair added a second entry instead of correcting one:\n%s", file)
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
