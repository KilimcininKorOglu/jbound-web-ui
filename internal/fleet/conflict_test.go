package fleet

import (
	"context"
	"testing"

	"jbound/internal/dnsfile"
)

// conflictsOf runs the classification over a cache the test lays out by hand.
func conflictsOf(t *testing.T, cache map[int64][]dnsfile.Record,
	records ...dnsfile.Record) []Conflict {

	t.Helper()

	harness := newWriteHarness(t, 2)
	service := harness.service(&fakeLister{byServer: cache}, &stubQuerier{})

	conflicts, err := service.Conflicts(context.Background(), groupTarget(), records)
	if err != nil {
		t.Fatalf("Conflicts returned an error: %v", err)
	}
	return conflicts
}

func TestANameNobodyAnswersForIsNoConflict(t *testing.T) {
	// The address is already in use under another name, which is ordinary: one
	// machine answers to more than one name.
	cache := map[int64][]dnsfile.Record{
		1: {record("other.example.net", "A", "192.0.2.10")},
		2: {record("other.example.net", "A", "192.0.2.10")},
	}

	if got := conflictsOf(t, cache, record("www.example.net", "A", "192.0.2.10")); len(got) != 0 {
		t.Errorf("got %+v, want nothing in the way", got)
	}
}

func TestARecordTheWholeTargetHoldsReadsAsExisting(t *testing.T) {
	cache := map[int64][]dnsfile.Record{
		1: {record("www.example.net", "A", "192.0.2.10")},
		2: {record("www.example.net", "A", "192.0.2.10")},
	}

	got := conflictsOf(t, cache, record("www.example.net", "A", "192.0.2.10"))
	if len(got) != 1 {
		t.Fatalf("got %+v, want one conflict", got)
	}
	if got[0].Kind != ConflictExists || !got[0].Everywhere {
		t.Errorf("got %+v, want it to read as already there on every server", got[0])
	}
	if !AlreadyEverywhere(got, 1) {
		t.Error("the submission does not read as one with nothing to write")
	}
}

func TestARecordOnlySomeServersHoldIsStillWritten(t *testing.T) {
	// The others are missing it, and that is what the write is for.
	cache := map[int64][]dnsfile.Record{
		1: {record("www.example.net", "A", "192.0.2.10")},
	}

	got := conflictsOf(t, cache, record("www.example.net", "A", "192.0.2.10"))
	if len(got) != 1 || got[0].Kind != ConflictExists {
		t.Fatalf("got %+v, want it to read as already there", got)
	}
	if got[0].Everywhere {
		t.Error("a record one server lacks reads as being everywhere")
	}
	if AlreadyEverywhere(got, 1) {
		t.Error("a submission with a server to write to reads as having nothing to do")
	}
	if len(got[0].Servers) != 1 || got[0].Servers[0] != "dns1" {
		t.Errorf("the servers holding it are %v, want dns1", got[0].Servers)
	}
}

func TestANameThatAnswersWithAnotherValueIsAChoice(t *testing.T) {
	// dns1 answers for the name, dns2 has never heard of it. One question
	// covers both: the answer replaces the value on one and writes it on the
	// other.
	cache := map[int64][]dnsfile.Record{
		1: {record("www.example.net", "A", "192.0.2.10")},
	}

	got := conflictsOf(t, cache, record("www.example.net", "A", "192.0.2.99"))
	if len(got) != 1 {
		t.Fatalf("got %+v, want one conflict", got)
	}
	if got[0].Kind != ConflictNameTaken {
		t.Fatalf("got %q, want the name to read as taken", got[0].Kind)
	}
	if got[0].Existing.Value != "192.0.2.10" {
		t.Errorf("the record in the way is %+v", got[0].Existing)
	}
	if len(got[0].Servers) != 1 || got[0].Servers[0] != "dns1" {
		t.Errorf("the servers answering are %v, want dns1", got[0].Servers)
	}
	if !NameTaken(got) {
		t.Error("the submission does not read as one that needs an answer")
	}
}

func TestATakenNameOutranksTheSameRecordElsewhere(t *testing.T) {
	// dns1 holds the record already and dns2 answers with something else. The
	// choice is the thing to put in front of the operator, because it is the
	// one that decides what gets written.
	cache := map[int64][]dnsfile.Record{
		1: {record("www.example.net", "A", "192.0.2.99")},
		2: {record("www.example.net", "A", "192.0.2.10")},
	}

	got := conflictsOf(t, cache, record("www.example.net", "A", "192.0.2.99"))
	if len(got) != 1 || got[0].Kind != ConflictNameTaken {
		t.Fatalf("got %+v, want the choice", got)
	}
	if len(got[0].Servers) != 1 || got[0].Servers[0] != "dns2" {
		t.Errorf("the servers answering differently are %v, want dns2", got[0].Servers)
	}
}

func TestATypeThatCarriesSeveralValuesIsNeverTaken(t *testing.T) {
	cache := map[int64][]dnsfile.Record{
		1: {{FQDN: "example.net", Type: "MX", Value: "mx1.example.net", Priority: 10}},
	}

	wanted := dnsfile.Record{
		FQDN: "example.net", Type: "MX", Value: "mx2.example.net", Priority: 20}

	if got := conflictsOf(t, cache, wanted); len(got) != 0 {
		t.Errorf("got %+v, want a second mail exchanger to pass", got)
	}
}

func TestEachRowOfABatchIsNumbered(t *testing.T) {
	// A message about a batch of twenty that does not say which row is in the
	// way leaves the operator to find it themselves.
	cache := map[int64][]dnsfile.Record{
		1: {record("www.example.net", "A", "192.0.2.10")},
	}

	got := conflictsOf(t, cache,
		record("first.example.net", "A", "192.0.2.1"),
		record("www.example.net", "A", "192.0.2.99"))

	if len(got) != 1 {
		t.Fatalf("got %+v, want the second row only", got)
	}
	if got[0].Row != 2 {
		t.Errorf("the conflict names row %d, want row 2", got[0].Row)
	}
}
