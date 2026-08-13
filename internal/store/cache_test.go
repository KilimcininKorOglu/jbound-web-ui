package store_test

import (
	"context"
	"testing"
	"time"

	"unbound-web/internal/dnsfile"
	"unbound-web/internal/fleet"
	"unbound-web/internal/server"
	"unbound-web/internal/store"
)

// cacheFixture holds a database with two servers and a group over both.
type cacheFixture struct {
	*fixture
	records *store.Records
	states  *store.States
	first   server.Server
	second  server.Server
	group   server.Group
}

func newCacheFixture(t *testing.T) *cacheFixture {
	t.Helper()

	base := newFixture(t)
	first := base.mustCreate(t, "dns1")
	second := base.mustCreate(t, "dns2")

	group, err := base.groups.Create(context.Background(), server.Group{
		Name: "resolvers", ServerIDs: []int64{first.ID},
	})
	if err != nil {
		t.Fatalf("cannot create the group: %v", err)
	}

	return &cacheFixture{
		fixture: base,
		records: store.NewRecords(base.db),
		states:  store.NewStates(base.db),
		first:   first,
		second:  second,
		group:   group,
	}
}

func cached(line int, fqdn, recordType, value string) dnsfile.Record {
	record := dnsfile.Record{Line: line, FQDN: fqdn, Type: recordType, Value: value}
	record.Raw = record.BuildLine()
	return record
}

func (f *cacheFixture) fill(t *testing.T, serverID int64, records ...dnsfile.Record) {
	t.Helper()

	if err := f.records.Replace(context.Background(), serverID, records); err != nil {
		t.Fatalf("Replace returned an error: %v", err)
	}
}

func TestReplaceStoresEveryField(t *testing.T) {
	f := newCacheFixture(t)
	f.fill(t, f.first.ID,
		dnsfile.Record{Line: 4, FQDN: "mail.example.net", Type: "MX",
			Value: "mx1.example.net", Priority: 20, Raw: `local-data: "mail.example.net. MX 20 mx1.example.net"`})

	page, err := f.records.List(context.Background(), fleet.Query{})
	if err != nil {
		t.Fatalf("List returned an error: %v", err)
	}
	if len(page.Rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(page.Rows))
	}

	row := page.Rows[0]
	if row.Line != 4 || row.FQDN != "mail.example.net" || row.Type != "MX" ||
		row.Value != "mx1.example.net" || row.Priority != 20 {
		t.Errorf("got %+v", row)
	}
	if row.ServerID != f.first.ID || row.ServerName != "dns1" {
		t.Errorf("the row does not name its server: %+v", row)
	}
	if row.Raw == "" {
		t.Error("the raw line did not survive")
	}
}

func TestReplaceSwapsTheWholeSet(t *testing.T) {
	// The file is authoritative. A record the panel still held after a refresh
	// would be one the server no longer has.
	f := newCacheFixture(t)
	ctx := context.Background()

	f.fill(t, f.first.ID,
		cached(1, "old.example.net", "A", "192.0.2.10"),
		cached(2, "gone.example.net", "A", "192.0.2.11"))
	f.fill(t, f.first.ID, cached(1, "new.example.net", "A", "192.0.2.20"))

	page, err := f.records.List(ctx, fleet.Query{})
	if err != nil {
		t.Fatalf("List returned an error: %v", err)
	}
	if len(page.Rows) != 1 || page.Rows[0].FQDN != "new.example.net" {
		t.Errorf("got %+v, want only the new record", page.Rows)
	}
}

func TestReplaceLeavesTheOtherServersAlone(t *testing.T) {
	f := newCacheFixture(t)

	f.fill(t, f.first.ID, cached(1, "one.example.net", "A", "192.0.2.10"))
	f.fill(t, f.second.ID, cached(1, "two.example.net", "A", "192.0.2.20"))
	f.fill(t, f.first.ID, cached(1, "three.example.net", "A", "192.0.2.30"))

	page, err := f.records.List(context.Background(), fleet.Query{})
	if err != nil {
		t.Fatalf("List returned an error: %v", err)
	}
	if len(page.Rows) != 2 {
		t.Fatalf("got %d rows, want 2:\n%+v", len(page.Rows), page.Rows)
	}
}

func TestReplaceWithNothingEmptiesTheServer(t *testing.T) {
	// A file somebody emptied on the target has to empty the cache as well.
	f := newCacheFixture(t)

	f.fill(t, f.first.ID, cached(1, "one.example.net", "A", "192.0.2.10"))
	f.fill(t, f.first.ID)

	page, err := f.records.List(context.Background(), fleet.Query{})
	if err != nil {
		t.Fatalf("List returned an error: %v", err)
	}
	if page.Total != 0 {
		t.Errorf("got %d records, want none", page.Total)
	}
}

func TestListScopesToOneServer(t *testing.T) {
	f := newCacheFixture(t)
	f.fill(t, f.first.ID, cached(1, "one.example.net", "A", "192.0.2.10"))
	f.fill(t, f.second.ID, cached(1, "two.example.net", "A", "192.0.2.20"))

	page, err := f.records.List(context.Background(), fleet.Query{
		Scope: fleet.ScopeServer, ServerID: f.second.ID})
	if err != nil {
		t.Fatalf("List returned an error: %v", err)
	}
	if len(page.Rows) != 1 || page.Rows[0].FQDN != "two.example.net" {
		t.Errorf("got %+v", page.Rows)
	}
}

func TestListScopesToAGroup(t *testing.T) {
	f := newCacheFixture(t)
	f.fill(t, f.first.ID, cached(1, "one.example.net", "A", "192.0.2.10"))
	f.fill(t, f.second.ID, cached(1, "two.example.net", "A", "192.0.2.20"))

	page, err := f.records.List(context.Background(), fleet.Query{
		Scope: fleet.ScopeGroup, GroupID: f.group.ID})
	if err != nil {
		t.Fatalf("List returned an error: %v", err)
	}
	if len(page.Rows) != 1 || page.Rows[0].ServerName != "dns1" {
		t.Errorf("got %+v, want only the member of the group", page.Rows)
	}
}

func TestListSearchesTheNameAndTheValueWithoutRegardToCase(t *testing.T) {
	f := newCacheFixture(t)
	f.fill(t, f.first.ID,
		cached(1, "WWW.example.net", "A", "192.0.2.10"),
		cached(2, "other.example.net", "CNAME", "WWW.example.net"),
		cached(3, "unrelated.example.net", "A", "198.51.100.7"))

	page, err := f.records.List(context.Background(), fleet.Query{Search: "wWw"})
	if err != nil {
		t.Fatalf("List returned an error: %v", err)
	}
	if page.Total != 2 {
		t.Errorf("got %d matches, want 2:\n%+v", page.Total, page.Rows)
	}
}

func TestListTreatsAWildcardAsText(t *testing.T) {
	// Without escaping, a search for "%" would match everything and read as a
	// broken filter rather than as a search.
	f := newCacheFixture(t)
	f.fill(t, f.first.ID,
		cached(1, "a_b.example.net", "A", "192.0.2.10"),
		cached(2, "axb.example.net", "A", "192.0.2.11"))

	page, err := f.records.List(context.Background(), fleet.Query{Search: "a_b"})
	if err != nil {
		t.Fatalf("List returned an error: %v", err)
	}
	if page.Total != 1 || page.Rows[0].FQDN != "a_b.example.net" {
		t.Errorf("got %+v, want only the literal match", page.Rows)
	}

	page, err = f.records.List(context.Background(), fleet.Query{Search: "%"})
	if err != nil {
		t.Fatalf("List returned an error: %v", err)
	}
	if page.Total != 0 {
		t.Errorf("a wildcard search matched %d records", page.Total)
	}
}

func TestListFiltersOnTheType(t *testing.T) {
	f := newCacheFixture(t)
	f.fill(t, f.first.ID,
		cached(1, "one.example.net", "A", "192.0.2.10"),
		cached(2, "two.example.net", "AAAA", "2001:db8::1"))

	page, err := f.records.List(context.Background(), fleet.Query{Type: "AAAA"})
	if err != nil {
		t.Fatalf("List returned an error: %v", err)
	}
	if page.Total != 1 || page.Rows[0].Type != "AAAA" {
		t.Errorf("got %+v", page.Rows)
	}
}

func TestListCountsTheFilteredSetRatherThanTheWholeCache(t *testing.T) {
	// A total taken before the filter would page over records the operator
	// cannot see, leaving empty pages at the end.
	f := newCacheFixture(t)
	f.fill(t, f.first.ID,
		cached(1, "match.example.net", "A", "192.0.2.10"),
		cached(2, "other.example.net", "A", "192.0.2.11"),
		cached(3, "another.example.net", "A", "192.0.2.12"))

	page, err := f.records.List(context.Background(), fleet.Query{Search: "match"})
	if err != nil {
		t.Fatalf("List returned an error: %v", err)
	}
	if page.Total != 1 || page.TotalPages != 1 {
		t.Errorf("total = %d over %d pages", page.Total, page.TotalPages)
	}
}

func TestListPagesThroughTheRecords(t *testing.T) {
	f := newCacheFixture(t)

	var records []dnsfile.Record
	for i := 1; i <= 25; i++ {
		records = append(records, cached(i, fqdnFor(i), "A", "192.0.2.10"))
	}
	f.fill(t, f.first.ID, records...)

	first, err := f.records.List(context.Background(), fleet.Query{PerPage: 10, Page: 1})
	if err != nil {
		t.Fatalf("List returned an error: %v", err)
	}
	if len(first.Rows) != 10 || first.Total != 25 || first.TotalPages != 3 {
		t.Fatalf("got %d rows of %d over %d pages", len(first.Rows), first.Total, first.TotalPages)
	}

	last, err := f.records.List(context.Background(), fleet.Query{PerPage: 10, Page: 3})
	if err != nil {
		t.Fatalf("List returned an error: %v", err)
	}
	if len(last.Rows) != 5 {
		t.Errorf("the last page holds %d rows, want 5", len(last.Rows))
	}
	if first.Rows[0].FQDN == last.Rows[0].FQDN {
		t.Error("the two pages start with the same record")
	}
}

func TestListClampsAPageBeyondTheEnd(t *testing.T) {
	// A page number out of range comes from a stale link, and an empty table
	// says less than the last page of records.
	f := newCacheFixture(t)
	f.fill(t, f.first.ID, cached(1, "one.example.net", "A", "192.0.2.10"))

	page, err := f.records.List(context.Background(), fleet.Query{Page: 99})
	if err != nil {
		t.Fatalf("List returned an error: %v", err)
	}
	if page.Page != 1 || len(page.Rows) != 1 {
		t.Errorf("page = %d with %d rows", page.Page, len(page.Rows))
	}
}

func TestListKeepsAStableOrder(t *testing.T) {
	// The reference project kept the order of the file, which says nothing
	// once several servers are shown at once.
	f := newCacheFixture(t)
	f.fill(t, f.second.ID, cached(1, "b.example.net", "A", "192.0.2.20"))
	f.fill(t, f.first.ID,
		cached(2, "c.example.net", "A", "192.0.2.12"),
		cached(1, "a.example.net", "A", "192.0.2.11"))

	page, err := f.records.List(context.Background(), fleet.Query{})
	if err != nil {
		t.Fatalf("List returned an error: %v", err)
	}

	want := []string{"dns1/a.example.net", "dns1/c.example.net", "dns2/b.example.net"}
	for i, expected := range want {
		got := page.Rows[i].ServerName + "/" + page.Rows[i].FQDN
		if got != expected {
			t.Errorf("position %d is %s, want %s", i, got, expected)
		}
	}
}

func TestDeletingAServerDropsItsCache(t *testing.T) {
	f := newCacheFixture(t)
	ctx := context.Background()

	f.fill(t, f.first.ID, cached(1, "one.example.net", "A", "192.0.2.10"))
	if err := f.servers.Delete(ctx, f.first.ID); err != nil {
		t.Fatalf("Delete returned an error: %v", err)
	}

	page, err := f.records.List(ctx, fleet.Query{})
	if err != nil {
		t.Fatalf("List returned an error: %v", err)
	}
	if page.Total != 0 {
		t.Errorf("%d cached records outlived their server", page.Total)
	}
}

func TestStateOfAServerNobodyHasReadIsNotAnError(t *testing.T) {
	f := newCacheFixture(t)

	state, err := f.states.Get(context.Background(), f.first.ID)
	if err != nil {
		t.Fatalf("Get returned an error: %v", err)
	}
	if state.FetchedAt != nil || state.Reachable {
		t.Errorf("got %+v, want a server nobody has read", state)
	}
}

func TestSetFetchedRecordsTheRead(t *testing.T) {
	f := newCacheFixture(t)
	ctx := context.Background()
	when := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)

	err := f.states.SetFetched(ctx, fleet.State{
		ServerID: f.first.ID, FileSHA256: "abc", FetchedAt: &when,
		UnboundActive: true, RecordCount: 7,
	})
	if err != nil {
		t.Fatalf("SetFetched returned an error: %v", err)
	}

	state, err := f.states.Get(ctx, f.first.ID)
	if err != nil {
		t.Fatalf("Get returned an error: %v", err)
	}
	if !state.Reachable || !state.UnboundActive || state.RecordCount != 7 || state.FileSHA256 != "abc" {
		t.Errorf("got %+v", state)
	}
	if state.FetchedAt == nil || !state.FetchedAt.Equal(when) {
		t.Errorf("fetched at %v, want %v", state.FetchedAt, when)
	}
}

func TestSetFetchedClearsAPreviousFailure(t *testing.T) {
	f := newCacheFixture(t)
	ctx := context.Background()
	when := time.Now().UTC()

	if err := f.states.SetUnreachable(ctx, f.first.ID, "connection refused"); err != nil {
		t.Fatalf("SetUnreachable returned an error: %v", err)
	}
	err := f.states.SetFetched(ctx, fleet.State{
		ServerID: f.first.ID, FileSHA256: "abc", FetchedAt: &when, RecordCount: 1})
	if err != nil {
		t.Fatalf("SetFetched returned an error: %v", err)
	}

	state, err := f.states.Get(ctx, f.first.ID)
	if err != nil {
		t.Fatalf("Get returned an error: %v", err)
	}
	if state.LastError != "" || !state.Reachable {
		t.Errorf("got %+v, want the failure cleared", state)
	}
}

func TestSetUnreachableKeepsWhatThePanelLastSaw(t *testing.T) {
	// Old records with a warning next to them say more than an empty page.
	f := newCacheFixture(t)
	ctx := context.Background()
	when := time.Now().UTC()

	err := f.states.SetFetched(ctx, fleet.State{
		ServerID: f.first.ID, FileSHA256: "abc", FetchedAt: &when, RecordCount: 3})
	if err != nil {
		t.Fatalf("SetFetched returned an error: %v", err)
	}
	if err := f.states.SetUnreachable(ctx, f.first.ID, "connection refused"); err != nil {
		t.Fatalf("SetUnreachable returned an error: %v", err)
	}

	state, err := f.states.Get(ctx, f.first.ID)
	if err != nil {
		t.Fatalf("Get returned an error: %v", err)
	}
	if state.Reachable || state.LastError != "connection refused" {
		t.Errorf("got %+v", state)
	}
	if state.FileSHA256 != "abc" || state.FetchedAt == nil {
		t.Error("the last successful read was forgotten")
	}
}

func TestSetAppliedIsIndependentOfTheRead(t *testing.T) {
	// The two digests are compared against each other, so writing one must
	// never move the other.
	f := newCacheFixture(t)
	ctx := context.Background()
	when := time.Now().UTC()

	if err := f.states.SetApplied(ctx, f.first.ID, "applied"); err != nil {
		t.Fatalf("SetApplied returned an error: %v", err)
	}
	err := f.states.SetFetched(ctx, fleet.State{
		ServerID: f.first.ID, FileSHA256: "current", FetchedAt: &when})
	if err != nil {
		t.Fatalf("SetFetched returned an error: %v", err)
	}

	state, err := f.states.Get(ctx, f.first.ID)
	if err != nil {
		t.Fatalf("Get returned an error: %v", err)
	}
	if state.AppliedSHA256 != "applied" || state.FileSHA256 != "current" {
		t.Errorf("got %+v", state)
	}
	if !state.Pending() {
		t.Error("a file that differs from the applied one is not reported as pending")
	}
}

func TestListStatesIsKeyedByServer(t *testing.T) {
	f := newCacheFixture(t)
	ctx := context.Background()
	when := time.Now().UTC()

	if err := f.states.SetFetched(ctx, fleet.State{
		ServerID: f.first.ID, FetchedAt: &when}); err != nil {
		t.Fatalf("SetFetched returned an error: %v", err)
	}
	if err := f.states.SetUnreachable(ctx, f.second.ID, "down"); err != nil {
		t.Fatalf("SetUnreachable returned an error: %v", err)
	}

	states, err := f.states.List(ctx)
	if err != nil {
		t.Fatalf("List returned an error: %v", err)
	}
	if len(states) != 2 {
		t.Fatalf("got %d states, want 2", len(states))
	}
	if !states[f.first.ID].Reachable || states[f.second.ID].Reachable {
		t.Errorf("got %+v", states)
	}
}

// fqdnFor builds a name that sorts in the order it was created.
func fqdnFor(i int) string {
	return string(rune('a'+(i-1)/10)) + string(rune('0'+(i-1)%10)) + ".example.net"
}
