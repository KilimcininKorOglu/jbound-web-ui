package fleet

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"unbound-web/internal/audit"
	"unbound-web/internal/dnsfile"
	"unbound-web/internal/server"
	"unbound-web/internal/settings"
)

// fakeLister answers with a fixed cache, so the service can be driven without
// a database behind it.
type fakeLister struct {
	page     Page
	byServer map[int64][]dnsfile.Record

	lastQuery Query
	err       error
}

func (f *fakeLister) List(_ context.Context, query Query) (Page, error) {
	f.lastQuery = query
	if f.err != nil {
		return Page{}, f.err
	}
	return f.page, nil
}

func (f *fakeLister) ByServer(_ context.Context, query Query) (map[int64][]dnsfile.Record, error) {
	f.lastQuery = query
	if f.err != nil {
		return nil, f.err
	}
	return f.byServer, nil
}

// stubQuerier answers one name per host.
type stubQuerier struct {
	mu      sync.Mutex
	answers map[string][]string
	errs    map[string]error
	asked   []string

	// delay holds a query open, and inFlight tracks how many overlap, which is
	// what proves the fan-out is bounded.
	delay    time.Duration
	inFlight *atomic.Int32
	peak     *atomic.Int32
}

func (s *stubQuerier) Ask(_ context.Context, host, domain, _ string) ([]string, error) {
	if s.inFlight != nil {
		current := s.inFlight.Add(1)
		defer s.inFlight.Add(-1)

		for {
			peak := s.peak.Load()
			if current <= peak || s.peak.CompareAndSwap(peak, current) {
				break
			}
		}
	}
	if s.delay > 0 {
		time.Sleep(s.delay)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.asked = append(s.asked, host+" "+domain)
	if err := s.errs[host]; err != nil {
		return nil, err
	}
	return s.answers[host], nil
}

func (s *stubQuerier) questions() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.asked...)
}

// service builds a record service over the harness, which already holds the
// servers, the group and the writable targets.
func (h *writeHarness) service(lister *fakeLister, queries NameQuerier) *Service {
	refresher := NewRefresher(h.servers, &fakeRecords{byID: map[int64][]dnsfile.Record{}},
		h.states, &writableConnector{byHost: h.targets}, "/data",
		settings.Fixed(server.Timeouts{Connect: time.Second, Command: time.Second}),
		settings.Fixed(2))

	return NewService(lister, h.states, h.writer, refresher, queries,
		audit.NewLogger(h.audit, nil), settings.Fixed(15*time.Minute))
}

func TestAStaleRowIsMarkedRatherThanHidden(t *testing.T) {
	// An empty page would say less than old records with a warning next to
	// them, so the row travels with the age of its cache.
	harness := newWriteHarness(t, 2)
	fresh := time.Now()

	if err := harness.states.SetFetched(context.Background(), State{
		ServerID: 1, FetchedAt: &fresh, Reachable: true}); err != nil {
		t.Fatalf("cannot record the state: %v", err)
	}
	// dns2 was last read a day ago.
	old := fresh.Add(-24 * time.Hour)
	if err := harness.states.SetFetched(context.Background(), State{
		ServerID: 2, FetchedAt: &old, Reachable: true}); err != nil {
		t.Fatalf("cannot record the state: %v", err)
	}

	// The first record sits on the server read a moment ago. The second sits
	// on both, and one of the two is a day old.
	lister := &fakeLister{page: Page{Rows: []Row{
		{Holders: []int64{1}, HolderNames: []string{"dns1"}},
		{Holders: []int64{1, 2}, HolderNames: []string{"dns1", "dns2"}},
	}}}
	service := harness.service(lister, &stubQuerier{})

	page, err := service.Page(context.Background(), Query{})
	if err != nil {
		t.Fatalf("cannot read the page: %v", err)
	}
	if page.Rows[0].Stale {
		t.Error("a row held only by the server read a moment ago is marked stale")
	}
	if !page.Rows[1].Stale {
		t.Error("a row held by the server read a day ago is not marked stale")
	}

	stale, err := service.Stale(context.Background())
	if err != nil {
		t.Fatalf("cannot read the stale map: %v", err)
	}
	if stale[1] || !stale[2] {
		t.Errorf("stale map = %v, want only dns2", stale)
	}
}

func TestAServerNobodyHasReadIsStale(t *testing.T) {
	harness := newWriteHarness(t, 1)
	service := harness.service(&fakeLister{}, &stubQuerier{})

	states, err := service.States(context.Background())
	if err != nil {
		t.Fatalf("cannot read the states: %v", err)
	}
	if len(states) != 0 {
		t.Fatalf("states = %v, want an empty map", states)
	}

	status, err := service.Status(context.Background(), Query{Scope: ScopeAll})
	if err != nil {
		t.Fatalf("cannot read the status: %v", err)
	}
	if len(status.Servers) != 1 || !status.Servers[0].Stale {
		t.Errorf("status = %+v, want the one server marked stale", status.Servers)
	}
}

func TestTheStatusOfAGroupCarriesItsName(t *testing.T) {
	harness := newWriteHarness(t, 3)
	service := harness.service(&fakeLister{}, &stubQuerier{})

	status, err := service.Status(context.Background(),
		Query{Scope: ScopeGroup, GroupID: 1})
	if err != nil {
		t.Fatalf("cannot read the status: %v", err)
	}

	if status.GroupName != "resolvers" {
		t.Errorf("group name = %q, want resolvers", status.GroupName)
	}
	if !status.CanApply {
		t.Error("a group cannot be applied to, and it is the point of a group")
	}
	if len(status.Servers) != 3 {
		t.Errorf("%d servers came back, want 3", len(status.Servers))
	}
}

func TestTheWholeFleetCannotBeAppliedTo(t *testing.T) {
	// A reload needs a single server or a group somebody built on purpose.
	harness := newWriteHarness(t, 2)
	service := harness.service(&fakeLister{}, &stubQuerier{})

	status, err := service.Status(context.Background(), Query{Scope: ScopeAll})
	if err != nil {
		t.Fatalf("cannot read the status: %v", err)
	}
	if status.CanApply {
		t.Error("the status bar offers a reload of the whole fleet")
	}
}

func TestAQueryAsksEveryServerOfTheGroup(t *testing.T) {
	harness := newWriteHarness(t, 3)
	queries := &stubQuerier{answers: map[string][]string{
		"dns1": {"10.0.0.1"}, "dns2": {"10.0.0.1"}, "dns3": {"10.0.0.1"},
	}}
	service := harness.service(&fakeLister{}, queries)

	report, err := service.Query(context.Background(), testActor(),
		groupTarget(), "www.example.net", "A")
	if err != nil {
		t.Fatalf("the query failed: %v", err)
	}

	if len(report.Results) != 3 {
		t.Fatalf("%d servers answered, want 3", len(report.Results))
	}
	if !report.Agree() {
		t.Errorf("three identical answers do not agree: %+v", report.Results)
	}
	if report.Failed() != 0 {
		t.Errorf("%d servers failed, want none", report.Failed())
	}
	if len(queries.questions()) != 3 {
		t.Errorf("the querier was asked %d times, want 3", len(queries.questions()))
	}
}

func TestAQueryHoldsTheConcurrencyLimit(t *testing.T) {
	// Every member forks a resolver query of its own, and any signed in
	// account can start one against the whole fleet, so the operator's
	// ceiling has to apply here as much as it does to a write.
	var inFlight, peak atomic.Int32

	harness := newWriteHarness(t, 8)
	queries := &stubQuerier{
		answers:  map[string][]string{},
		inFlight: &inFlight, peak: &peak, delay: 20 * time.Millisecond,
	}
	service := harness.service(&fakeLister{}, queries)

	report, err := service.Query(context.Background(), testActor(),
		groupTarget(), "www.example.net", "A")
	if err != nil {
		t.Fatalf("the query failed: %v", err)
	}
	if len(report.Results) != 8 {
		t.Fatalf("%d servers answered, want 8", len(report.Results))
	}

	if peak.Load() > 2 {
		t.Errorf("%d queries overlapped, want at most 2", peak.Load())
	}
	if peak.Load() < 2 {
		t.Error("the queries ran one after another, so the limit does nothing")
	}
}

func TestAQueryReportsTheServerThatDisagrees(t *testing.T) {
	// A record that resolves on two servers and not on the third is drift the
	// record table cannot show, because the files may well be identical.
	harness := newWriteHarness(t, 3)
	queries := &stubQuerier{answers: map[string][]string{
		"dns1": {"10.0.0.1"}, "dns2": {"10.0.0.1"}, "dns3": nil,
	}}
	service := harness.service(&fakeLister{}, queries)

	report, err := service.Query(context.Background(), testActor(),
		groupTarget(), "www.example.net", "")
	if err != nil {
		t.Fatalf("the query failed: %v", err)
	}
	if report.Agree() {
		t.Errorf("a resolver answering nothing agrees with the others: %+v", report.Results)
	}
}

func TestAQueryCountsTheServersItCouldNotAsk(t *testing.T) {
	harness := newWriteHarness(t, 2)
	queries := &stubQuerier{
		answers: map[string][]string{"dns1": {"10.0.0.1"}},
		errs:    map[string]error{"dns2": errors.New("no servers could be reached")},
	}
	service := harness.service(&fakeLister{}, queries)

	report, err := service.Query(context.Background(), testActor(),
		groupTarget(), "www.example.net", "A")
	if err != nil {
		t.Fatalf("the query failed: %v", err)
	}

	if report.Failed() != 1 {
		t.Errorf("%d servers failed, want 1", report.Failed())
	}
	// The one that answered still counts as agreement, because a server that
	// could not be asked said nothing to disagree with.
	if !report.Agree() {
		t.Errorf("a single answer does not agree with itself: %+v", report.Results)
	}
}

func TestAQueryRefusesANameThatIsNotOne(t *testing.T) {
	// The name becomes a command argument. It is checked here as well as in
	// the querier, so the rule holds whichever querier is behind the interface.
	harness := newWriteHarness(t, 2)
	queries := &stubQuerier{}
	service := harness.service(&fakeLister{}, queries)

	cases := []struct {
		name       string
		domain     string
		recordType string
	}{
		{name: "a shell fragment", domain: "www.example.net; rm -rf /"},
		{name: "an empty name"},
		{name: "an unknown type", domain: "www.example.net", recordType: "SPF"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := service.Query(context.Background(), testActor(), groupTarget(),
				testCase.domain, testCase.recordType)
			if err == nil {
				t.Fatal("the query was accepted")
			}
			if len(queries.questions()) != 0 {
				t.Errorf("the querier was asked anyway: %v", queries.questions())
			}
		})
	}
}

func TestAQueryIsAudited(t *testing.T) {
	// A query changes nothing, and one row still names what was asked and
	// where, because reading the fleet is part of what an operator did.
	harness := newWriteHarness(t, 3)
	queries := &stubQuerier{answers: map[string][]string{"dns1": {"10.0.0.1"}}}
	service := harness.service(&fakeLister{}, queries)

	if _, err := service.Query(context.Background(), testActor(),
		groupTarget(), "www.example.net", "A"); err != nil {
		t.Fatalf("the query failed: %v", err)
	}

	entries := harness.audit.all()
	if len(entries) != 1 {
		t.Fatalf("%d audit rows were written, want 1", len(entries))
	}
	if entries[0].Action != audit.ActionDNSQuery {
		t.Errorf("action = %q, want %q", entries[0].Action, audit.ActionDNSQuery)
	}
	if !strings.Contains(entries[0].Details, "www.example.net") {
		t.Errorf("the row does not name what was asked: %q", entries[0].Details)
	}
	// The server column names a machine only when a single one was asked.
	if entries[0].ServerID != nil {
		t.Errorf("a group query named one server: %+v", entries[0])
	}
}

func TestTheDiffIsBuiltFromTheCacheOfTheTarget(t *testing.T) {
	harness := newWriteHarness(t, 3)
	lister := &fakeLister{byServer: map[int64][]dnsfile.Record{
		1: {record("www.example.net", "A", "192.0.2.10")},
		2: {record("www.example.net", "A", "192.0.2.99")},
	}}
	service := harness.service(lister, &stubQuerier{})

	diff, err := service.Diff(context.Background(),
		Query{Scope: ScopeGroup, GroupID: 1}, false)
	if err != nil {
		t.Fatalf("cannot build the diff: %v", err)
	}

	if diff.GroupName != "resolvers" {
		t.Errorf("group name = %q, want resolvers", diff.GroupName)
	}
	if len(diff.Servers) != 3 {
		t.Fatalf("%d columns came back, want 3", len(diff.Servers))
	}
	if len(diff.Rows) == 0 {
		t.Fatal("the diff holds no row")
	}
	if diff.Rows[0].Match() {
		t.Errorf("three servers holding two values agree: %+v", diff.Rows[0])
	}
}

func TestTheDiffCanBeNarrowedToTheDifferences(t *testing.T) {
	harness := newWriteHarness(t, 2)
	agreed := record("mail.example.net", "A", "192.0.2.20")
	lister := &fakeLister{byServer: map[int64][]dnsfile.Record{
		1: {agreed, record("www.example.net", "A", "192.0.2.10")},
		2: {agreed},
	}}
	service := harness.service(lister, &stubQuerier{})

	diff, err := service.Diff(context.Background(),
		Query{Scope: ScopeGroup, GroupID: 1}, true)
	if err != nil {
		t.Fatalf("cannot build the diff: %v", err)
	}

	if !diff.OnlyMismatches {
		t.Error("the diff does not report that it was narrowed")
	}
	if len(diff.Rows) != 1 {
		t.Fatalf("%d rows came back, want the one that differs", len(diff.Rows))
	}
	if diff.Rows[0].FQDN != "www.example.net" {
		t.Errorf("the row is %q, want the missing record", diff.Rows[0].FQDN)
	}
}

func TestARepairGoesThroughTheWriter(t *testing.T) {
	harness := newWriteHarness(t, 3)
	service := harness.service(&fakeLister{}, &stubQuerier{})

	// dns2 is missing the record the other two hold.
	harness.targets["dns2"].content = []byte("# managed by the panel\n")

	want := dnsfile.Record{FQDN: "www.example.net", Type: "A", Value: "192.0.2.10"}
	report, err := service.Repair(context.Background(), testActor(), groupTarget(), want)
	if err != nil {
		t.Fatalf("the repair failed: %v", err)
	}

	if len(report.Results) != 3 {
		t.Fatalf("%d servers were covered, want 3", len(report.Results))
	}
	if !strings.Contains(harness.targets["dns2"].file(), "192.0.2.10") {
		t.Errorf("the record did not land on dns2:\n%s", harness.targets["dns2"].file())
	}

	var repaired, skipped int
	for _, result := range report.Results {
		switch result.Status {
		case StatusSuccess:
			repaired++
		case StatusSkipped:
			skipped++
		}
	}
	if repaired != 1 || skipped != 2 {
		t.Errorf("%d repaired and %d skipped, want 1 and 2", repaired, skipped)
	}
}

func TestTheQueryBoundsAreClamped(t *testing.T) {
	cases := []struct {
		name    string
		query   Query
		scope   string
		perPage int
		page    int
	}{
		{name: "an empty query covers the fleet",
			scope: ScopeAll, perPage: DefaultPerPage, page: 1},
		{name: "a page of one is raised to the minimum",
			query: Query{PerPage: 1}, scope: ScopeAll, perPage: MinPerPage, page: 1},
		{name: "a page of a thousand is cut to the maximum",
			query: Query{PerPage: 1000}, scope: ScopeAll, perPage: MaxPerPage, page: 1},
		{name: "a scope that was chosen is kept",
			query: Query{Scope: ScopeGroup, GroupID: 1, Page: -2},
			scope: ScopeGroup, perPage: DefaultPerPage, page: 1},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			query := testCase.query
			query.Normalise()

			if query.Scope != testCase.scope {
				t.Errorf("scope = %q, want %q", query.Scope, testCase.scope)
			}
			if query.PerPage != testCase.perPage {
				t.Errorf("per page = %d, want %d", query.PerPage, testCase.perPage)
			}
			if query.Page != testCase.page {
				t.Errorf("page = %d, want %d", query.Page, testCase.page)
			}
		})
	}
}

func TestAPageBeyondTheEndComesBackAsTheLastOne(t *testing.T) {
	page := NewPage(Query{Page: 12, PerPage: 25}, 60)

	if page.TotalPages != 3 {
		t.Errorf("total pages = %d, want 3", page.TotalPages)
	}
	if page.Page != 3 {
		t.Errorf("page = %d, want 3", page.Page)
	}
	if page.Offset() != 50 {
		t.Errorf("offset = %d, want 50", page.Offset())
	}
}

func TestThePageCountsTheServersOfTheTarget(t *testing.T) {
	// The count is the denominator of every row's holder count, so a row that
	// two of three servers hold reads as drift rather than as agreement.
	harness := newWriteHarness(t, 3)
	lister := &fakeLister{page: Page{Rows: []Row{
		{Holders: []int64{1, 2, 3}},
		{Holders: []int64{1, 2}},
	}}}
	service := harness.service(lister, &stubQuerier{})

	page, err := service.Page(context.Background(), Query{Scope: ScopeGroup, GroupID: 1})
	if err != nil {
		t.Fatalf("cannot read the page: %v", err)
	}

	if page.TargetServers != 3 {
		t.Fatalf("target = %d servers, want 3", page.TargetServers)
	}
	if !page.Rows[0].Complete(page.TargetServers) {
		t.Error("a record every server holds reads as incomplete")
	}
	if page.Rows[1].Complete(page.TargetServers) {
		t.Error("a record one server misses reads as complete")
	}
}

func TestADisabledServerIsNotPartOfTheTargetCount(t *testing.T) {
	// A disabled server is left out of every operation, so counting it would
	// make a record every working server holds read as incomplete.
	harness := newWriteHarness(t, 3)

	members := harness.groups.members[1]
	members[len(members)-1].Enabled = false

	service := harness.service(&fakeLister{}, &stubQuerier{})

	page, err := service.Page(context.Background(), Query{Scope: ScopeGroup, GroupID: 1})
	if err != nil {
		t.Fatalf("cannot read the page: %v", err)
	}
	if page.TargetServers != 2 {
		t.Errorf("target = %d servers, want the two that are enabled", page.TargetServers)
	}
}

func TestADisabledServerDoesNotFillThePlaceOfOneThatLacksTheRecord(t *testing.T) {
	// A refresh pass reads only the enabled servers, so a disabled one keeps
	// its cached rows for ever. Counting them let a record two of three
	// servers hold read as complete, and the records page then showed no
	// drift marker for drift that was really there.
	harness := newWriteHarness(t, 3)

	members := harness.groups.members[1]
	members[len(members)-1].Enabled = false
	disabled := members[len(members)-1].ID

	lister := &fakeLister{page: Page{Rows: []Row{
		// Held by one enabled server and by the disabled one.
		{Holders: []int64{1, disabled}, HolderNames: []string{"dns1", "dns3"}},
		// Held by both enabled servers.
		{Holders: []int64{1, 2}, HolderNames: []string{"dns1", "dns2"}},
	}}}
	service := harness.service(lister, &stubQuerier{})

	page, err := service.Page(context.Background(), Query{Scope: ScopeGroup, GroupID: 1})
	if err != nil {
		t.Fatalf("cannot read the page: %v", err)
	}

	if page.TargetServers != 2 {
		t.Fatalf("target = %d servers, want the two that are enabled", page.TargetServers)
	}
	if page.Rows[0].Complete(page.TargetServers) {
		t.Error("a record one enabled server lacks reads as complete")
	}
	if got := page.Rows[0].Holders; len(got) != 1 || got[0] != 1 {
		t.Errorf("holders = %v, want only the enabled server", got)
	}
	// The names are what the operator reads, so they follow the same set.
	if got := page.Rows[0].HolderNames; len(got) != 1 {
		t.Errorf("holder names = %v, want only the enabled server", got)
	}
	if !page.Rows[1].Complete(page.TargetServers) {
		t.Error("a record every enabled server holds reads as incomplete")
	}
}
