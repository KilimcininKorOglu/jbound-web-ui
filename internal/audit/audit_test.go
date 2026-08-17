package audit

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
	"time"

	"jbound/internal/paging"
)

// fakeRepo records what the logger stored.
type fakeRepo struct {
	entries []Entry
	at      []time.Time
	err     error

	page      Page
	lastQuery Query
	listErr   error

	// ctxErr is what the context said when the write arrived, and deadline is
	// how long it had left. A row that must survive a cancelled request is
	// checked against both.
	ctxErr   error
	deadline time.Time
}

func (f *fakeRepo) Write(ctx context.Context, entry Entry, at time.Time) error {
	f.entries = append(f.entries, entry)
	f.at = append(f.at, at)
	f.ctxErr = ctx.Err()
	f.deadline, _ = ctx.Deadline()
	return f.err
}

func (f *fakeRepo) List(_ context.Context, query Query) (Page, error) {
	f.lastQuery = query
	return f.page, f.listErr
}

func TestAnEntryWithoutAnActionIsRefused(t *testing.T) {
	// A row nobody can filter on is worse than no row, because it reads as a
	// complete log that happens to be missing the event.
	repo := &fakeRepo{}
	logger := NewLogger(repo)

	if err := logger.Write(context.Background(), Entry{Username: "dnsadmin"}); err == nil {
		t.Fatal("the logger accepted an entry with no action")
	}
	if len(repo.entries) != 0 {
		t.Errorf("the entry was stored anyway: %+v", repo.entries)
	}
}

func TestTheMissingFieldsReadAsWords(t *testing.T) {
	repo := &fakeRepo{}
	logger := NewLogger(repo)

	if err := logger.Write(context.Background(), Entry{Action: ActionCacheRefresh}); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	stored := repo.entries[0]
	if stored.Username != "system" {
		t.Errorf("username = %q, want system", stored.Username)
	}
	if stored.IPAddress != "unknown" {
		t.Errorf("ip = %q, want unknown", stored.IPAddress)
	}
}

func TestTheStoredTimeIsUTC(t *testing.T) {
	// Every timestamp in the database is UTC. A row written in local time
	// would sort against the others and read hours off in the log.
	repo := &fakeRepo{}
	logger := NewLogger(repo)

	if err := logger.Write(context.Background(), Entry{Action: ActionLogin}); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if zone, _ := repo.at[0].Zone(); zone != "UTC" {
		t.Errorf("the entry was stored in %s", zone)
	}
}

// The queue reads the row out of the database rather than being handed the
// entry, so the wake-up is worth nothing until the row is there.
func TestTheQueueIsWokenOnceTheRowHasLanded(t *testing.T) {
	repo := &fakeRepo{}
	woken := 0
	logger := NewLogger(repo).WithNotify(func() { woken++ })

	if err := logger.Write(context.Background(), Entry{Action: ActionLogin}); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if woken != 1 {
		t.Errorf("the queue was woken %d times, want 1", woken)
	}
}

func TestTheQueueIsNotWokenForARowThatWasNotWritten(t *testing.T) {
	// A wake-up over a failed insert sends the queue looking for a row that is
	// not there, and the failure would read as a delivery that is late.
	woken := 0
	for _, tc := range []struct {
		name  string
		repo  *fakeRepo
		entry Entry
	}{
		{"the database refused it", &fakeRepo{err: errors.New("database is locked")},
			Entry{Action: ActionServerDelete}},
		{"the entry had no action", &fakeRepo{}, Entry{Username: "dnsadmin"}},
	} {
		logger := NewLogger(tc.repo).WithNotify(func() { woken++ })
		if err := logger.Write(context.Background(), tc.entry); err == nil {
			t.Errorf("%s: the caller was not told", tc.name)
		}
	}
	if woken != 0 {
		t.Errorf("the queue was woken %d times, want none", woken)
	}
}

// The wake-up is optional. A panel that never forwards, and every caller that
// has no queue, hand the logger nothing to call.
func TestAPanelWithoutAQueueStillWrites(t *testing.T) {
	repo := &fakeRepo{}
	logger := NewLogger(repo)

	if err := logger.Write(context.Background(), Entry{Action: ActionLogout}); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if len(repo.entries) != 1 {
		t.Errorf("the entry was stored %d times, want 1", len(repo.entries))
	}
}

func TestTheListingIsHandedToTheRepository(t *testing.T) {
	repo := &fakeRepo{page: Page{Window: paging.Window{Total: 3}}}
	logger := NewLogger(repo)

	page, err := logger.List(context.Background(), Query{Action: ActionDNSAdd, PerPage: 25})
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if page.Total != 3 {
		t.Errorf("total = %d, want 3", page.Total)
	}
	if repo.lastQuery.Action != ActionDNSAdd {
		t.Errorf("the query lost its filter: %+v", repo.lastQuery)
	}
}

func TestThePageBoundsAreClamped(t *testing.T) {
	cases := []struct {
		name    string
		query   Query
		perPage int
		page    int
	}{
		{name: "an empty query takes the default", perPage: DefaultPerPage, page: 1},
		{name: "a page of five is raised to the minimum",
			query: Query{PerPage: 5}, perPage: paging.Min, page: 1},
		{name: "a page of a thousand is cut to the maximum",
			query: Query{PerPage: 1000}, perPage: paging.Max, page: 1},
		{name: "page zero is the first page",
			query: Query{Page: 0}, perPage: DefaultPerPage, page: 1},
		{name: "a negative page is the first page",
			query: Query{Page: -4}, perPage: DefaultPerPage, page: 1},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			query := testCase.query
			query.Normalise()

			if query.PerPage != testCase.perPage {
				t.Errorf("per page = %d, want %d", query.PerPage, testCase.perPage)
			}
			if query.Page != testCase.page {
				t.Errorf("page = %d, want %d", query.Page, testCase.page)
			}
		})
	}
}

func TestAPageBeyondTheEndFallsBackToTheLastOne(t *testing.T) {
	// A page number out of range comes from a stale link rather than from a
	// page nobody wrote, so it reads better as the last page than as empty.
	query := Query{Page: 9, PerPage: 10}
	page := NewPage(query, 25)

	if page.TotalPages != 3 {
		t.Errorf("total pages = %d, want 3", page.TotalPages)
	}
	if page.Page != 3 {
		t.Errorf("page = %d, want 3", page.Page)
	}
	if page.Offset() != 20 {
		t.Errorf("offset = %d, want 20", page.Offset())
	}
}

func TestAnEmptyLogStillHasOnePage(t *testing.T) {
	page := NewPage(Query{Page: 1, PerPage: 50}, 0)

	if page.TotalPages != 1 {
		t.Errorf("total pages = %d, want 1", page.TotalPages)
	}
	if page.Offset() != 0 {
		t.Errorf("offset = %d, want 0", page.Offset())
	}
}

func TestTheFilterOffersEveryActionThePanelWrites(t *testing.T) {
	// The list is read off the source rather than repeated here. An action
	// added as a constant and forgotten in the filter would otherwise be an
	// action the log cannot be narrowed to.
	declared := declaredActions(t)
	offered := map[string]bool{}
	for _, action := range Actions() {
		if offered[action] {
			t.Errorf("the filter offers %q twice", action)
		}
		offered[action] = true
	}

	for name, value := range declared {
		if !offered[value] {
			t.Errorf("%s writes %q, which the filter does not offer", name, value)
		}
	}
	if len(offered) != len(declared) {
		t.Errorf("the filter offers %d actions, and the panel writes %d",
			len(offered), len(declared))
	}
}

// declaredActions reads every Action constant out of the package source.
func declaredActions(t *testing.T) map[string]string {
	t.Helper()

	file, err := parser.ParseFile(token.NewFileSet(), "audit.go", nil, 0)
	if err != nil {
		t.Fatalf("cannot read audit.go: %v", err)
	}

	found := map[string]string{}
	ast.Inspect(file, func(node ast.Node) bool {
		spec, ok := node.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for i, name := range spec.Names {
			if !strings.HasPrefix(name.Name, "Action") || i >= len(spec.Values) {
				continue
			}
			literal, ok := spec.Values[i].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				continue
			}
			value, err := strconv.Unquote(literal.Value)
			if err != nil {
				t.Fatalf("cannot read the value of %s: %v", name.Name, err)
			}
			found[name.Name] = value
		}
		return true
	})

	if len(found) == 0 {
		t.Fatal("no action constant was found in audit.go")
	}
	return found
}

func TestACancelledRequestStillGetsItsAuditRow(t *testing.T) {
	// The entry describes a resolver that has already been changed. htmx
	// cancels a request whenever it fires a second one from the same element,
	// and that used to take the row with it.
	repo := &fakeRepo{}
	logger := NewLogger(repo)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := logger.Write(ctx, Entry{
		Username: "dnsadmin", Action: ActionDNSAdd, Details: "Added A record",
	}); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	if len(repo.entries) != 1 {
		t.Fatalf("stored %d entries, want 1", len(repo.entries))
	}
	if repo.ctxErr != nil {
		t.Errorf("the store was handed a dead context: %v", repo.ctxErr)
	}
}

func TestTheDetachedWriteIsStillBounded(t *testing.T) {
	// Detaching the cancellation must not hand the store a context that never
	// ends, or an unavailable database holds the caller for ever.
	repo := &fakeRepo{}
	logger := NewLogger(repo)

	if err := logger.Write(context.Background(), Entry{
		Username: "dnsadmin", Action: ActionDNSAdd,
	}); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if repo.deadline.IsZero() {
		t.Fatal("the store was handed a context with no deadline")
	}
	if left := time.Until(repo.deadline); left <= 0 || left > storeTimeout {
		t.Errorf("deadline in %s, want at most %s", left, storeTimeout)
	}
}
