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
)

// fakeRepo records what the logger stored.
type fakeRepo struct {
	entries []Entry
	at      []time.Time
	err     error

	page      Page
	lastQuery Query
	listErr   error
}

func (f *fakeRepo) Write(_ context.Context, entry Entry, at time.Time) error {
	f.entries = append(f.entries, entry)
	f.at = append(f.at, at)
	return f.err
}

func (f *fakeRepo) List(_ context.Context, query Query) (Page, error) {
	f.lastQuery = query
	return f.page, f.listErr
}

// fakeForwarder records what the logger mirrored.
type fakeForwarder struct {
	entries []Entry
	err     error
}

func (f *fakeForwarder) Forward(entry Entry) error {
	f.entries = append(f.entries, entry)
	return f.err
}

func TestAnEntryWithoutAnActionIsRefused(t *testing.T) {
	// A row nobody can filter on is worse than no row, because it reads as a
	// complete log that happens to be missing the event.
	repo := &fakeRepo{}
	logger := NewLogger(repo, nil)

	if err := logger.Write(context.Background(), Entry{Username: "dnsadmin"}); err == nil {
		t.Fatal("the logger accepted an entry with no action")
	}
	if len(repo.entries) != 0 {
		t.Errorf("the entry was stored anyway: %+v", repo.entries)
	}
}

func TestTheMissingFieldsReadAsWords(t *testing.T) {
	repo := &fakeRepo{}
	logger := NewLogger(repo, nil)

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
	logger := NewLogger(repo, nil)

	if err := logger.Write(context.Background(), Entry{Action: ActionLogin}); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if zone, _ := repo.at[0].Zone(); zone != "UTC" {
		t.Errorf("the entry was stored in %s", zone)
	}
}

func TestTheEntryIsMirroredWithTheServerName(t *testing.T) {
	// The name never reaches the database. It travels with the entry so the
	// forwarded event can say which machine the action landed on.
	repo := &fakeRepo{}
	forwarder := &fakeForwarder{}
	logger := NewLogger(repo, forwarder)

	id := int64(7)
	err := logger.Write(context.Background(), Entry{
		Action: ActionDNSAdd, Username: "dnsadmin", ServerID: &id, ServerName: "dns2"})
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}

	if len(forwarder.entries) != 1 {
		t.Fatalf("the entry was forwarded %d times, want 1", len(forwarder.entries))
	}
	if forwarder.entries[0].ServerName != "dns2" {
		t.Errorf("server name = %q, want dns2", forwarder.entries[0].ServerName)
	}
}

func TestAForwarderThatIsDownDoesNotFailTheAction(t *testing.T) {
	// The entry is in the database. Failing a record change over a syslog
	// socket would cost more than the mirror is worth.
	repo := &fakeRepo{}
	forwarder := &fakeForwarder{err: errors.New("connection refused")}
	logger := NewLogger(repo, forwarder)

	if err := logger.Write(context.Background(), Entry{Action: ActionLogin}); err != nil {
		t.Errorf("write returned %v, want nil", err)
	}
}

func TestADatabaseFailureStillReachesTheMirror(t *testing.T) {
	// The mirror sits off the panel host, which is exactly where a record is
	// worth having when the panel database is the thing that went wrong.
	repo := &fakeRepo{err: errors.New("database is locked")}
	forwarder := &fakeForwarder{}
	logger := NewLogger(repo, forwarder)

	if err := logger.Write(context.Background(), Entry{Action: ActionServerDelete}); err == nil {
		t.Error("the caller was not told that the entry could not be stored")
	}
	if len(forwarder.entries) != 1 {
		t.Errorf("the entry was forwarded %d times, want 1", len(forwarder.entries))
	}
}

// The switch stops the mirror and nothing else. The database is the primary
// record, so an operator silencing a noisy receiver must not lose the trail.
func TestForwardingOffStillWritesTheEntry(t *testing.T) {
	repo := &fakeRepo{}
	forwarder := &fakeForwarder{}
	logger := NewLogger(repo, forwarder).WithForwarding(func() bool { return false })

	if err := logger.Write(context.Background(), Entry{Action: ActionLogin}); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	if len(repo.entries) != 1 {
		t.Errorf("%d row(s) written, want 1", len(repo.entries))
	}
	if len(forwarder.entries) != 0 {
		t.Errorf("%d entry(s) forwarded with the switch off, want none",
			len(forwarder.entries))
	}
}

// The switch is read per entry rather than held, so turning it back on takes
// effect on the next action.
func TestForwardingResumesWhenTheSwitchGoesBackOn(t *testing.T) {
	repo := &fakeRepo{}
	forwarder := &fakeForwarder{}

	enabled := false
	logger := NewLogger(repo, forwarder).WithForwarding(func() bool { return enabled })

	ctx := context.Background()
	if err := logger.Write(ctx, Entry{Action: ActionLogin}); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	enabled = true
	if err := logger.Write(ctx, Entry{Action: ActionLogout}); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	if len(forwarder.entries) != 1 {
		t.Fatalf("%d entry(s) forwarded, want the second one only",
			len(forwarder.entries))
	}
	if forwarder.entries[0].Action != ActionLogout {
		t.Errorf("forwarded %s, want %s", forwarder.entries[0].Action, ActionLogout)
	}
}

func TestAPanelWithoutASIEMStillWrites(t *testing.T) {
	repo := &fakeRepo{}
	logger := NewLogger(repo, nil)

	if err := logger.Write(context.Background(), Entry{Action: ActionLogout}); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if len(repo.entries) != 1 {
		t.Errorf("the entry was stored %d times, want 1", len(repo.entries))
	}
}

func TestTheListingIsHandedToTheRepository(t *testing.T) {
	repo := &fakeRepo{page: Page{Total: 3}}
	logger := NewLogger(repo, nil)

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
			query: Query{PerPage: 5}, perPage: MinPerPage, page: 1},
		{name: "a page of a thousand is cut to the maximum",
			query: Query{PerPage: 1000}, perPage: MaxPerPage, page: 1},
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
