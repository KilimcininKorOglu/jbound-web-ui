package store_test

import (
	"context"
	"testing"
	"time"

	"jbound/internal/audit"
	"jbound/internal/server"
	"jbound/internal/store"
)

// auditFixture holds a log with rows from two servers and none from a third
// action, which is what every filter below is measured against.
type auditFixture struct {
	*fixture
	logs  *store.AuditLogs
	first server.Server
}

func newAuditFixture(t *testing.T) *auditFixture {
	t.Helper()

	base := newFixture(t)
	return &auditFixture{
		fixture: base,
		logs:    store.NewAuditLogs(base.db),
		first:   base.mustCreate(t, "dns1"),
	}
}

// write stores one entry at a fixed moment, so the order of the page is the
// order the test wrote rather than the speed of the machine running it.
func (f *auditFixture) write(t *testing.T, entry audit.Entry, minute int) {
	t.Helper()

	at := time.Date(2026, 3, 1, 12, minute, 0, 0, time.UTC)
	if err := f.logs.Write(context.Background(), entry, at); err != nil {
		t.Fatalf("cannot write the audit entry: %v", err)
	}
}

func TestTheAuditPageComesBackNewestFirst(t *testing.T) {
	f := newAuditFixture(t)

	f.write(t, audit.Entry{Username: "dnsadmin", Action: audit.ActionLogin,
		Details: "signed in", IPAddress: "192.0.2.1"}, 1)
	f.write(t, audit.Entry{Username: "dnsadmin", Action: audit.ActionDNSAdd,
		ServerID: &f.first.ID, Details: "added www", IPAddress: "192.0.2.1"}, 2)

	page, err := f.logs.List(context.Background(), audit.Query{})
	if err != nil {
		t.Fatalf("cannot list the log: %v", err)
	}

	if page.Total != 2 {
		t.Fatalf("total = %d, want 2", page.Total)
	}
	if page.Rows[0].Action != audit.ActionDNSAdd {
		t.Errorf("the newest row is %q, want the record change", page.Rows[0].Action)
	}
	if page.Rows[0].ServerName != "dns1" {
		t.Errorf("server name = %q, want dns1", page.Rows[0].ServerName)
	}
	// A login targets no server, so the column stays empty rather than naming
	// one the action never touched.
	if page.Rows[1].ServerID != nil || page.Rows[1].ServerName != "" {
		t.Errorf("the login row names a server: %+v", page.Rows[1])
	}
	if !page.Rows[0].CreatedAt.Equal(
		time.Date(2026, 3, 1, 12, 2, 0, 0, time.UTC)) {
		t.Errorf("created at = %s, want the moment it was written", page.Rows[0].CreatedAt)
	}
}

func TestARowOutlivesTheServerItNames(t *testing.T) {
	// Losing the history of a server the moment it is removed would defeat the
	// point of keeping it.
	f := newAuditFixture(t)
	f.write(t, audit.Entry{Username: "dnsadmin", Action: audit.ActionDNSDelete,
		ServerID: &f.first.ID, Details: "removed www", IPAddress: "192.0.2.1"}, 1)

	if err := f.servers.Delete(context.Background(), f.first.ID); err != nil {
		t.Fatalf("cannot delete the server: %v", err)
	}

	page, err := f.logs.List(context.Background(), audit.Query{})
	if err != nil {
		t.Fatalf("cannot list the log: %v", err)
	}
	if page.Total != 1 {
		t.Fatalf("total = %d, want the row to survive", page.Total)
	}
	if page.Rows[0].Details != "removed www" {
		t.Errorf("the row lost its details: %+v", page.Rows[0])
	}
	if page.Rows[0].ServerName != "" {
		t.Errorf("server name = %q, want it empty", page.Rows[0].ServerName)
	}
}

func TestTheAuditFiltersNarrowTheSameRows(t *testing.T) {
	f := newAuditFixture(t)
	second := f.mustCreate(t, "dns2")

	f.write(t, audit.Entry{Username: "dnsadmin", Action: audit.ActionLogin,
		Details: "signed in", IPAddress: "192.0.2.1"}, 1)
	f.write(t, audit.Entry{Username: "dnsuser", Action: audit.ActionDNSAdd,
		ServerID: &f.first.ID, Details: "added www.example.local", IPAddress: "10.0.0.5"}, 2)
	f.write(t, audit.Entry{Username: "dnsadmin", Action: audit.ActionDNSAdd,
		ServerID: &second.ID, Details: "added mail.example.local", IPAddress: "10.0.0.6"}, 3)

	cases := []struct {
		name  string
		query audit.Query
		want  int
	}{
		{name: "no filter", want: 3},
		{name: "one action", query: audit.Query{Action: audit.ActionDNSAdd}, want: 2},
		{name: "one server", query: audit.Query{ServerID: second.ID}, want: 1},
		{name: "a name in the details", query: audit.Query{Search: "mail"}, want: 1},
		{name: "a user name", query: audit.Query{Search: "dnsuser"}, want: 1},
		{name: "an address", query: audit.Query{Search: "10.0.0.6"}, want: 1},
		{name: "the search ignores case", query: audit.Query{Search: "DNSADMIN"}, want: 2},
		{
			name:  "two filters narrow together",
			query: audit.Query{Action: audit.ActionDNSAdd, Search: "dnsadmin"},
			want:  1,
		},
		{name: "a filter nothing matches", query: audit.Query{Search: "ftp"}, want: 0},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			page, err := f.logs.List(context.Background(), testCase.query)
			if err != nil {
				t.Fatalf("cannot list the log: %v", err)
			}
			if page.Total != testCase.want {
				t.Errorf("total = %d, want %d", page.Total, testCase.want)
			}
			if len(page.Rows) != testCase.want {
				t.Errorf("%d rows came back, and the count says %d",
					len(page.Rows), page.Total)
			}
		})
	}
}

func TestTheAuditSearchTakesAWildcardLiterally(t *testing.T) {
	// A percent sign in the box is a character the operator typed, not a
	// pattern. Without the escape it would match every row.
	f := newAuditFixture(t)

	f.write(t, audit.Entry{Username: "dnsadmin", Action: audit.ActionDNSAdd,
		Details: "added 100% cache", IPAddress: "192.0.2.1"}, 1)
	f.write(t, audit.Entry{Username: "dnsadmin", Action: audit.ActionDNSAdd,
		Details: "added www", IPAddress: "192.0.2.1"}, 2)

	page, err := f.logs.List(context.Background(), audit.Query{Search: "100%"})
	if err != nil {
		t.Fatalf("cannot list the log: %v", err)
	}
	if page.Total != 1 {
		t.Errorf("total = %d, want the literal match alone", page.Total)
	}
}

func TestTheAuditPageIsBounded(t *testing.T) {
	f := newAuditFixture(t)
	for i := range 12 {
		f.write(t, audit.Entry{Username: "dnsadmin", Action: audit.ActionLogin,
			Details: "signed in", IPAddress: "192.0.2.1"}, i)
	}

	page, err := f.logs.List(context.Background(), audit.Query{Page: 2, PerPage: 10})
	if err != nil {
		t.Fatalf("cannot list the log: %v", err)
	}

	if page.Total != 12 || page.TotalPages != 2 {
		t.Fatalf("total = %d over %d pages, want 12 over 2", page.Total, page.TotalPages)
	}
	if len(page.Rows) != 2 {
		t.Errorf("the second page holds %d rows, want 2", len(page.Rows))
	}
}

func TestAnEntryWrittenInATransactionLeavesWithIt(t *testing.T) {
	// The import command writes a whole trail or none of it, which only works
	// if the insert takes part in the caller's transaction rather than opening
	// one of its own.
	ctx := context.Background()
	f := newFixture(t)
	logs := store.NewAuditLogs(f.db)

	tx, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("cannot start a transaction: %v", err)
	}

	entry := audit.Entry{Username: "dnsadmin", Action: audit.ActionLogin,
		Details: "rolled back", IPAddress: "10.0.0.5"}
	if err := store.WriteAuditTx(ctx, tx, entry, time.Now()); err != nil {
		t.Fatalf("cannot write inside the transaction: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("cannot roll back: %v", err)
	}

	page, err := logs.List(ctx, audit.Query{Page: 1, PerPage: 25})
	if err != nil {
		t.Fatalf("cannot list the trail: %v", err)
	}
	if page.Total != 0 {
		t.Errorf("the trail holds %d rows after a rollback, want 0", page.Total)
	}

	// And the committed case, so the test does not pass simply because nothing
	// was ever written.
	tx, err = f.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("cannot start a second transaction: %v", err)
	}
	if err := store.WriteAuditTx(ctx, tx, entry, time.Now()); err != nil {
		t.Fatalf("cannot write inside the transaction: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("cannot commit: %v", err)
	}

	page, err = logs.List(ctx, audit.Query{Page: 1, PerPage: 25})
	if err != nil {
		t.Fatalf("cannot list the trail: %v", err)
	}
	if page.Total != 1 {
		t.Errorf("the trail holds %d rows after a commit, want 1", page.Total)
	}
}

// --- What the SIEM sender reads -------------------------------------------

func TestTheRowsAfterACursorComeBackOldestFirst(t *testing.T) {
	// A receiver has to be told what happened in the order it happened, which
	// is the opposite of the order the page shows.
	f := newAuditFixture(t)

	for i, action := range []string{
		audit.ActionLogin, audit.ActionDNSAdd, audit.ActionDNSDelete,
	} {
		f.write(t, audit.Entry{UID: 1000, Username: "dnsadmin", Action: action}, i)
	}

	rows, err := f.logs.After(context.Background(), 0, 10)
	if err != nil {
		t.Fatalf("After returned an error: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("got %d rows, want 3", len(rows))
	}
	if rows[0].Action != audit.ActionLogin || rows[2].Action != audit.ActionDNSDelete {
		t.Errorf("the rows are not oldest first: %v", []string{
			rows[0].Action, rows[1].Action, rows[2].Action})
	}
}

func TestACursorSkipsTheRowsItAlreadyNames(t *testing.T) {
	f := newAuditFixture(t)

	for i, action := range []string{
		audit.ActionLogin, audit.ActionDNSAdd, audit.ActionDNSDelete,
	} {
		f.write(t, audit.Entry{UID: 1000, Username: "dnsadmin", Action: action}, i)
	}

	all, err := f.logs.After(context.Background(), 0, 10)
	if err != nil {
		t.Fatalf("After returned an error: %v", err)
	}

	rest, err := f.logs.After(context.Background(), all[0].ID, 10)
	if err != nil {
		t.Fatalf("After returned an error: %v", err)
	}
	if len(rest) != 2 || rest[0].Action != audit.ActionDNSAdd {
		t.Errorf("got %d rows starting with %q", len(rest), rest[0].Action)
	}
}

func TestOneRoundReadsAContiguousRunOfIdentifiers(t *testing.T) {
	// An audit import writes rows whose timestamps are older than rows already
	// in the trail. Ordering a round by created_at would make the batch a
	// scattered set of identifiers, and a sender that then remembers the last
	// one it saw would step over everything in between.
	f := newAuditFixture(t)

	f.write(t, audit.Entry{UID: 1000, Username: "dnsadmin", Action: audit.ActionLogin}, 30)
	f.write(t, audit.Entry{UID: 1000, Username: "dnsadmin", Action: audit.ActionDNSAdd}, 40)
	// Written last, dated first, which is what an import looks like.
	f.write(t, audit.Entry{UID: 1000, Username: "dnsadmin",
		Action: audit.ActionAuditImport}, 1)

	rows, err := f.logs.After(context.Background(), 0, 2)
	if err != nil {
		t.Fatalf("After returned an error: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	if rows[1].ID != rows[0].ID+1 {
		t.Errorf("the round skipped an identifier: %d then %d", rows[0].ID, rows[1].ID)
	}
	if rows[0].Action != audit.ActionLogin || rows[1].Action != audit.ActionDNSAdd {
		t.Errorf("the round was ordered by time rather than by identifier: %v",
			[]string{rows[0].Action, rows[1].Action})
	}
}

func TestTheLimitBoundsWhatOneRoundReads(t *testing.T) {
	f := newAuditFixture(t)
	for i := range 5 {
		f.write(t, audit.Entry{UID: 1000, Username: "dnsadmin", Action: audit.ActionLogin}, i)
	}

	rows, err := f.logs.After(context.Background(), 0, 2)
	if err != nil {
		t.Fatalf("After returned an error: %v", err)
	}
	if len(rows) != 2 {
		t.Errorf("got %d rows, want the limit of 2", len(rows))
	}
}

func TestARowKeepsItsServerNameForTheReceiver(t *testing.T) {
	// The CEF dhost field carries it, so a receiver reads the target as a name
	// rather than as a row identifier out of the panel database.
	f := newAuditFixture(t)
	id := f.first.ID
	f.write(t, audit.Entry{UID: 1000, Username: "dnsadmin",
		ServerID: &id, Action: audit.ActionDNSAdd}, 0)

	rows, err := f.logs.After(context.Background(), 0, 10)
	if err != nil {
		t.Fatalf("After returned an error: %v", err)
	}
	if len(rows) != 1 || rows[0].ServerName != "dns1" {
		t.Errorf("the server name did not travel with the row: %+v", rows)
	}
}

// --- The cursor -----------------------------------------------------------

func TestACursorNobodyWroteReadsAsZero(t *testing.T) {
	f := newFixture(t)
	cursor := store.NewSIEMCursor(f.db)

	last, err := cursor.Read(context.Background())
	if err != nil {
		t.Fatalf("Read returned an error: %v", err)
	}
	if last != 0 {
		t.Errorf("last = %d, want 0", last)
	}
}

func TestTheCursorComesBackTheWayItWasWritten(t *testing.T) {
	f := newFixture(t)
	cursor := store.NewSIEMCursor(f.db)
	ctx := context.Background()

	if err := cursor.Write(ctx, 42); err != nil {
		t.Fatalf("Write returned an error: %v", err)
	}
	if last, _ := cursor.Read(ctx); last != 42 {
		t.Errorf("last = %d, want 42", last)
	}

	// Twice, because the second call takes the conflict branch rather than the
	// insert, and a broken upsert would only show there.
	if err := cursor.Write(ctx, 43); err != nil {
		t.Fatalf("the second write returned an error: %v", err)
	}
	if last, _ := cursor.Read(ctx); last != 43 {
		t.Errorf("last = %d, want 43", last)
	}
}

func TestTheCursorNeverMovesBackwards(t *testing.T) {
	// A caller that read a stale value would otherwise send the receiver rows
	// it already holds.
	f := newFixture(t)
	cursor := store.NewSIEMCursor(f.db)
	ctx := context.Background()

	if err := cursor.Write(ctx, 100); err != nil {
		t.Fatalf("Write returned an error: %v", err)
	}
	if err := cursor.Write(ctx, 40); err != nil {
		t.Fatalf("Write returned an error: %v", err)
	}

	if last, _ := cursor.Read(ctx); last != 100 {
		t.Errorf("last = %d, want it to stay at 100", last)
	}
}

func TestTheNewestIdentifierIsWhereForwardingStarts(t *testing.T) {
	// Enabling a receiver must not empty months of trail into it.
	f := newAuditFixture(t)
	cursor := store.NewSIEMCursor(f.db)
	ctx := context.Background()

	if newest, _ := cursor.NewestAuditID(ctx); newest != 0 {
		t.Errorf("an empty trail reports %d, want 0", newest)
	}

	for i := range 3 {
		f.write(t, audit.Entry{UID: 1000, Username: "dnsadmin", Action: audit.ActionLogin}, i)
	}

	newest, err := cursor.NewestAuditID(ctx)
	if err != nil {
		t.Fatalf("NewestAuditID returned an error: %v", err)
	}
	rows, _ := f.logs.After(ctx, 0, 10)
	if newest != rows[len(rows)-1].ID {
		t.Errorf("newest = %d, want the last row %d", newest, rows[len(rows)-1].ID)
	}

	if pending, _ := cursor.Pending(ctx, newest); pending != 0 {
		t.Errorf("pending = %d after starting at the newest row, want 0", pending)
	}
}

func TestThePendingCountIsWhatTheReceiverIsOwed(t *testing.T) {
	f := newAuditFixture(t)
	cursor := store.NewSIEMCursor(f.db)
	ctx := context.Background()

	for i := range 4 {
		f.write(t, audit.Entry{UID: 1000, Username: "dnsadmin", Action: audit.ActionLogin}, i)
	}

	rows, _ := f.logs.After(ctx, 0, 10)
	if pending, _ := cursor.Pending(ctx, rows[1].ID); pending != 2 {
		t.Errorf("pending = %d, want 2", pending)
	}
	if pending, _ := cursor.Pending(ctx, 0); pending != 4 {
		t.Errorf("pending = %d, want 4", pending)
	}
}
