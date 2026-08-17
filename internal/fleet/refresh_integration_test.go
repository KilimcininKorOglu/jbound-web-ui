//go:build integration

// Exercises the cache refresh against the development targets.
//
// What cannot be proven with a fake is the round trip: whether the file a real
// server holds parses into the records the panel shows, and whether a server
// that goes away leaves those records in place.
//
// Run it with: make dev-itest

package fleet_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"jbound/internal/audit"
	"jbound/internal/database"
	"jbound/internal/dnsquery"
	"jbound/internal/fleet"
	"jbound/internal/paging"
	"jbound/internal/server"
	"jbound/internal/settings"
	"jbound/internal/store"
	"jbound/internal/transport"
)

const (
	testTarget  = "dns1"
	testUser    = "dnsops"
	testKeyPath = "/var/lib/jbound/keys/dev_ed25519"

	// unreachable is from the RFC 5737 documentation block, so a connection
	// there times out rather than landing somewhere real.
	unreachable = "192.0.2.1"
)

type harness struct {
	refresher *fleet.Refresher
	service   *fleet.Service
	servers   *store.Servers
	records   *store.Records
	states    *store.States
	record    server.Server
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	ctx := context.Background()

	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatalf("cannot open the test database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	dataDir := t.TempDir()
	keys, err := server.NewKeyStore(dataDir)
	if err != nil {
		t.Fatalf("cannot create the key store: %v", err)
	}

	pool := transport.NewPool(ctx, settings.Fixed(30*time.Second))
	t.Cleanup(pool.Close)

	servers := store.NewServers(db.DB)
	records := store.NewRecords(db.DB)
	states := store.NewStates(db.DB)
	timeouts := settings.Fixed(server.Timeouts{Connect: 5 * time.Second, Command: 15 * time.Second})

	auditLog := audit.NewLogger(store.NewAuditLogs(db.DB))
	service := server.NewService(servers, store.NewGroups(db.DB), keys, pool,
		auditLog, dataDir, timeouts)

	material, err := os.ReadFile(testKeyPath)
	if err != nil {
		t.Fatalf("the development key is missing, run the tests inside the stack: %v", err)
	}

	record, _, err := service.Create(ctx,
		server.Actor{UID: 1001, Username: "dnsadmin", IPAddress: "203.0.113.5"},
		server.CreateInput{
			Server: server.Server{
				Name: testTarget, Host: testTarget, SSHUser: testUser, Enabled: true,
				// The containers carry no systemd, so the init script answers.
				StatusCmd: "/usr/sbin/service unbound status",
			},
			PrivateKey: string(material),
		})
	if err != nil {
		t.Fatalf("cannot store the target: %v", err)
	}

	// The refresh needs an approved host key, which is its own action.
	offer, err := service.ScanHostKey(ctx, record.ID)
	if err != nil {
		t.Fatalf("cannot read the host key: %v", err)
	}
	if err := servers.SetHostKey(ctx, record.ID, offer.AuthorizedKey); err != nil {
		t.Fatalf("cannot store the host key: %v", err)
	}
	record.HostKey = offer.AuthorizedKey

	refresher := fleet.NewRefresher(servers, records, states, pool, dataDir, timeouts, settings.Fixed(2))
	writer := fleet.NewWriter(servers, service, pool, refresher, auditLog,
		store.NewBackups(db.DB), dataDir, timeouts, settings.Fixed(2))

	return &harness{
		refresher: refresher,
		service: fleet.NewService(records, states, writer, refresher,
			dnsquery.New("dig", settings.Fixed(10*time.Second)), auditLog,
			settings.Fixed(15*time.Minute), settings.Fixed(fleet.DefaultPerPage)),
		servers: servers,
		records: records,
		states:  states,
		record:  record,
	}
}

func (h *harness) cached(t *testing.T) fleet.Page {
	t.Helper()

	page, err := h.records.List(context.Background(), fleet.Query{PerPage: paging.Max})
	if err != nil {
		t.Fatalf("cannot read the cached records: %v", err)
	}
	return page
}

func TestRefreshReadsTheSeededTarget(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	result, err := h.refresher.One(ctx, h.record.ID)
	if err != nil {
		t.Fatalf("One returned an error: %v", err)
	}
	if !result.OK() {
		t.Fatalf("the refresh failed: %v", result.Err)
	}
	if result.Records == 0 {
		t.Fatal("the seeded target parsed to nothing")
	}

	page := h.cached(t)
	if page.Total != result.Records {
		t.Errorf("the cache holds %d records, the read found %d", page.Total, result.Records)
	}

	var seen bool
	for _, row := range page.Rows {
		if row.FQDN == "ns1.example.local" && row.Type == "A" {
			seen = true
		}
		if len(row.HolderNames) != 1 || row.HolderNames[0] != testTarget {
			t.Errorf("a row is attributed to %v", row.HolderNames)
		}
	}
	if !seen {
		t.Errorf("the seeded record is not in the cache:\n%+v", page.Rows)
	}

	state, err := h.states.Get(ctx, h.record.ID)
	if err != nil {
		t.Fatalf("Get returned an error: %v", err)
	}
	if !state.Reachable || state.FileSHA256 == "" || state.FetchedAt == nil {
		t.Errorf("got %+v", state)
	}
	if !state.UnboundActive {
		t.Error("the resolver on the target is not reported as running")
	}
}

func TestAServerThatGoesAwayKeepsItsRecords(t *testing.T) {
	// An empty page says less than old records with a warning next to them.
	h := newHarness(t)
	ctx := context.Background()

	if result, err := h.refresher.One(ctx, h.record.ID); err != nil || !result.OK() {
		t.Fatalf("the first refresh failed: %v %v", err, result.Err)
	}
	before := h.cached(t)
	if before.Total == 0 {
		t.Fatal("the first refresh cached nothing")
	}

	// Move the record to an address nothing answers on, which is what a server
	// that has gone away looks like from here.
	moved := h.record
	moved.Host = unreachable
	if err := h.servers.Update(ctx, moved); err != nil {
		t.Fatalf("Update returned an error: %v", err)
	}

	result, err := h.refresher.One(ctx, h.record.ID)
	if err != nil {
		t.Fatalf("One returned an error: %v", err)
	}
	if result.OK() {
		t.Fatal("the refresh reported success against an unreachable server")
	}

	after := h.cached(t)
	if after.Total != before.Total {
		t.Errorf("the cache went from %d records to %d", before.Total, after.Total)
	}

	state, err := h.states.Get(ctx, h.record.ID)
	if err != nil {
		t.Fatalf("Get returned an error: %v", err)
	}
	if state.Reachable {
		t.Error("an unreachable server is still marked reachable")
	}
	if state.LastError == "" {
		t.Error("the failure was not recorded")
	}
	if state.FetchedAt == nil {
		t.Fatal("the time of the last successful read was forgotten")
	}
	if !state.Stale(state.FetchedAt.Add(time.Hour), 15*time.Minute) {
		t.Error("a server nobody could read for an hour is not stale")
	}
}

func TestRefreshingTwiceLeavesTheSameRecords(t *testing.T) {
	// The whole set is replaced on every pass, so a refresh that duplicated or
	// dropped rows would show up here rather than on somebody's screen.
	h := newHarness(t)
	ctx := context.Background()

	if _, err := h.refresher.One(ctx, h.record.ID); err != nil {
		t.Fatalf("the first refresh failed: %v", err)
	}
	first := h.cached(t)

	if _, err := h.refresher.One(ctx, h.record.ID); err != nil {
		t.Fatalf("the second refresh failed: %v", err)
	}
	second := h.cached(t)

	if first.Total != second.Total {
		t.Fatalf("the cache went from %d records to %d", first.Total, second.Total)
	}
	for i := range first.Rows {
		if first.Rows[i].Raw != second.Rows[i].Raw {
			t.Errorf("row %d changed:\n  %s\n  %s", i, first.Rows[i].Raw, second.Rows[i].Raw)
		}
	}
}

func TestAllReadsEveryEnabledServer(t *testing.T) {
	h := newHarness(t)

	results, err := h.refresher.All(context.Background())
	if err != nil {
		t.Fatalf("All returned an error: %v", err)
	}
	if len(results) != 1 || !results[0].OK() {
		t.Fatalf("got %+v", results)
	}
	if results[0].ServerName != testTarget {
		t.Errorf("the result names %q", results[0].ServerName)
	}
}
