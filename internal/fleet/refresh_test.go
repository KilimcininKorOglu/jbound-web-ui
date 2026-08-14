package fleet

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"unbound-web/internal/dnsfile"
	"unbound-web/internal/server"
	"unbound-web/internal/settings"
	"unbound-web/internal/transport"
)

// --- Fakes -----------------------------------------------------------------

type fakeServers struct {
	records map[int64]server.Server
}

func (f *fakeServers) ListEnabled(context.Context) ([]server.Server, error) {
	var enabled []server.Server
	for _, record := range f.records {
		if record.Enabled {
			enabled = append(enabled, record)
		}
	}
	return enabled, nil
}

func (f *fakeServers) Get(_ context.Context, id int64) (server.Server, error) {
	record, ok := f.records[id]
	if !ok {
		return server.Server{}, errors.New("not found")
	}
	return record, nil
}

type fakeRecords struct {
	mu      sync.Mutex
	byID    map[int64][]dnsfile.Record
	written int
	err     error
}

func (f *fakeRecords) Replace(_ context.Context, serverID int64, records []dnsfile.Record) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.err != nil {
		return f.err
	}
	f.byID[serverID] = records
	f.written++
	return nil
}

func (f *fakeRecords) get(serverID int64) []dnsfile.Record {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.byID[serverID]
}

type fakeStates struct {
	mu       sync.Mutex
	states   map[int64]State
	failures map[int64]string
}

func (f *fakeStates) SetFetched(_ context.Context, state State) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.states[state.ServerID] = state
	delete(f.failures, state.ServerID)
	return nil
}

func (f *fakeStates) SetUnreachable(_ context.Context, serverID int64, failure string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.failures[serverID] = failure
	state := f.states[serverID]
	state.ServerID = serverID
	state.Reachable = false
	state.LastError = failure
	f.states[serverID] = state
	return nil
}

func (f *fakeStates) SetApplied(_ context.Context, serverID int64, digest string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	state := f.states[serverID]
	state.ServerID = serverID
	state.AppliedSHA256 = digest
	f.states[serverID] = state
	return nil
}

func (f *fakeStates) Get(_ context.Context, serverID int64) (State, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.states[serverID], nil
}

func (f *fakeStates) List(context.Context) (map[int64]State, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	copied := make(map[int64]State, len(f.states))
	maps.Copy(copied, f.states)
	return copied, nil
}

func (f *fakeStates) failure(serverID int64) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.failures[serverID]
}

// fakeTransport answers with fixed content, or with a failure.
type fakeTransport struct {
	content []byte
	digest  string
	readErr error

	active    bool
	statusErr error

	// inFlight tracks how many reads overlap, which is what proves the
	// concurrency limit holds.
	inFlight *atomic.Int32
	peak     *atomic.Int32
	delay    time.Duration
}

func (f *fakeTransport) ReadHostEntries(context.Context) ([]byte, string, error) {
	if f.inFlight != nil {
		current := f.inFlight.Add(1)
		defer f.inFlight.Add(-1)

		for {
			peak := f.peak.Load()
			if current <= peak || f.peak.CompareAndSwap(peak, current) {
				break
			}
		}
		time.Sleep(f.delay)
	}
	if f.readErr != nil {
		return nil, "", f.readErr
	}
	return f.content, f.digest, nil
}

func (f *fakeTransport) WriteHostEntries(context.Context, []byte, string) error { return nil }
func (f *fakeTransport) Reload(context.Context) (string, error)                 { return "", nil }
func (f *fakeTransport) Probe(context.Context) error                            { return nil }
func (f *fakeTransport) Close() error                                           { return nil }

func (f *fakeTransport) ServiceStatus(context.Context) (bool, string, error) {
	if f.statusErr != nil {
		return false, "", f.statusErr
	}
	return f.active, "active", nil
}

type fakeConnector struct {
	byHost map[string]*fakeTransport
	err    error
}

func (f *fakeConnector) Get(cfg transport.Config) (transport.Transport, error) {
	if f.err != nil {
		return nil, f.err
	}
	client, ok := f.byHost[cfg.Host]
	if !ok {
		return nil, fmt.Errorf("no target for %s", cfg.Host)
	}
	return client, nil
}

// --- Harness ---------------------------------------------------------------

const sample = `# managed by the panel
local-data: "www.example.net. A 192.0.2.10"
local-data: "mail.example.net. MX 20 mx1.example.net"
`

type harness struct {
	refresher *Refresher
	servers   *fakeServers
	records   *fakeRecords
	states    *fakeStates
	connector *fakeConnector
}

func newHarness(t *testing.T, targets ...*fakeTransport) *harness {
	t.Helper()

	servers := &fakeServers{records: map[int64]server.Server{}}
	connector := &fakeConnector{byHost: map[string]*fakeTransport{}}

	for i, target := range targets {
		id := int64(i + 1)
		name := fmt.Sprintf("dns%d", id)

		record := server.Server{
			ID: id, Name: name, Host: name, SSHUser: "dnsops",
			SSHKeyPath: server.KeyRelPath(id), HostKey: "ssh-ed25519 AAAAapproved",
			Enabled: true,
		}
		record.ApplyDefaults()

		servers.records[id] = record
		connector.byHost[name] = target
	}

	records := &fakeRecords{byID: map[int64][]dnsfile.Record{}}
	states := &fakeStates{states: map[int64]State{}, failures: map[int64]string{}}

	return &harness{
		refresher: NewRefresher(servers, records, states, connector, "/data",
			settings.Fixed(server.Timeouts{Connect: time.Second, Command: time.Second}),
			settings.Fixed(2)),
		servers:   servers,
		records:   records,
		states:    states,
		connector: connector,
	}
}

func workingTarget() *fakeTransport {
	return &fakeTransport{content: []byte(sample), digest: "abc123", active: true}
}

// --- Tests -----------------------------------------------------------------

func TestRefreshFillsTheCacheFromTheFile(t *testing.T) {
	h := newHarness(t, workingTarget())

	result, err := h.refresher.One(context.Background(), 1)
	if err != nil {
		t.Fatalf("One returned an error: %v", err)
	}
	if !result.OK() {
		t.Fatalf("the refresh failed: %v", result.Err)
	}
	if result.Records != 2 {
		t.Errorf("got %d records, want 2", result.Records)
	}

	cached := h.records.get(1)
	if len(cached) != 2 || cached[0].FQDN != "www.example.net" {
		t.Errorf("got %+v", cached)
	}
}

func TestRefreshRecordsWhatItSaw(t *testing.T) {
	h := newHarness(t, workingTarget())

	if _, err := h.refresher.One(context.Background(), 1); err != nil {
		t.Fatalf("One returned an error: %v", err)
	}

	state, err := h.states.Get(context.Background(), 1)
	if err != nil {
		t.Fatalf("Get returned an error: %v", err)
	}
	if !state.Reachable || !state.UnboundActive {
		t.Errorf("got %+v", state)
	}
	if state.FileSHA256 != "abc123" || state.RecordCount != 2 {
		t.Errorf("got %+v", state)
	}
	if state.FetchedAt == nil {
		t.Error("the read was not timed")
	}
}

func TestARefreshThatCannotReadKeepsTheRecordsItHas(t *testing.T) {
	// An empty page says less than old records with a warning next to them.
	h := newHarness(t, workingTarget())
	ctx := context.Background()

	if _, err := h.refresher.One(ctx, 1); err != nil {
		t.Fatalf("the first refresh failed: %v", err)
	}

	h.connector.byHost["dns1"] = &fakeTransport{readErr: transport.ErrUnreachable}

	result, err := h.refresher.One(ctx, 1)
	if err != nil {
		t.Fatalf("One returned an error: %v", err)
	}
	if result.OK() {
		t.Fatal("the refresh reported success against an unreachable server")
	}

	if len(h.records.get(1)) != 2 {
		t.Errorf("the cached records were dropped: %+v", h.records.get(1))
	}
	if h.states.failure(1) == "" {
		t.Error("the failure was not recorded")
	}

	state, _ := h.states.Get(ctx, 1)
	if state.Reachable {
		t.Error("an unreachable server is still marked reachable")
	}
	if state.FileSHA256 != "abc123" {
		t.Error("the digest of the last successful read was forgotten")
	}
}

func TestRefreshDoesNotReachOutToAnUnapprovedServer(t *testing.T) {
	// The connection would fail on the host key anyway, and the message would
	// point at the network instead of at the missing approval.
	h := newHarness(t, workingTarget())

	record := h.servers.records[1]
	record.HostKey = ""
	h.servers.records[1] = record

	result, err := h.refresher.One(context.Background(), 1)
	if err != nil {
		t.Fatalf("One returned an error: %v", err)
	}
	if !errors.Is(result.Err, transport.ErrHostKeyUnknown) {
		t.Fatalf("got %v, want ErrHostKeyUnknown", result.Err)
	}
	if len(h.records.get(1)) != 0 {
		t.Error("a server nobody approved filled the cache")
	}
}

func TestARefreshSurvivesAResolverThatWillNotAnswer(t *testing.T) {
	// The records were read. Whether the resolver is running is worth knowing
	// but not worth throwing the file away over.
	target := workingTarget()
	target.statusErr = errors.New("no such service")
	h := newHarness(t, target)

	result, err := h.refresher.One(context.Background(), 1)
	if err != nil {
		t.Fatalf("One returned an error: %v", err)
	}
	if !result.OK() {
		t.Fatalf("the refresh failed: %v", result.Err)
	}

	state, _ := h.states.Get(context.Background(), 1)
	if !state.Reachable || state.UnboundActive {
		t.Errorf("got %+v, want reachable with an inactive resolver", state)
	}
}

func TestOneUnreachableServerDoesNotStopTheOthers(t *testing.T) {
	h := newHarness(t, workingTarget(),
		&fakeTransport{readErr: transport.ErrUnreachable}, workingTarget())

	results, err := h.refresher.All(context.Background())
	if err != nil {
		t.Fatalf("All returned an error: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}

	failed := 0
	for _, result := range results {
		if !result.OK() {
			failed++
		}
	}
	if failed != 1 {
		t.Errorf("%d servers failed, want 1", failed)
	}
	if len(h.records.get(1)) != 2 || len(h.records.get(3)) != 2 {
		t.Error("a working server was left unrefreshed")
	}
}

func TestAllSkipsADisabledServer(t *testing.T) {
	h := newHarness(t, workingTarget(), workingTarget())

	record := h.servers.records[2]
	record.Enabled = false
	h.servers.records[2] = record

	results, err := h.refresher.All(context.Background())
	if err != nil {
		t.Fatalf("All returned an error: %v", err)
	}
	if len(results) != 1 || results[0].ServerID != 1 {
		t.Errorf("got %+v, want only the enabled server", results)
	}
}

func TestAllHoldsTheConcurrencyLimit(t *testing.T) {
	// A fleet larger than the panel host can hold connections for would take
	// it down rather than take longer.
	var inFlight, peak atomic.Int32

	targets := make([]*fakeTransport, 8)
	for i := range targets {
		targets[i] = &fakeTransport{
			content: []byte(sample), digest: "abc123", active: true,
			inFlight: &inFlight, peak: &peak, delay: 20 * time.Millisecond,
		}
	}

	h := newHarness(t, targets...)

	results, err := h.refresher.All(context.Background())
	if err != nil {
		t.Fatalf("All returned an error: %v", err)
	}
	if len(results) != 8 {
		t.Fatalf("got %d results, want 8", len(results))
	}
	if peak.Load() > 2 {
		t.Errorf("%d reads overlapped, want at most 2", peak.Load())
	}
	if peak.Load() < 2 {
		t.Error("the reads ran one after another, so the limit does nothing")
	}
}

func TestAResultNamesTheServerItBelongsTo(t *testing.T) {
	h := newHarness(t, workingTarget(), &fakeTransport{readErr: transport.ErrUnreachable})

	results, err := h.refresher.All(context.Background())
	if err != nil {
		t.Fatalf("All returned an error: %v", err)
	}
	for _, result := range results {
		if result.ServerName == "" {
			t.Errorf("a result carries no server name: %+v", result)
		}
	}
}

func TestStaleIsDecidedAgainstTheLastRead(t *testing.T) {
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	recent := now.Add(-time.Minute)
	old := now.Add(-time.Hour)

	if (State{}).Stale(now, time.Minute) != true {
		t.Error("a server nobody has read is not stale")
	}
	if (State{FetchedAt: &recent}).Stale(now, 15*time.Minute) {
		t.Error("a recent read is stale")
	}
	if !(State{FetchedAt: &old}).Stale(now, 15*time.Minute) {
		t.Error("an hour old read is not stale")
	}
}

func TestAFailedReadStoresTheClassAndNotTheText(t *testing.T) {
	// CommandError carries the remote command line, its paths and its stderr.
	// The row it lands in is read by every signed in account, so only the
	// class is allowed to survive the write.
	target := workingTarget()
	target.readErr = &transport.CommandError{
		Command:  "/usr/bin/base64 -w0 /etc/unbound/host_entries.conf",
		ExitCode: 1,
		Stderr:   "sudo: a password is required",
	}
	h := newHarness(t, target)

	if _, err := h.refresher.One(context.Background(), 1); err != nil {
		t.Fatalf("One returned an error: %v", err)
	}

	stored := h.states.failure(1)
	if stored != transport.CodeCommandFailed {
		t.Fatalf("stored failure = %q, want %q", stored, transport.CodeCommandFailed)
	}
	if strings.Contains(stored, "base64") || strings.Contains(stored, "sudo") {
		t.Errorf("stored failure carries the remote command: %q", stored)
	}
}

func TestAnUnapprovedHostKeyStoresItsOwnClass(t *testing.T) {
	// An operator who reads "no approved host key" goes to the trust button.
	// One who reads "unreachable" goes to the network, which is the wrong step.
	h := newHarness(t, workingTarget())

	record := h.servers.records[1]
	record.HostKey = ""
	h.servers.records[1] = record

	if _, err := h.refresher.One(context.Background(), 1); err != nil {
		t.Fatalf("One returned an error: %v", err)
	}

	if stored := h.states.failure(1); stored != transport.CodeHostKeyUnknown {
		t.Errorf("stored failure = %q, want %q", stored, transport.CodeHostKeyUnknown)
	}
}
