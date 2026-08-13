package fleet

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"unbound-web/internal/audit"
	"unbound-web/internal/dnsfile"
	"unbound-web/internal/server"
	"unbound-web/internal/transport"
)

// --- Fakes -----------------------------------------------------------------

type fakeGroups struct {
	groups  map[int64]server.Group
	members map[int64][]server.Server
}

func (f *fakeGroups) GetGroup(_ context.Context, id int64) (server.Group, error) {
	group, ok := f.groups[id]
	if !ok {
		return server.Group{}, errors.New("not found")
	}
	return group, nil
}

func (f *fakeGroups) Targets(_ context.Context, id int64) ([]server.Server, error) {
	members := f.members[id]
	if len(members) == 0 {
		return nil, errors.New("the group has no members")
	}
	return members, nil
}

type fakeAudit struct {
	mu      sync.Mutex
	entries []audit.Entry
}

func (f *fakeAudit) Write(_ context.Context, entry audit.Entry, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.entries = append(f.entries, entry)
	return nil
}

func (f *fakeAudit) all() []audit.Entry {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]audit.Entry(nil), f.entries...)
}

// writableTarget holds the file in memory and answers like a real server.
type writableTarget struct {
	mu       sync.Mutex
	content  []byte
	writeErr error
	readErr  error

	// expectations records what each write was checked against, which is what
	// proves the digest travels back.
	expectations []string
}

func newWritableTarget(content string) *writableTarget {
	return &writableTarget{content: []byte(content)}
}

func (t *writableTarget) ReadHostEntries(context.Context) ([]byte, string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.readErr != nil {
		return nil, "", t.readErr
	}
	return append([]byte(nil), t.content...), contentDigest(t.content), nil
}

func (t *writableTarget) WriteHostEntries(_ context.Context, data []byte, expect string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.expectations = append(t.expectations, expect)
	if t.writeErr != nil {
		return t.writeErr
	}
	if expect != contentDigest(t.content) {
		return transport.ErrConflict
	}
	t.content = append([]byte(nil), data...)
	return nil
}

func (t *writableTarget) Reload(context.Context) (string, error) { return "", nil }
func (t *writableTarget) Probe(context.Context) error            { return nil }
func (t *writableTarget) Close() error                           { return nil }

func (t *writableTarget) ServiceStatus(context.Context) (bool, string, error) {
	return true, "active", nil
}

func (t *writableTarget) file() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.content)
}

// contentDigest stands in for the SHA-256 of the file. The real digest is the
// transport's business; what matters here is that it changes with the content.
func contentDigest(content []byte) string {
	return fmt.Sprintf("digest-%d", len(content))
}

// --- Harness ---------------------------------------------------------------

const seeded = `# managed by the panel
local-data: "www.example.net. A 192.0.2.10"
local-data: "mail.example.net. MX 20 mx1.example.net"
`

type writeHarness struct {
	writer    *Writer
	servers   *fakeServers
	groups    *fakeGroups
	connector *fakeConnector
	audit     *fakeAudit
	targets   map[string]*writableTarget
}

func newWriteHarness(t *testing.T, count int) *writeHarness {
	t.Helper()

	servers := &fakeServers{records: map[int64]server.Server{}}
	connector := &fakeConnector{byHost: map[string]*fakeTransport{}}
	writable := map[string]*writableTarget{}
	var members []server.Server

	for i := 1; i <= count; i++ {
		id := int64(i)
		name := fmt.Sprintf("dns%d", i)

		record := server.Server{
			ID: id, Name: name, Host: name, SSHUser: "dnsops",
			SSHKeyPath: server.KeyRelPath(id), HostKey: "ssh-ed25519 AAAAapproved",
			Enabled: true,
		}
		record.ApplyDefaults()

		servers.records[id] = record
		members = append(members, record)
		writable[name] = newWritableTarget(seeded)
	}

	groups := &fakeGroups{
		groups:  map[int64]server.Group{1: {ID: 1, Name: "resolvers"}},
		members: map[int64][]server.Server{1: members},
	}

	records := &fakeRecords{byID: map[int64][]dnsfile.Record{}}
	states := &fakeStates{states: map[int64]State{}, failures: map[int64]string{}}
	auditRepo := &fakeAudit{}
	timeouts := server.Timeouts{Connect: time.Second, Command: time.Second}

	harness := &writeHarness{
		servers:   servers,
		groups:    groups,
		connector: connector,
		audit:     auditRepo,
		targets:   writable,
	}

	// The connector answers with the writable targets, which the fake
	// transport map cannot hold, so it is replaced wholesale.
	pool := &writableConnector{byHost: writable}
	refresher := NewRefresher(servers, records, states, pool, "/data", timeouts, 2)
	harness.writer = NewWriter(servers, groups, pool, refresher,
		audit.NewLogger(auditRepo), "/data", timeouts, 2)

	return harness
}

type writableConnector struct {
	byHost map[string]*writableTarget
	err    error
}

func (c *writableConnector) Get(cfg transport.Config) (transport.Transport, error) {
	if c.err != nil {
		return nil, c.err
	}
	target, ok := c.byHost[cfg.Host]
	if !ok {
		return nil, transport.ErrUnreachable
	}
	return target, nil
}

func addOperation() Operation {
	return Operation{Kind: OpAdd, Record: dnsfile.Record{
		FQDN: "new.example.net", Type: "A", Value: "192.0.2.20"}}
}

func groupTarget() Target { return Target{Scope: ScopeGroup, GroupID: 1} }

func testActor() server.Actor {
	return server.Actor{UID: 1001, Username: "dnsadmin", IPAddress: "203.0.113.5"}
}

// --- Tests -----------------------------------------------------------------

func TestApplyWritesToEveryMemberOfTheGroup(t *testing.T) {
	h := newWriteHarness(t, 3)

	report, err := h.writer.Apply(context.Background(), testActor(), groupTarget(), addOperation())
	if err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	if !report.OK() {
		t.Fatalf("got %+v", report.Results)
	}

	for name, target := range h.targets {
		if !strings.Contains(target.file(), "new.example.net") {
			t.Errorf("%s did not receive the record:\n%s", name, target.file())
		}
	}
}

func TestApplyReportsOneResultPerServer(t *testing.T) {
	h := newWriteHarness(t, 3)

	report, err := h.writer.Apply(context.Background(), testActor(), groupTarget(), addOperation())
	if err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	if len(report.Results) != 3 {
		t.Fatalf("got %d results, want 3", len(report.Results))
	}
	for _, result := range report.Results {
		if result.ServerName == "" || result.Status != StatusSuccess || result.Message == "" {
			t.Errorf("got %+v", result)
		}
	}
	if report.GroupName != "resolvers" {
		t.Errorf("group name = %q", report.GroupName)
	}
}

func TestOneFailingServerDoesNotStopTheOthers(t *testing.T) {
	h := newWriteHarness(t, 3)
	h.targets["dns2"].writeErr = transport.ErrCommandFailed

	report, err := h.writer.Apply(context.Background(), testActor(), groupTarget(), addOperation())
	if err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}

	success, failed, skipped := report.Counts()
	if success != 2 || failed != 1 || skipped != 0 {
		t.Fatalf("counts = %d/%d/%d, want 2 success and 1 failure", success, failed, skipped)
	}
	if !report.Partial() {
		t.Error("a mixed outcome is not reported as partial")
	}
	if !strings.Contains(h.targets["dns1"].file(), "new.example.net") {
		t.Error("a working server was left unwritten")
	}
}

func TestADisabledServerIsSkippedRatherThanFailed(t *testing.T) {
	h := newWriteHarness(t, 2)

	record := h.servers.records[2]
	record.Enabled = false
	h.servers.records[2] = record
	h.groups.members[1][1] = record

	report, err := h.writer.Apply(context.Background(), testActor(), groupTarget(), addOperation())
	if err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}

	success, failed, skipped := report.Counts()
	if success != 1 || failed != 0 || skipped != 1 {
		t.Fatalf("counts = %d/%d/%d, want one skipped", success, failed, skipped)
	}
	if !report.OK() {
		t.Error("a skipped server counts as a failure")
	}
	if strings.Contains(h.targets["dns2"].file(), "new.example.net") {
		t.Error("a disabled server was written to")
	}
}

func TestAnUnapprovedServerFailsWithoutBeingReached(t *testing.T) {
	h := newWriteHarness(t, 2)

	record := h.servers.records[2]
	record.HostKey = ""
	h.servers.records[2] = record
	h.groups.members[1][1] = record

	report, err := h.writer.Apply(context.Background(), testActor(), groupTarget(), addOperation())
	if err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}

	for _, result := range report.Results {
		if result.ServerID != 2 {
			continue
		}
		if result.Status != StatusFailed {
			t.Errorf("status = %s, want failed", result.Status)
		}
		if !strings.Contains(result.Message, "host key") {
			t.Errorf("the message does not name the reason: %q", result.Message)
		}
	}
	if len(h.targets["dns2"].expectations) != 0 {
		t.Error("a server nobody approved was written to")
	}
}

func TestTheReadDigestTravelsBackWithTheWrite(t *testing.T) {
	// Without it, a file that changed on the target between the read and the
	// write would be replaced rather than refused.
	h := newWriteHarness(t, 1)

	if _, err := h.writer.Apply(context.Background(), testActor(), groupTarget(), addOperation()); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}

	target := h.targets["dns1"]
	if len(target.expectations) != 1 {
		t.Fatalf("got %d writes, want 1", len(target.expectations))
	}
	if target.expectations[0] != contentDigest([]byte(seeded)) {
		t.Errorf("the write was checked against %q", target.expectations[0])
	}
}

func TestAConflictIsReportedAsAFailure(t *testing.T) {
	h := newWriteHarness(t, 1)
	h.targets["dns1"].writeErr = transport.ErrConflict

	report, err := h.writer.Apply(context.Background(), testActor(), groupTarget(), addOperation())
	if err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	if report.Results[0].Status != StatusFailed {
		t.Fatalf("got %+v", report.Results[0])
	}
	if !strings.Contains(report.Results[0].Message, "changed") {
		t.Errorf("the message does not explain the conflict: %q", report.Results[0].Message)
	}
}

func TestEditReplacesTheRecordOnEveryServer(t *testing.T) {
	h := newWriteHarness(t, 2)

	op := Operation{
		Kind: OpEdit,
		Old:  dnsfile.Record{FQDN: "www.example.net", Type: "A", Value: "192.0.2.10"},
		Record: dnsfile.Record{
			FQDN: "www.example.net", Type: "A", Value: "192.0.2.99"},
	}

	report, err := h.writer.Apply(context.Background(), testActor(), groupTarget(), op)
	if err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	if !report.OK() {
		t.Fatalf("got %+v", report.Results)
	}

	for name, target := range h.targets {
		if !strings.Contains(target.file(), "192.0.2.99") {
			t.Errorf("%s still holds the old value:\n%s", name, target.file())
		}
	}
}

func TestDeleteRemovesTheRecordFromEveryServer(t *testing.T) {
	h := newWriteHarness(t, 2)

	op := Operation{Kind: OpDelete, Record: dnsfile.Record{
		FQDN: "www.example.net", Type: "A", Value: "192.0.2.10"}}

	if _, err := h.writer.Apply(context.Background(), testActor(), groupTarget(), op); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}

	for name, target := range h.targets {
		if strings.Contains(target.file(), "192.0.2.10") {
			t.Errorf("%s still holds the record:\n%s", name, target.file())
		}
	}
}

func TestARecordMissingOnOneServerFailsOnlyThere(t *testing.T) {
	// The servers drifted apart before the panel arrived, which is exactly the
	// case the fleet view exists for.
	h := newWriteHarness(t, 2)
	h.targets["dns2"].content = []byte("# empty on purpose\n")

	op := Operation{Kind: OpDelete, Record: dnsfile.Record{
		FQDN: "www.example.net", Type: "A", Value: "192.0.2.10"}}

	report, err := h.writer.Apply(context.Background(), testActor(), groupTarget(), op)
	if err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}

	success, failed, _ := report.Counts()
	if success != 1 || failed != 1 {
		t.Fatalf("counts = %d success and %d failed", success, failed)
	}
	for _, result := range report.Results {
		if result.ServerID == 2 && !strings.Contains(result.Message, "not in the file") {
			t.Errorf("the message does not explain the failure: %q", result.Message)
		}
	}
}

func TestAnInvalidRecordNeverReachesAServer(t *testing.T) {
	h := newWriteHarness(t, 2)

	op := Operation{Kind: OpAdd, Record: dnsfile.Record{
		FQDN: "not a name", Type: "A", Value: "192.0.2.20"}}

	_, err := h.writer.Apply(context.Background(), testActor(), groupTarget(), op)
	if !errors.Is(err, dnsfile.ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid", err)
	}

	for name, target := range h.targets {
		if len(target.expectations) != 0 {
			t.Errorf("%s was written to for a refused record", name)
		}
	}
}

func TestAnEditValidatesTheRecordItReplaces(t *testing.T) {
	// The old values build the line that is matched, so a bad one would look
	// for a record that cannot exist and fail on every server at once.
	h := newWriteHarness(t, 1)

	op := Operation{
		Kind:   OpEdit,
		Old:    dnsfile.Record{FQDN: "www example.net", Type: "A", Value: "192.0.2.10"},
		Record: dnsfile.Record{FQDN: "www.example.net", Type: "A", Value: "192.0.2.99"},
	}

	_, err := h.writer.Apply(context.Background(), testActor(), groupTarget(), op)
	if !errors.Is(err, dnsfile.ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid", err)
	}
}

func TestAWriteAgainstEveryServerIsRefused(t *testing.T) {
	// Changing the whole fleet at once has to be a group somebody built on
	// purpose, not a scope left over from a listing.
	h := newWriteHarness(t, 2)

	_, err := h.writer.Apply(context.Background(), testActor(),
		Target{Scope: ScopeAll}, addOperation())
	if !errors.Is(err, ErrScope) {
		t.Fatalf("got %v, want ErrScope", err)
	}
}

func TestAnEmptyGroupIsRefused(t *testing.T) {
	h := newWriteHarness(t, 1)
	h.groups.members[1] = nil

	if _, err := h.writer.Apply(context.Background(), testActor(), groupTarget(), addOperation()); err == nil {
		t.Fatal("an operation against an empty group was accepted")
	}
}

func TestOneAuditRowPerServerThatChanged(t *testing.T) {
	h := newWriteHarness(t, 3)
	h.targets["dns2"].writeErr = transport.ErrCommandFailed

	if _, err := h.writer.Apply(context.Background(), testActor(), groupTarget(), addOperation()); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}

	entries := h.audit.all()
	if len(entries) != 2 {
		t.Fatalf("got %d audit rows, want one per server that changed", len(entries))
	}
	for _, entry := range entries {
		if entry.Action != audit.ActionDNSAdd {
			t.Errorf("action = %q", entry.Action)
		}
		if entry.ServerID == nil {
			t.Error("the row names no server")
		}
		if entry.Username != "dnsadmin" || entry.IPAddress != "203.0.113.5" {
			t.Errorf("the row is not attributed: %+v", entry)
		}
		if !strings.Contains(entry.Details, "Added A record: new.example.net -> 192.0.2.20") {
			t.Errorf("details = %q", entry.Details)
		}
		if !strings.Contains(entry.Details, "group resolvers") {
			t.Errorf("the details do not name the group: %q", entry.Details)
		}
	}
}

func TestTheAuditDetailNamesTheServerForASingleTarget(t *testing.T) {
	h := newWriteHarness(t, 2)

	_, err := h.writer.Apply(context.Background(), testActor(),
		Target{Scope: ScopeServer, ServerID: 1}, addOperation())
	if err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}

	entries := h.audit.all()
	if len(entries) != 1 {
		t.Fatalf("got %d audit rows, want 1", len(entries))
	}
	if !strings.Contains(entries[0].Details, "on dns1") {
		t.Errorf("details = %q", entries[0].Details)
	}
	if strings.Contains(entries[0].Details, "group") {
		t.Errorf("a single server change names a group: %q", entries[0].Details)
	}
}

func TestASuccessfulWriteRefreshesThatServer(t *testing.T) {
	// The file changed, so what the panel shows for that server is now stale.
	h := newWriteHarness(t, 1)

	if _, err := h.writer.Apply(context.Background(), testActor(), groupTarget(), addOperation()); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}

	cached := h.writer.refresh.records.(*fakeRecords).get(1)
	var seen bool
	for _, record := range cached {
		if record.FQDN == "new.example.net" {
			seen = true
		}
	}
	if !seen {
		t.Errorf("the cache does not hold the new record: %+v", cached)
	}
}

func TestTwoChangesToOneServerBothLand(t *testing.T) {
	// Without the per server lock, both would read the same file and the
	// second write would be refused as a conflict.
	h := newWriteHarness(t, 1)

	first := addOperation()
	second := Operation{Kind: OpAdd, Record: dnsfile.Record{
		FQDN: "second.example.net", Type: "A", Value: "192.0.2.21"}}

	var wait sync.WaitGroup
	reports := make([]Report, 2)
	errs := make([]error, 2)

	for i, op := range []Operation{first, second} {
		wait.Add(1)
		go func() {
			defer wait.Done()
			reports[i], errs[i] = h.writer.Apply(
				context.Background(), testActor(), groupTarget(), op)
		}()
	}
	wait.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("operation %d returned an error: %v", i, err)
		}
		if !reports[i].OK() {
			t.Fatalf("operation %d failed: %+v", i, reports[i].Results)
		}
	}

	file := h.targets["dns1"].file()
	if !strings.Contains(file, "new.example.net") || !strings.Contains(file, "second.example.net") {
		t.Errorf("one of the two changes was lost:\n%s", file)
	}
}
