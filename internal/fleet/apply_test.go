package fleet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"jbound/internal/audit"
	"jbound/internal/dnsfile"
	"jbound/internal/server"
	"jbound/internal/settings"
	"jbound/internal/transport"
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

// List satisfies the repository. The listing is covered where it is used.
func (f *fakeAudit) List(context.Context, audit.Query) (audit.Page, error) {
	return audit.Page{}, nil
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

	// firstReadErr fails the first read and no other, which is how a server
	// that was unreachable while a batch collected its records can still be
	// read by the write that follows.
	firstReadErr error

	reloadOut string
	reloadErr error
	reloads   int

	// The second and third rungs of a reload, counted so a test can prove a
	// rung that should not have run did not run.
	fallbackErr error
	fallbacks   int
	restartErr  error
	restarts    int

	// checkErr is what the configuration check answers. checks counts the
	// calls, because the check runs on the write path rather than on demand.
	checkErr error
	checks   int

	// active is what ServiceStatus reports. activeAfter lets a rung change it,
	// which is how a reload that leaves the resolver stopped is written down.
	active      bool
	activeAfter map[string]bool

	// expectations records what each write was checked against, which is what
	// proves the digest travels back.
	expectations []string

	// includeOutput is what the target says when asked to confirm the
	// resolver reads the records file, and includeErr is how that fails.
	// calls records the order of every transport call, because whether the
	// include is confirmed before the read is the whole point of the step.
	includeOutput string
	includeErr    error
	calls         []string
}

func newWritableTarget(content string) *writableTarget {
	return &writableTarget{content: []byte(content), active: true}
}

func (t *writableTarget) EnsureInclude(context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.calls = append(t.calls, "ensure-include")
	if t.includeErr != nil {
		return "", t.includeErr
	}
	if t.includeOutput == "" {
		return "ok", nil
	}
	return t.includeOutput, nil
}

func (t *writableTarget) ReadRecords(context.Context) ([]byte, string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.calls = append(t.calls, "read")
	if t.firstReadErr != nil {
		err := t.firstReadErr
		t.firstReadErr = nil
		return nil, "", err
	}
	if t.readErr != nil {
		return nil, "", t.readErr
	}
	return append([]byte(nil), t.content...), contentDigest(t.content), nil
}

func (t *writableTarget) WriteRecords(_ context.Context, data []byte, expect string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.calls = append(t.calls, "write")
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

func (t *writableTarget) Reload(context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.reloads++
	t.applyRungState("reload")
	if t.reloadErr != nil {
		return "", t.reloadErr
	}
	return t.reloadOut, nil
}

func (t *writableTarget) ReloadFallback(context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.fallbacks++
	t.applyRungState("fallback")
	if t.fallbackErr != nil {
		return "", t.fallbackErr
	}
	return "reloaded", nil
}

func (t *writableTarget) Restart(context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.restarts++
	t.applyRungState("restart")
	if t.restartErr != nil {
		return "", t.restartErr
	}
	return "restarted", nil
}

func (t *writableTarget) CheckConfig(context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.calls = append(t.calls, "checkconf")
	t.checks++
	if t.checkErr != nil {
		return "unbound-checkconf: fatal error", t.checkErr
	}
	return "unbound-checkconf: no errors", nil
}

// applyRungState moves the service state the way a rung would. The caller
// holds the lock.
func (t *writableTarget) applyRungState(rung string) {
	if active, ok := t.activeAfter[rung]; ok {
		t.active = active
	}
}

func (t *writableTarget) Probe(context.Context) error { return nil }
func (t *writableTarget) Close() error                { return nil }

func (t *writableTarget) ServiceStatus(context.Context) (bool, string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.active, "state", nil
}

// failEveryRung makes the whole ladder fail, which is what "the reload did not
// work" means now that a failed step escalates to the next one.
func (t *writableTarget) failEveryRung(err error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.reloadErr, t.fallbackErr, t.restartErr = err, err, err
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

// seeded is what a target holds before a test changes anything. It carries the
// clause header, because every write the panel makes puts one there and a
// target that has taken one write has it from then on.
const seeded = `server:
# managed by the panel
local-data: "www.example.net. A 192.0.2.10"
local-data: "mail.example.net. MX 20 mx1.example.net"
`

type writeHarness struct {
	writer    *Writer
	refresher *Refresher
	servers   *fakeServers
	groups    *fakeGroups
	connector *fakeConnector
	audit     *fakeAudit
	states    *fakeStates
	backups   *fakeBackups
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
		states:    states,
		targets:   writable,
	}

	// The connector answers with the writable targets, which the fake
	// transport map cannot hold, so it is replaced wholesale.
	pool := &writableConnector{byHost: writable}
	refresher := NewRefresher(servers, records, states, pool, "/data",
		settings.Fixed(timeouts), settings.Fixed(2))
	harness.refresher = refresher
	harness.backups = &fakeBackups{saved: map[int64]FileBackup{}}
	harness.writer = NewWriter(servers, groups, pool, refresher,
		audit.NewLogger(auditRepo, nil), harness.backups, "/data",
		settings.Fixed(timeouts), settings.Fixed(2))

	// A real restart is given half a minute to bring the resolver back. The
	// fakes answer at once, so waiting that out would only make the suite
	// slow enough that nobody runs it.
	harness.writer.restartSettle = 20 * time.Millisecond

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
		wait.Go(func() {
			reports[i], errs[i] = h.writer.Apply(
				context.Background(), testActor(), groupTarget(), op)
		})
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

// captureLog sends the structured stream to a buffer for the length of one
// test, so an assertion can read what an operator would read.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()

	var buffer bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buffer, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &buffer
}

func TestAFailedWriteNamesTheServerInTheLog(t *testing.T) {
	// The report table is the only other place a failure appears, and it lives
	// exactly as long as the page it was rendered into.
	logged := captureLog(t)

	h := newWriteHarness(t, 3)
	h.targets["dns2"].writeErr = transport.ErrCommandFailed

	if _, err := h.writer.Apply(context.Background(), testActor(), groupTarget(), addOperation()); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}

	output := logged.String()
	if !strings.Contains(output, "cannot write a record to a server") {
		t.Fatalf("the failure was not logged:\n%s", output)
	}
	if !strings.Contains(output, "server=dns2") {
		t.Errorf("the log does not name the server:\n%s", output)
	}
	if !strings.Contains(output, "operation=add") {
		t.Errorf("the log does not name the operation:\n%s", output)
	}
	if strings.Contains(output, "server=dns1") {
		t.Errorf("a server that succeeded was logged as a failure:\n%s", output)
	}
}

func TestAnAddDeclaresTheZoneOfTheRecordOnEveryServer(t *testing.T) {
	// Under a parent zone the operator declared static or redirect, a record
	// with no zone line of its own is written and never answered. The panel
	// reports it applied, and the resolver disagrees.
	h := newWriteHarness(t, 3)

	report, err := h.writer.Apply(context.Background(), testActor(), groupTarget(), addOperation())
	if err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	if !report.OK() {
		t.Fatalf("got %+v", report.Results)
	}

	for name, target := range h.targets {
		if !strings.Contains(target.file(), `local-zone: "example.net." transparent`) {
			t.Errorf("%s carries no zone for the record:\n%s", name, target.file())
		}
	}
}

func TestASecondRecordOfTheSameZoneAddsNoSecondZoneLine(t *testing.T) {
	h := newWriteHarness(t, 1)

	for _, value := range []string{"192.0.2.20", "192.0.2.21"} {
		op := Operation{Kind: OpAdd, Record: dnsfile.Record{
			FQDN: "new.example.net", Type: "A", Value: value}}

		report, err := h.writer.Apply(context.Background(), testActor(),
			Target{Scope: ScopeServer, ServerID: 1}, op)
		if err != nil {
			t.Fatalf("Apply returned an error: %v", err)
		}
		if !report.OK() {
			t.Fatalf("got %+v", report.Results)
		}
	}

	file := h.targets["dns1"].file()
	if got := strings.Count(file, "local-zone:"); got != 1 {
		t.Errorf("the file carries %d zone lines, want 1:\n%s", got, file)
	}
}

func TestAnEditThatMovesARecordDeclaresTheNewZone(t *testing.T) {
	h := newWriteHarness(t, 1)
	target := Target{Scope: ScopeServer, ServerID: 1}

	add := addOperation()
	if _, err := h.writer.Apply(context.Background(), testActor(), target, add); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}

	edit := Operation{
		Kind: OpEdit,
		Old:  add.Record,
		Record: dnsfile.Record{
			FQDN: "moved.example.org", Type: "A", Value: "192.0.2.20"},
	}
	report, err := h.writer.Apply(context.Background(), testActor(), target, edit)
	if err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	if !report.OK() {
		t.Fatalf("got %+v", report.Results)
	}

	if file := h.targets["dns1"].file(); !strings.Contains(file,
		`local-zone: "example.org." transparent`) {
		t.Errorf("the new zone was not declared:\n%s", file)
	}
}

func TestADeleteLeavesTheZoneLineWhereItIs(t *testing.T) {
	// A transparent zone with no local data of its own changes no answer, and
	// removing it would reach every other name under it.
	h := newWriteHarness(t, 1)
	target := Target{Scope: ScopeServer, ServerID: 1}

	add := addOperation()
	if _, err := h.writer.Apply(context.Background(), testActor(), target, add); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}

	del := Operation{Kind: OpDelete, Record: add.Record}
	if _, err := h.writer.Apply(context.Background(), testActor(), target, del); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}

	file := h.targets["dns1"].file()
	if strings.Contains(file, "new.example.net") {
		t.Errorf("the record survived the delete:\n%s", file)
	}
	if !strings.Contains(file, `local-zone: "example.net." transparent`) {
		t.Errorf("the zone line went with the record:\n%s", file)
	}
}

func TestAChangeTheResolverRefusesPutsThePreviousFileBack(t *testing.T) {
	// The check can only run once the change is on the target, because the
	// file the panel writes is included inside a server clause. A refusal
	// therefore has to undo the write rather than decline to make it.
	h := newWriteHarness(t, 1)
	target := h.targets["dns1"]
	before := target.file()
	target.checkErr = transport.ErrCommandFailed

	report, err := h.writer.Apply(context.Background(), testActor(),
		Target{Scope: ScopeServer, ServerID: 1}, addOperation())
	if err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}

	if report.OK() {
		t.Errorf("the change was reported as applied: %+v", report.Results)
	}
	if got := target.file(); got != before {
		t.Errorf("the refused change stayed on the server:\n%s", got)
	}
	if target.checks != 1 {
		t.Errorf("the configuration was checked %d times", target.checks)
	}
}

func TestARefusedConfigurationSaysWhatTheResolverSaid(t *testing.T) {
	// "The change failed" sends the operator to the server to find out why.
	// The resolver already said why on stderr.
	h := newWriteHarness(t, 1)
	h.targets["dns1"].checkErr = transport.ErrCommandFailed

	report, err := h.writer.Apply(context.Background(), testActor(),
		Target{Scope: ScopeServer, ServerID: 1}, addOperation())
	if err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}

	if len(report.Results) != 1 {
		t.Fatalf("got %d results, want 1", len(report.Results))
	}
	if !strings.Contains(report.Results[0].Message, "unbound-checkconf") {
		t.Errorf("the message does not carry what the check said: %q",
			report.Results[0].Message)
	}
}

func TestAValidConfigurationLeavesTheChangeWhereItIs(t *testing.T) {
	h := newWriteHarness(t, 1)

	report, err := h.writer.Apply(context.Background(), testActor(),
		Target{Scope: ScopeServer, ServerID: 1}, addOperation())
	if err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	if !report.OK() {
		t.Fatalf("got %+v", report.Results)
	}

	if !strings.Contains(h.targets["dns1"].file(), "new.example.net") {
		t.Errorf("the change did not survive the check:\n%s", h.targets["dns1"].file())
	}
	if h.targets["dns1"].checks != 1 {
		t.Errorf("the configuration was checked %d times, want 1", h.targets["dns1"].checks)
	}
}

func TestATargetWithNoCheckCommandStillTakesTheChange(t *testing.T) {
	// A server whose sudoers rules have not been extended keeps working. The
	// step is skipped rather than failed.
	h := newWriteHarness(t, 1)
	h.targets["dns1"].checkErr = transport.ErrStepSkipped

	report, err := h.writer.Apply(context.Background(), testActor(),
		Target{Scope: ScopeServer, ServerID: 1}, addOperation())
	if err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	if !report.OK() {
		t.Fatalf("got %+v", report.Results)
	}
	if !strings.Contains(h.targets["dns1"].file(), "new.example.net") {
		t.Errorf("the change was rolled back:\n%s", h.targets["dns1"].file())
	}
}

func batchOperation(values ...string) Operation {
	records := make([]dnsfile.Record, 0, len(values))
	for i, value := range values {
		records = append(records, dnsfile.Record{
			FQDN:  fmt.Sprintf("bulk%d.example.net", i+1),
			Type:  "A",
			Value: value,
		})
	}
	return Operation{Kind: OpAddMany, Records: records}
}

func TestABatchReachesTheServerInOneWrite(t *testing.T) {
	// One write and one reload for the whole list. Writing each record on its
	// own would put the fleet through as many read, write and reload rounds as
	// the operator typed rows.
	h := newWriteHarness(t, 1)
	target := h.targets["dns1"]

	op := batchOperation("192.0.2.31", "192.0.2.32", "192.0.2.33")
	report, err := h.writer.Apply(context.Background(), testActor(),
		Target{Scope: ScopeServer, ServerID: 1}, op)
	if err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	if !report.OK() {
		t.Fatalf("got %+v", report.Results)
	}

	file := target.file()
	for _, value := range []string{"192.0.2.31", "192.0.2.32", "192.0.2.33"} {
		if !strings.Contains(file, value) {
			t.Errorf("%s is not in the file:\n%s", value, file)
		}
	}
	if len(target.expectations) != 1 {
		t.Errorf("the server was written to %d times, want 1", len(target.expectations))
	}
}

func TestABatchDeclaresTheZoneOfEveryRecord(t *testing.T) {
	h := newWriteHarness(t, 1)

	op := Operation{Kind: OpAddMany, Records: []dnsfile.Record{
		{FQDN: "one.example.net", Type: "A", Value: "192.0.2.31"},
		{FQDN: "two.example.org", Type: "A", Value: "192.0.2.32"},
	}}
	if _, err := h.writer.Apply(context.Background(), testActor(),
		Target{Scope: ScopeServer, ServerID: 1}, op); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}

	file := h.targets["dns1"].file()
	for _, zone := range []string{`"example.net."`, `"example.org."`} {
		if !strings.Contains(file, "local-zone: "+zone) {
			t.Errorf("no zone line for %s:\n%s", zone, file)
		}
	}
}

func TestOneBadRowStopsTheWholeBatch(t *testing.T) {
	// Half a list is worse than none of it: the operator has to work out which
	// half arrived before they can try again.
	op := batchOperation("192.0.2.31", "not-an-address", "192.0.2.33")

	err := op.Validate()
	if err == nil {
		t.Fatal("the batch was accepted")
	}
	if !strings.Contains(err.Error(), "row 2") {
		t.Errorf("the message does not name the row: %v", err)
	}
}

func TestARefusedBatchReachesNoServer(t *testing.T) {
	h := newWriteHarness(t, 1)
	target := h.targets["dns1"]
	before := target.file()

	op := Operation{Kind: OpAddMany, Records: []dnsfile.Record{
		{FQDN: "one.example.net", Type: "A", Value: "192.0.2.31"},
		// Already in the seeded file, so the add refuses it.
		{FQDN: "www.example.net", Type: "A", Value: "192.0.2.10"},
	}}

	report, err := h.writer.Apply(context.Background(), testActor(),
		Target{Scope: ScopeServer, ServerID: 1}, op)
	if err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	if report.OK() {
		t.Fatalf("the batch was reported as written: %+v", report.Results)
	}
	if got := target.file(); got != before {
		t.Errorf("part of the batch was written:\n%s", got)
	}
}

func TestABatchThatRepeatsARowIsRefusedBeforeAnyServerIsTouched(t *testing.T) {
	op := Operation{Kind: OpAddMany, Records: []dnsfile.Record{
		{FQDN: "one.example.net", Type: "A", Value: "192.0.2.31"},
		{FQDN: "one.example.net", Type: "A", Value: "192.0.2.31"},
	}}

	err := op.Validate()
	if err == nil {
		t.Fatal("the batch was accepted")
	}
	if !strings.Contains(err.Error(), "row 2") {
		t.Errorf("the message does not name the row: %v", err)
	}
}

func TestAnEmptyBatchIsRefused(t *testing.T) {
	if err := (Operation{Kind: OpAddMany}).Validate(); err == nil {
		t.Error("a batch with no record was accepted")
	}
}

func TestABatchLeavesOneAuditRowPerServer(t *testing.T) {
	// One action, one row. A row per record would bury the change the operator
	// made under the records it consisted of.
	h := newWriteHarness(t, 3)

	op := batchOperation("192.0.2.31", "192.0.2.32", "192.0.2.33")
	if _, err := h.writer.Apply(context.Background(), testActor(),
		groupTarget(), op); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}

	entries := h.audit.all()
	if len(entries) != 3 {
		t.Fatalf("got %d audit rows, want one per server", len(entries))
	}
	for _, entry := range entries {
		if entry.Action != audit.ActionDNSAdd {
			t.Errorf("action = %q", entry.Action)
		}
		if !strings.Contains(entry.Details, "Added 3 records") {
			t.Errorf("details = %q", entry.Details)
		}
		if !strings.Contains(entry.Details, "bulk1.example.net") {
			t.Errorf("the row does not name what was added: %q", entry.Details)
		}
	}
}

func TestABatchBeyondTheLimitIsRefused(t *testing.T) {
	records := make([]dnsfile.Record, maxBatch+1)
	for i := range records {
		records[i] = dnsfile.Record{
			FQDN:  fmt.Sprintf("bulk%d.example.net", i),
			Type:  "A",
			Value: "192.0.2.31",
		}
	}

	if err := (Operation{Kind: OpAddMany, Records: records}).Validate(); err == nil {
		t.Error("a batch beyond the limit was accepted")
	}
}

// callOrder reports every transport call this target took, in order.
func (t *writableTarget) callOrder() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.calls...)
}

// --- Blocked names ---------------------------------------------------------

// blockOperation blocks one name across the target.
func blockOperation(fqdn, behaviour string) Operation {
	return Operation{Kind: OpAdd, Record: dnsfile.Record{FQDN: fqdn, Type: behaviour}}
}

func TestBlockingANameReachesEveryServer(t *testing.T) {
	h := newWriteHarness(t, 3)

	report, err := h.writer.Apply(context.Background(), testActor(), groupTarget(),
		blockOperation("ads.example.net", dnsfile.TypeNXDOMAIN))
	if err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	if !report.OK() {
		t.Fatalf("got %+v", report.Results)
	}

	for name, target := range h.targets {
		if !strings.Contains(target.file(), `local-zone: "ads.example.net." always_nxdomain`) {
			t.Errorf("%s did not receive the block:\n%s", name, target.file())
		}
	}
}

func TestBlockingANameDeclaresNoParentZone(t *testing.T) {
	// The block is already a zone line. A transparent parent beside it would
	// be a decision about every other name under example.net, which is not
	// what blocking one name asks for.
	h := newWriteHarness(t, 1)

	if _, err := h.writer.Apply(context.Background(), testActor(), groupTarget(),
		blockOperation("ads.example.net", dnsfile.TypeREFUSED)); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}

	file := h.targets["dns1"].file()
	if strings.Contains(file, `local-zone: "example.net." transparent`) {
		t.Errorf("a parent zone was declared for a block:\n%s", file)
	}
}

func TestARecordUnderABlockedNameNeverReachesAServer(t *testing.T) {
	// The record would be written, pass the configuration check, survive the
	// reload and answer nothing, while the panel reported it applied.
	h := newWriteHarness(t, 3)

	if _, err := h.writer.Apply(context.Background(), testActor(), groupTarget(),
		blockOperation("ads.example.net", dnsfile.TypeNXDOMAIN)); err != nil {
		t.Fatalf("cannot block the name: %v", err)
	}

	report, err := h.writer.Apply(context.Background(), testActor(), groupTarget(),
		Operation{Kind: OpAdd, Record: dnsfile.Record{
			FQDN: "www.ads.example.net", Type: "A", Value: "192.0.2.30"}})
	if err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	if report.OK() {
		t.Fatalf("the record was accepted: %+v", report.Results)
	}

	for _, result := range report.Results {
		if !strings.Contains(result.Message, "ads.example.net") {
			t.Errorf("%s does not name the block: %q", result.ServerName, result.Message)
		}
	}
	for name, target := range h.targets {
		if strings.Contains(target.file(), "www.ads.example.net") {
			t.Errorf("%s took the record anyway:\n%s", name, target.file())
		}
	}
}

func TestBlockingANameThatAlreadyHasRecordsIsRefused(t *testing.T) {
	// The records would stay in the listing while the resolver answered
	// nothing for them, which is the same contradiction from the other side.
	h := newWriteHarness(t, 1)

	report, err := h.writer.Apply(context.Background(), testActor(), groupTarget(),
		blockOperation("example.net", dnsfile.TypeNXDOMAIN))
	if err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	if report.OK() {
		t.Fatalf("the block was accepted: %+v", report.Results)
	}
	if !strings.Contains(report.Results[0].Message, "www.example.net") {
		t.Errorf("the message does not name the record in the way: %q",
			report.Results[0].Message)
	}
}

func TestARemovedBlockLetsTheNameBeUsedAgain(t *testing.T) {
	h := newWriteHarness(t, 1)

	if _, err := h.writer.Apply(context.Background(), testActor(), groupTarget(),
		blockOperation("ads.example.net", dnsfile.TypeNXDOMAIN)); err != nil {
		t.Fatalf("cannot block the name: %v", err)
	}
	if _, err := h.writer.Apply(context.Background(), testActor(), groupTarget(),
		Operation{Kind: OpDelete, Record: dnsfile.Record{
			FQDN: "ads.example.net", Type: dnsfile.TypeNXDOMAIN}}); err != nil {
		t.Fatalf("cannot remove the block: %v", err)
	}

	report, err := h.writer.Apply(context.Background(), testActor(), groupTarget(),
		Operation{Kind: OpAdd, Record: dnsfile.Record{
			FQDN: "ads.example.net", Type: "A", Value: "192.0.2.30"}})
	if err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	if !report.OK() {
		t.Fatalf("the record was still refused: %+v", report.Results)
	}
}

func TestTheTrailReadsAsABlockRatherThanARecord(t *testing.T) {
	// A row saying a record was added with an empty value reads as an address
	// that went missing.
	h := newWriteHarness(t, 1)

	if _, err := h.writer.Apply(context.Background(), testActor(), groupTarget(),
		blockOperation("ads.example.net", dnsfile.TypeNXDOMAIN)); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}

	entries := h.audit.all()
	if len(entries) == 0 {
		t.Fatal("no audit row was written")
	}
	details := entries[len(entries)-1].Details
	if !strings.Contains(details, "Blocked ads.example.net with NXDOMAIN") {
		t.Errorf("details = %q", details)
	}
}
