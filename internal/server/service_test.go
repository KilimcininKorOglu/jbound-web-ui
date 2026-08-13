package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"unbound-web/internal/audit"
	"unbound-web/internal/transport"
)

// --- Fakes -----------------------------------------------------------------

type fakeRepo struct {
	records map[int64]Server
	nextID  int64
	created []Server
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{records: map[int64]Server{}, nextID: 1}
}

func (f *fakeRepo) Create(_ context.Context, record Server) (Server, error) {
	for _, existing := range f.records {
		if existing.Name == record.Name {
			return Server{}, errors.New("the name is already in use")
		}
	}
	record.ID = f.nextID
	f.nextID++
	f.records[record.ID] = record
	f.created = append(f.created, record)
	return record, nil
}

func (f *fakeRepo) Update(_ context.Context, record Server) error {
	if _, ok := f.records[record.ID]; !ok {
		return errors.New("not found")
	}
	f.records[record.ID] = record
	return nil
}

func (f *fakeRepo) SetHostKey(_ context.Context, id int64, hostKey string) error {
	record, ok := f.records[id]
	if !ok {
		return errors.New("not found")
	}
	record.HostKey = hostKey
	f.records[id] = record
	return nil
}

func (f *fakeRepo) SetReachability(_ context.Context, id int64, at time.Time, failure string) error {
	record, ok := f.records[id]
	if !ok {
		return errors.New("not found")
	}
	record.LastError = failure
	if failure == "" {
		stamp := at
		record.LastSeenAt = &stamp
	}
	f.records[id] = record
	return nil
}

func (f *fakeRepo) Get(_ context.Context, id int64) (Server, error) {
	record, ok := f.records[id]
	if !ok {
		return Server{}, errors.New("not found")
	}
	return record, nil
}

func (f *fakeRepo) List(_ context.Context) ([]Server, error) {
	var all []Server
	for _, record := range f.records {
		all = append(all, record)
	}
	return all, nil
}

func (f *fakeRepo) Delete(_ context.Context, id int64) error {
	if _, ok := f.records[id]; !ok {
		return errors.New("not found")
	}
	delete(f.records, id)
	return nil
}

type fakeGroupRepo struct {
	groups map[int64]Group
	nextID int64
}

func newFakeGroupRepo() *fakeGroupRepo {
	return &fakeGroupRepo{groups: map[int64]Group{}, nextID: 1}
}

func (f *fakeGroupRepo) Create(_ context.Context, group Group) (Group, error) {
	group.ID = f.nextID
	f.nextID++
	f.groups[group.ID] = group
	return group, nil
}

func (f *fakeGroupRepo) Update(_ context.Context, group Group) error {
	if _, ok := f.groups[group.ID]; !ok {
		return errors.New("not found")
	}
	f.groups[group.ID] = group
	return nil
}

func (f *fakeGroupRepo) Get(_ context.Context, id int64) (Group, error) {
	group, ok := f.groups[id]
	if !ok {
		return Group{}, errors.New("not found")
	}
	return group, nil
}

func (f *fakeGroupRepo) List(_ context.Context) ([]Group, error) {
	var all []Group
	for _, group := range f.groups {
		all = append(all, group)
	}
	return all, nil
}

func (f *fakeGroupRepo) Members(_ context.Context, id int64) ([]Server, error) {
	group, ok := f.groups[id]
	if !ok {
		return nil, errors.New("not found")
	}
	members := make([]Server, 0, len(group.ServerIDs))
	for _, serverID := range group.ServerIDs {
		members = append(members, Server{ID: serverID})
	}
	return members, nil
}

func (f *fakeGroupRepo) Delete(_ context.Context, id int64) error {
	if _, ok := f.groups[id]; !ok {
		return errors.New("not found")
	}
	delete(f.groups, id)
	return nil
}

// fakeTransport answers a probe with whatever the test asked for.
type fakeTransport struct {
	probeErr error
}

func (f *fakeTransport) ReadHostEntries(context.Context) ([]byte, string, error) {
	return nil, "", nil
}
func (f *fakeTransport) WriteHostEntries(context.Context, []byte, string) error { return nil }
func (f *fakeTransport) Reload(context.Context) (string, error)                 { return "", nil }
func (f *fakeTransport) ServiceStatus(context.Context) (bool, string, error)    { return true, "", nil }
func (f *fakeTransport) Probe(context.Context) error                            { return f.probeErr }
func (f *fakeTransport) Close() error                                           { return nil }

type fakeConnector struct {
	transport *fakeTransport
	getErr    error
	removed   []int64
}

func (f *fakeConnector) Get(transport.Config) (transport.Transport, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.transport, nil
}

func (f *fakeConnector) Remove(id int64) { f.removed = append(f.removed, id) }

type fakeAuditRepo struct {
	entries []audit.Entry
}

func (f *fakeAuditRepo) Write(_ context.Context, entry audit.Entry, _ time.Time) error {
	f.entries = append(f.entries, entry)
	return nil
}

func (f *fakeAuditRepo) actions() []string {
	var actions []string
	for _, entry := range f.entries {
		actions = append(actions, entry.Action)
	}
	return actions
}

// --- Harness ---------------------------------------------------------------

type harness struct {
	service   *Service
	servers   *fakeRepo
	groups    *fakeGroupRepo
	connector *fakeConnector
	auditLog  *fakeAuditRepo
	keys      *KeyStore
	dataDir   string
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	dataDir := t.TempDir()
	keys, err := NewKeyStore(filepath.Join(dataDir, "keys"))
	if err != nil {
		t.Fatalf("cannot create the key store: %v", err)
	}

	servers := newFakeRepo()
	groups := newFakeGroupRepo()
	connector := &fakeConnector{transport: &fakeTransport{}}
	auditRepo := &fakeAuditRepo{}

	return &harness{
		service: NewService(servers, groups, keys, connector,
			audit.NewLogger(auditRepo), dataDir,
			Timeouts{Connect: time.Second, Command: time.Second}),
		servers:   servers,
		groups:    groups,
		connector: connector,
		auditLog:  auditRepo,
		keys:      keys,
		dataDir:   dataDir,
	}
}

func testActor() Actor {
	return Actor{UID: 1001, Username: "dnsadmin", IPAddress: "203.0.113.5"}
}

func newServerInput(name string) CreateInput {
	return CreateInput{Server: Server{
		Name: name, Host: name + ".example", SSHUser: "dnsops", Enabled: true,
	}}
}

// --- Tests -----------------------------------------------------------------

func TestCreateGeneratesAKeyAndRecordsTheAction(t *testing.T) {
	h := newHarness(t)

	record, pair, err := h.service.Create(context.Background(), testActor(), newServerInput("dns1"))
	if err != nil {
		t.Fatalf("Create returned an error: %v", err)
	}

	if record.SSHKeyPath != "dns1.key" {
		t.Errorf("key path = %q", record.SSHKeyPath)
	}
	if !strings.HasPrefix(pair.PublicKey, "ssh-ed25519 ") {
		t.Errorf("public key = %q", pair.PublicKey)
	}
	if record.Trusted() {
		t.Error("a new server starts with an approved host key")
	}

	if got := h.auditLog.actions(); len(got) != 1 || got[0] != audit.ActionServerCreate {
		t.Errorf("audit actions = %v", got)
	}
	if details := h.auditLog.entries[0].Details; !strings.Contains(details, "dnsops@dns1.example:22") {
		t.Errorf("the audit detail does not name the endpoint: %q", details)
	}
}

func TestCreateRemovesTheKeyWhenTheRecordIsRefused(t *testing.T) {
	// A key left behind would block the next attempt with the same name.
	h := newHarness(t)
	ctx := context.Background()

	if _, _, err := h.service.Create(ctx, testActor(), newServerInput("dns1")); err != nil {
		t.Fatalf("the first Create failed: %v", err)
	}
	if _, _, err := h.service.Create(ctx, testActor(), newServerInput("dns1")); err == nil {
		t.Fatal("Create accepted a duplicate name")
	}

	// The first key must still be there and no second one written.
	if _, err := os.Stat(filepath.Join(h.keys.Dir(), "dns1.key")); err != nil {
		t.Errorf("the key of the existing server is gone: %v", err)
	}
}

func TestCreateRefusesAnInvalidRecordBeforeWritingAKey(t *testing.T) {
	h := newHarness(t)

	_, _, err := h.service.Create(context.Background(), testActor(), CreateInput{
		Server: Server{Name: "../escape", Host: "dns1.example", SSHUser: "dnsops"}})
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("got %v, want ErrValidation", err)
	}

	entries, _ := os.ReadDir(h.keys.Dir())
	if len(entries) != 0 {
		t.Errorf("%d key files were written for a refused record", len(entries))
	}
}

func TestCreateRefusesAnInjectedCommandAndLeavesNoKey(t *testing.T) {
	h := newHarness(t)
	input := newServerInput("dns1")
	input.Server.ReloadCmd = "sudo service unbound reload; id"

	_, _, err := h.service.Create(context.Background(), testActor(), input)
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("got %v, want ErrValidation", err)
	}

	entries, _ := os.ReadDir(h.keys.Dir())
	if len(entries) != 0 {
		t.Errorf("%d key files survived a refused record", len(entries))
	}
}

func TestUpdateKeepsTheKeyPathAndTheHostKey(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	record, _, err := h.service.Create(ctx, testActor(), newServerInput("dns1"))
	if err != nil {
		t.Fatalf("Create returned an error: %v", err)
	}
	if err := h.servers.SetHostKey(ctx, record.ID, "ssh-ed25519 AAAAapproved"); err != nil {
		t.Fatalf("SetHostKey returned an error: %v", err)
	}

	changed := record
	changed.Host = "moved.example"
	changed.SSHKeyPath = "../../etc/shadow"
	changed.HostKey = "ssh-ed25519 AAAAattacker"

	if err := h.service.Update(ctx, testActor(), changed); err != nil {
		t.Fatalf("Update returned an error: %v", err)
	}

	stored, err := h.servers.Get(ctx, record.ID)
	if err != nil {
		t.Fatalf("Get returned an error: %v", err)
	}
	if stored.SSHKeyPath != "dns1.key" {
		t.Errorf("key path = %q, want the original", stored.SSHKeyPath)
	}
	if stored.HostKey != "ssh-ed25519 AAAAapproved" {
		t.Errorf("host key = %q, want the approved one", stored.HostKey)
	}
	if stored.Host != "moved.example" {
		t.Errorf("host = %q, want the edit to land", stored.Host)
	}
}

func TestUpdateDropsThePooledConnection(t *testing.T) {
	// The connection carries the previous address and credentials.
	h := newHarness(t)
	ctx := context.Background()

	record, _, err := h.service.Create(ctx, testActor(), newServerInput("dns1"))
	if err != nil {
		t.Fatalf("Create returned an error: %v", err)
	}

	record.Host = "moved.example"
	if err := h.service.Update(ctx, testActor(), record); err != nil {
		t.Fatalf("Update returned an error: %v", err)
	}
	if len(h.connector.removed) != 1 || h.connector.removed[0] != record.ID {
		t.Errorf("removed = %v, want the updated server", h.connector.removed)
	}
}

func TestDeleteRemovesTheRecordTheKeyAndTheConnection(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	record, _, err := h.service.Create(ctx, testActor(), newServerInput("dns1"))
	if err != nil {
		t.Fatalf("Create returned an error: %v", err)
	}

	if err := h.service.Delete(ctx, testActor(), record.ID); err != nil {
		t.Fatalf("Delete returned an error: %v", err)
	}

	if _, err := h.servers.Get(ctx, record.ID); err == nil {
		t.Error("the record survived")
	}
	if _, err := os.Stat(filepath.Join(h.keys.Dir(), "dns1.key")); !os.IsNotExist(err) {
		t.Error("the private key survived the deletion")
	}
	if len(h.connector.removed) == 0 {
		t.Error("the pooled connection was left open")
	}
	if got := h.auditLog.actions(); got[len(got)-1] != audit.ActionServerDelete {
		t.Errorf("audit actions = %v", got)
	}
}

func TestTestConnectionReportsSuccess(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	record, _, err := h.service.Create(ctx, testActor(), newServerInput("dns1"))
	if err != nil {
		t.Fatalf("Create returned an error: %v", err)
	}

	result, err := h.service.TestConnection(ctx, record.ID)
	if err != nil {
		t.Fatalf("TestConnection returned an error: %v", err)
	}
	if !result.OK {
		t.Fatalf("the probe failed: %+v", result)
	}

	stored, _ := h.servers.Get(ctx, record.ID)
	if stored.LastSeenAt == nil {
		t.Error("a successful test did not record the contact")
	}
	if stored.LastError != "" {
		t.Errorf("last error = %q, want it cleared", stored.LastError)
	}
}

func TestTestConnectionReportsTheFailedStep(t *testing.T) {
	// The step is what tells the operator whether to look at the network, the
	// key, the file or the sudoers rules.
	h := newHarness(t)
	ctx := context.Background()
	h.connector.transport.probeErr = &transport.ProbeError{
		Step: transport.StepWrite, Err: transport.ErrCommandFailed}

	record, _, err := h.service.Create(ctx, testActor(), newServerInput("dns1"))
	if err != nil {
		t.Fatalf("Create returned an error: %v", err)
	}

	result, err := h.service.TestConnection(ctx, record.ID)
	if err != nil {
		t.Fatalf("TestConnection returned an error: %v", err)
	}
	if result.OK {
		t.Fatal("a failing probe reported success")
	}
	if result.Step != transport.StepWrite {
		t.Errorf("step = %q, want %q", result.Step, transport.StepWrite)
	}

	stored, _ := h.servers.Get(ctx, record.ID)
	if stored.LastError == "" {
		t.Error("the failure was not recorded on the server")
	}
	if stored.LastSeenAt != nil {
		t.Error("a failed test was recorded as a successful contact")
	}
}

func TestCreateGroupChecksItsMembers(t *testing.T) {
	// The foreign key would refuse this as well, but the message would name a
	// constraint rather than the server the operator picked.
	h := newHarness(t)

	_, err := h.service.CreateGroup(context.Background(), testActor(), Group{
		Name: "resolvers", ServerIDs: []int64{404}})
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("got %v, want ErrValidation", err)
	}
}

func TestGroupActionsAreAudited(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	record, _, err := h.service.Create(ctx, testActor(), newServerInput("dns1"))
	if err != nil {
		t.Fatalf("Create returned an error: %v", err)
	}

	group, err := h.service.CreateGroup(ctx, testActor(), Group{
		Name: "resolvers", ServerIDs: []int64{record.ID}})
	if err != nil {
		t.Fatalf("CreateGroup returned an error: %v", err)
	}

	group.Description = "the office pair"
	if err := h.service.UpdateGroup(ctx, testActor(), group); err != nil {
		t.Fatalf("UpdateGroup returned an error: %v", err)
	}
	if err := h.service.DeleteGroup(ctx, testActor(), group.ID); err != nil {
		t.Fatalf("DeleteGroup returned an error: %v", err)
	}

	want := []string{
		audit.ActionServerCreate,
		audit.ActionGroupCreate,
		audit.ActionGroupUpdate,
		audit.ActionGroupDelete,
	}
	got := h.auditLog.actions()
	if len(got) != len(want) {
		t.Fatalf("audit actions = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("audit action %d = %s, want %s", i, got[i], want[i])
		}
	}
}

func TestTargetsRefusesAnEmptyGroup(t *testing.T) {
	// Nothing would reach a resolver, and the operator would have no way to
	// tell that apart from a success.
	h := newHarness(t)
	ctx := context.Background()

	group, err := h.service.CreateGroup(ctx, testActor(), Group{Name: "resolvers"})
	if err != nil {
		t.Fatalf("CreateGroup returned an error: %v", err)
	}

	_, err = h.service.Targets(ctx, group.ID)
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("got %v, want ErrValidation", err)
	}
	if !strings.Contains(err.Error(), "no members") {
		t.Errorf("the error does not explain the refusal: %v", err)
	}
}

func TestPublicKeyNeverExposesThePrivateHalf(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	record, _, err := h.service.Create(ctx, testActor(), newServerInput("dns1"))
	if err != nil {
		t.Fatalf("Create returned an error: %v", err)
	}

	pair, err := h.service.PublicKey(ctx, record.ID)
	if err != nil {
		t.Fatalf("PublicKey returned an error: %v", err)
	}
	if strings.Contains(pair.PublicKey, "PRIVATE KEY") {
		t.Error("the private key came back from PublicKey")
	}
	if !strings.HasPrefix(pair.Fingerprint, "SHA256:") {
		t.Errorf("fingerprint = %q", pair.Fingerprint)
	}
}
