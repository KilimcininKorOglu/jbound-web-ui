package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"jbound/internal/audit"
	"jbound/internal/settings"
	"jbound/internal/transport"
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

func (f *fakeRepo) SetKeyPath(_ context.Context, id int64, relPath string) error {
	record, ok := f.records[id]
	if !ok {
		return errors.New("not found")
	}
	record.SSHKeyPath = relPath
	f.records[id] = record
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

// List satisfies the repository. The listing is covered where it is used.
func (f *fakeAuditRepo) List(context.Context, audit.Query) (audit.Page, error) {
	return audit.Page{}, nil
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
	keys, err := NewKeyStore(dataDir)
	if err != nil {
		t.Fatalf("cannot create the key store: %v", err)
	}

	servers := newFakeRepo()
	groups := newFakeGroupRepo()
	connector := &fakeConnector{transport: &fakeTransport{}}
	auditRepo := &fakeAuditRepo{}

	return &harness{
		service: NewService(servers, groups, keys, connector,
			audit.NewLogger(auditRepo, nil), dataDir,
			settings.Fixed(Timeouts{Connect: time.Second, Command: time.Second})),
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

	if record.SSHKeyPath != KeyRelPath(record.ID) {
		t.Errorf("key path = %q, want it named after the record", record.SSHKeyPath)
	}
	if _, err := os.Stat(filepath.Join(h.dataDir, record.SSHKeyPath)); err != nil {
		t.Errorf("the key file is missing: %v", err)
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

func TestCreateWritesNoKeyWhenTheRecordIsRefused(t *testing.T) {
	// The record is written first, so a refused name never reaches the key
	// store and the key of the existing server stays untouched.
	h := newHarness(t)
	ctx := context.Background()

	existing, _, err := h.service.Create(ctx, testActor(), newServerInput("dns1"))
	if err != nil {
		t.Fatalf("the first Create failed: %v", err)
	}
	if _, _, err := h.service.Create(ctx, testActor(), newServerInput("dns1")); err == nil {
		t.Fatal("Create accepted a duplicate name")
	}

	entries, err := os.ReadDir(h.keys.Dir())
	if err != nil {
		t.Fatalf("cannot read the key directory: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d key files, want only the one of the existing server", len(entries))
	}
	if _, err := os.Stat(filepath.Join(h.dataDir, existing.SSHKeyPath)); err != nil {
		t.Errorf("the key of the existing server is gone: %v", err)
	}
}

func TestCreateRemovesTheRecordWhenTheKeyIsRefused(t *testing.T) {
	// A server without a key can reach nothing, so a half finished creation
	// must not survive as a row the operator has to notice and clean up.
	h := newHarness(t)

	input := newServerInput("dns1")
	input.PrivateKey = "this is not a key"

	if _, _, err := h.service.Create(context.Background(), testActor(), input); !errors.Is(err, ErrValidation) {
		t.Fatalf("got %v, want ErrValidation", err)
	}

	records, err := h.servers.List(context.Background())
	if err != nil {
		t.Fatalf("List returned an error: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("%d records survived a refused key", len(records))
	}
	if got := h.auditLog.actions(); len(got) != 0 {
		t.Errorf("audit actions = %v, want none for a creation that did not finish", got)
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
	if stored.SSHKeyPath != record.SSHKeyPath {
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

func TestRotateKeyKeepsTheRecordAndReplacesTheKey(t *testing.T) {
	// Deleting and re-creating the server was the only way to re-key it, and
	// that cascade takes the cached records, the state row and the group
	// membership with it.
	h := newHarness(t)
	ctx := context.Background()

	record, first, err := h.service.Create(ctx, testActor(), newServerInput("dns1"))
	if err != nil {
		t.Fatalf("Create returned an error: %v", err)
	}

	same, second, err := h.service.RotateKey(ctx, testActor(), record.ID)
	if err != nil {
		t.Fatalf("RotateKey returned an error: %v", err)
	}

	if second.Fingerprint == first.Fingerprint {
		t.Error("the rotation produced the same key")
	}
	if same.ID != record.ID || same.Name != record.Name {
		t.Errorf("the record changed: %+v", same)
	}

	stored, err := h.servers.Get(ctx, record.ID)
	if err != nil {
		t.Fatalf("the record did not survive: %v", err)
	}
	if stored.SSHKeyPath != record.SSHKeyPath {
		t.Errorf("key path = %q, want the original", stored.SSHKeyPath)
	}

	current, err := h.service.PublicKey(ctx, record.ID)
	if err != nil {
		t.Fatalf("cannot read the stored key: %v", err)
	}
	if current.Fingerprint != second.Fingerprint {
		t.Error("the stored key is not the one the rotation reported")
	}
}

func TestRotateKeyDropsThePooledConnection(t *testing.T) {
	// The open session was authenticated with the key that just went. Leaving
	// it up would make the rotation look finished before the new public key is
	// anywhere near the target.
	h := newHarness(t)
	ctx := context.Background()

	record, _, err := h.service.Create(ctx, testActor(), newServerInput("dns1"))
	if err != nil {
		t.Fatalf("Create returned an error: %v", err)
	}

	if _, _, err := h.service.RotateKey(ctx, testActor(), record.ID); err != nil {
		t.Fatalf("RotateKey returned an error: %v", err)
	}
	if len(h.connector.removed) != 1 || h.connector.removed[0] != record.ID {
		t.Errorf("removed = %v, want the rotated server", h.connector.removed)
	}
}

func TestRotateKeyIsAudited(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	record, _, err := h.service.Create(ctx, testActor(), newServerInput("dns1"))
	if err != nil {
		t.Fatalf("Create returned an error: %v", err)
	}
	if _, _, err := h.service.RotateKey(ctx, testActor(), record.ID); err != nil {
		t.Fatalf("RotateKey returned an error: %v", err)
	}

	actions := h.auditLog.actions()
	if actions[len(actions)-1] != audit.ActionServerRotateKey {
		t.Errorf("audit actions = %v", actions)
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

	result, err := h.service.TestConnection(ctx, testActor(), record.ID)
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

	result, err := h.service.TestConnection(ctx, testActor(), record.ID)
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

func TestAConnectionTestIsAudited(t *testing.T) {
	// The probe opens a session to the configured host with the panel's key
	// and writes the outcome onto the row, which is the evidence the pages
	// present as health. An investigator reading a trust decision needs the
	// probe that produced the fingerprint next to it.
	h := newHarness(t)
	ctx := context.Background()

	record, _, err := h.service.Create(ctx, testActor(), newServerInput("dns1"))
	if err != nil {
		t.Fatalf("Create returned an error: %v", err)
	}
	if _, err := h.service.TestConnection(ctx, testActor(), record.ID); err != nil {
		t.Fatalf("TestConnection returned an error: %v", err)
	}

	entry := h.auditLog.entries[len(h.auditLog.entries)-1]
	if entry.Action != audit.ActionServerTest {
		t.Fatalf("action = %q, want %q", entry.Action, audit.ActionServerTest)
	}
	if entry.Username != testActor().Username || entry.IPAddress != testActor().IPAddress {
		t.Errorf("the entry does not name who tested: %+v", entry)
	}
	if entry.ServerName != "dns1" || entry.ServerID == nil || *entry.ServerID != record.ID {
		t.Errorf("the entry does not name the server: %+v", entry)
	}
}

func TestAFailedConnectionTestIsAuditedByItsClass(t *testing.T) {
	// The class rather than the text, for the same reason the row stores the
	// class: the text names the remote command, its paths and its stderr, and
	// this entry is mirrored to the SIEM.
	h := newHarness(t)
	ctx := context.Background()
	h.connector.transport.probeErr = &transport.ProbeError{
		Step: transport.StepWrite,
		Err: &transport.CommandError{
			Command:  "/usr/bin/base64 -w0 /etc/unbound/host_entries.conf",
			ExitCode: 1,
			Stderr:   "sudo: a password is required",
		},
	}

	record, _, err := h.service.Create(ctx, testActor(), newServerInput("dns1"))
	if err != nil {
		t.Fatalf("Create returned an error: %v", err)
	}
	if _, err := h.service.TestConnection(ctx, testActor(), record.ID); err != nil {
		t.Fatalf("TestConnection returned an error: %v", err)
	}

	entry := h.auditLog.entries[len(h.auditLog.entries)-1]
	if entry.Action != audit.ActionServerTest {
		t.Fatalf("action = %q, want %q", entry.Action, audit.ActionServerTest)
	}
	if !strings.Contains(entry.Details, transport.CodeCommandFailed) {
		t.Errorf("the entry does not carry the failure class: %q", entry.Details)
	}
	for _, secret := range []string{"base64", "host_entries.conf", "sudo"} {
		if strings.Contains(entry.Details, secret) {
			t.Errorf("the entry carries %q: %s", secret, entry.Details)
		}
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

func TestTheReadsGoStraightToTheStore(t *testing.T) {
	// The service adds nothing to a read. The test exists so a future guard on
	// one of them cannot be added without a test noticing.
	h := newHarness(t)
	ctx := context.Background()

	created, _, err := h.service.Create(ctx, testActor(), newServerInput("dns1"))
	if err != nil {
		t.Fatalf("cannot create the server: %v", err)
	}

	found, err := h.service.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("cannot read the server: %v", err)
	}
	if found.Name != "dns1" {
		t.Errorf("name = %q, want dns1", found.Name)
	}

	all, err := h.service.List(ctx)
	if err != nil {
		t.Fatalf("cannot list the servers: %v", err)
	}
	if len(all) != 1 {
		t.Errorf("%d servers came back, want 1", len(all))
	}

	if _, err := h.service.Get(ctx, 404); err == nil {
		t.Error("a server that does not exist was read")
	}
}

func TestTheGroupReadsGoStraightToTheStore(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	created, _, err := h.service.Create(ctx, testActor(), newServerInput("dns1"))
	if err != nil {
		t.Fatalf("cannot create the server: %v", err)
	}
	group, err := h.service.CreateGroup(ctx, testActor(), Group{
		Name: "resolvers", ServerIDs: []int64{created.ID}})
	if err != nil {
		t.Fatalf("cannot create the group: %v", err)
	}

	found, err := h.service.GetGroup(ctx, group.ID)
	if err != nil {
		t.Fatalf("cannot read the group: %v", err)
	}
	if found.Name != "resolvers" {
		t.Errorf("name = %q, want resolvers", found.Name)
	}

	all, err := h.service.ListGroups(ctx)
	if err != nil {
		t.Fatalf("cannot list the groups: %v", err)
	}
	if len(all) != 1 {
		t.Errorf("%d groups came back, want 1", len(all))
	}
}

func TestARecordedProbeFailureKeepsItsTextOutOfTheDatabase(t *testing.T) {
	// The stored value is read back into the server table, where it used to
	// travel into a tooltip. A probe failure names the remote command, its
	// paths and its stderr, so the class is what is kept.
	h := newHarness(t)
	ctx := context.Background()
	h.connector.transport.probeErr = &transport.ProbeError{
		Step: transport.StepWrite,
		Err: &transport.CommandError{
			Command:  "/usr/bin/base64 -w0 /etc/unbound/host_entries.conf",
			ExitCode: 1,
			Stderr:   "sudo: a password is required",
		},
	}

	record, _, err := h.service.Create(ctx, testActor(), newServerInput("dns1"))
	if err != nil {
		t.Fatalf("Create returned an error: %v", err)
	}
	if _, err := h.service.TestConnection(ctx, testActor(), record.ID); err != nil {
		t.Fatalf("TestConnection returned an error: %v", err)
	}

	stored, _ := h.servers.Get(ctx, record.ID)
	if stored.LastError != transport.CodeCommandFailed {
		t.Errorf("stored failure = %q, want the class %q",
			stored.LastError, transport.CodeCommandFailed)
	}
	for _, secret := range []string{"base64", "host_entries.conf", "sudo"} {
		if strings.Contains(stored.LastError, secret) {
			t.Errorf("the stored failure carries %q", secret)
		}
	}
}
