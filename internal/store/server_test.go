package store_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"unbound-web/internal/database"
	"unbound-web/internal/server"
	"unbound-web/internal/store"
)

type fixture struct {
	servers *store.Servers
	groups  *store.Groups
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	db, err := database.Open(context.Background(), filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatalf("cannot open the test database: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	return &fixture{
		servers: store.NewServers(db.DB),
		groups:  store.NewGroups(db.DB),
	}
}

func sampleServer(name string) server.Server {
	record := server.Server{
		Name:       name,
		Host:       name + ".example",
		SSHUser:    "dnsops",
		SSHKeyPath: "keys/" + name + ".key",
		Enabled:    true,
	}
	record.ApplyDefaults()
	return record
}

func (f *fixture) mustCreate(t *testing.T, name string) server.Server {
	t.Helper()

	record, err := f.servers.Create(context.Background(), sampleServer(name))
	if err != nil {
		t.Fatalf("cannot create the server %s: %v", name, err)
	}
	return record
}

func TestServerRoundTrip(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	created := f.mustCreate(t, "dns1")
	if created.ID == 0 {
		t.Fatal("the new server has no identifier")
	}

	read, err := f.servers.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get returned an error: %v", err)
	}
	if read.Name != "dns1" || read.Host != "dns1.example" || read.SSHUser != "dnsops" {
		t.Errorf("got %+v", read)
	}
	if !read.Enabled {
		t.Error("the enabled flag did not survive")
	}
	if read.SSHPort != server.DefaultSSHPort || read.Sha256Path != server.DefaultSha256Path {
		t.Errorf("the defaults did not survive: %+v", read)
	}
	if read.CreatedAt.IsZero() || read.CreatedAt.Location() != time.UTC {
		t.Errorf("created_at = %v, want a UTC timestamp", read.CreatedAt)
	}
	if read.LastSeenAt != nil {
		t.Error("a server nobody contacted has a last seen time")
	}
}

func TestServerNameIsUnique(t *testing.T) {
	f := newFixture(t)
	f.mustCreate(t, "dns1")

	_, err := f.servers.Create(context.Background(), sampleServer("dns1"))
	if !errors.Is(err, server.ErrNameTaken) {
		t.Fatalf("got %v, want ErrNameTaken", err)
	}
}

func TestUpdateWritesTheEditableFields(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	record := f.mustCreate(t, "dns1")

	record.Host = "moved.example"
	record.SSHPort = 2222
	record.Enabled = false
	record.ReloadCmd = "sudo /usr/sbin/service unbound restart"

	if err := f.servers.Update(ctx, record); err != nil {
		t.Fatalf("Update returned an error: %v", err)
	}

	read, err := f.servers.Get(ctx, record.ID)
	if err != nil {
		t.Fatalf("Get returned an error: %v", err)
	}
	if read.Host != "moved.example" || read.SSHPort != 2222 || read.Enabled {
		t.Errorf("the update did not land: %+v", read)
	}
	if read.ReloadCmd != "sudo /usr/sbin/service unbound restart" {
		t.Errorf("reload command = %q", read.ReloadCmd)
	}
}

func TestUpdateLeavesTheHostKeyAlone(t *testing.T) {
	// Approving a key is its own action, so a routine edit must not be able to
	// trust a different server.
	f := newFixture(t)
	ctx := context.Background()
	record := f.mustCreate(t, "dns1")

	if err := f.servers.SetHostKey(ctx, record.ID, "ssh-ed25519 AAAAapproved"); err != nil {
		t.Fatalf("SetHostKey returned an error: %v", err)
	}

	record.HostKey = "ssh-ed25519 AAAAsomethingelse"
	record.Host = "moved.example"
	if err := f.servers.Update(ctx, record); err != nil {
		t.Fatalf("Update returned an error: %v", err)
	}

	read, err := f.servers.Get(ctx, record.ID)
	if err != nil {
		t.Fatalf("Get returned an error: %v", err)
	}
	if read.HostKey != "ssh-ed25519 AAAAapproved" {
		t.Errorf("host key = %q, want the approved one", read.HostKey)
	}
}

func TestSetReachabilityRecordsBothOutcomes(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	record := f.mustCreate(t, "dns1")

	when := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	if err := f.servers.SetReachability(ctx, record.ID, when, ""); err != nil {
		t.Fatalf("SetReachability returned an error: %v", err)
	}

	read, err := f.servers.Get(ctx, record.ID)
	if err != nil {
		t.Fatalf("Get returned an error: %v", err)
	}
	if read.LastSeenAt == nil || !read.LastSeenAt.Equal(when) {
		t.Errorf("last seen = %v, want %v", read.LastSeenAt, when)
	}
	if read.LastError != "" {
		t.Errorf("last error = %q, want it cleared", read.LastError)
	}

	// A failure records the reason and leaves the last contact where it was.
	if err := f.servers.SetReachability(ctx, record.ID, when, "connection refused"); err != nil {
		t.Fatalf("SetReachability returned an error: %v", err)
	}
	read, err = f.servers.Get(ctx, record.ID)
	if err != nil {
		t.Fatalf("Get returned an error: %v", err)
	}
	if read.LastError != "connection refused" {
		t.Errorf("last error = %q", read.LastError)
	}
	if read.LastSeenAt != nil {
		t.Error("a failed contact was recorded as a successful one")
	}
}

func TestListIsOrderedByName(t *testing.T) {
	f := newFixture(t)
	for _, name := range []string{"dns3", "dns1", "dns2"} {
		f.mustCreate(t, name)
	}

	servers, err := f.servers.List(context.Background())
	if err != nil {
		t.Fatalf("List returned an error: %v", err)
	}
	if len(servers) != 3 {
		t.Fatalf("got %d servers, want 3", len(servers))
	}
	for i, want := range []string{"dns1", "dns2", "dns3"} {
		if servers[i].Name != want {
			t.Errorf("position %d is %s, want %s", i, servers[i].Name, want)
		}
	}
}

func TestListEnabledSkipsDisabledServers(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	f.mustCreate(t, "dns1")
	disabled := f.mustCreate(t, "dns2")
	disabled.Enabled = false
	if err := f.servers.Update(ctx, disabled); err != nil {
		t.Fatalf("Update returned an error: %v", err)
	}

	enabled, err := f.servers.ListEnabled(ctx)
	if err != nil {
		t.Fatalf("ListEnabled returned an error: %v", err)
	}
	if len(enabled) != 1 || enabled[0].Name != "dns1" {
		t.Errorf("got %+v, want only dns1", enabled)
	}
}

func TestGetReportsAMissingServer(t *testing.T) {
	f := newFixture(t)

	if _, err := f.servers.Get(context.Background(), 404); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestGroupRoundTripWithMembership(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	first := f.mustCreate(t, "dns1")
	second := f.mustCreate(t, "dns2")

	created, err := f.groups.Create(ctx, server.Group{
		Name:        "resolvers",
		Description: "the pair that answers the office",
		ServerIDs:   []int64{first.ID, second.ID},
	})
	if err != nil {
		t.Fatalf("Create returned an error: %v", err)
	}
	if len(created.ServerIDs) != 2 {
		t.Fatalf("got %d members, want 2", len(created.ServerIDs))
	}

	members, err := f.groups.Members(ctx, created.ID)
	if err != nil {
		t.Fatalf("Members returned an error: %v", err)
	}
	if len(members) != 2 || members[0].Name != "dns1" || members[1].Name != "dns2" {
		t.Errorf("got %+v, want dns1 and dns2 in name order", members)
	}
}

func TestGroupUpdateReplacesTheMembership(t *testing.T) {
	// The form submits the whole set, so a merge would make unchecking a
	// server do nothing.
	f := newFixture(t)
	ctx := context.Background()

	first := f.mustCreate(t, "dns1")
	second := f.mustCreate(t, "dns2")

	group, err := f.groups.Create(ctx, server.Group{
		Name: "resolvers", ServerIDs: []int64{first.ID, second.ID}})
	if err != nil {
		t.Fatalf("Create returned an error: %v", err)
	}

	group.ServerIDs = []int64{second.ID}
	if err := f.groups.Update(ctx, group); err != nil {
		t.Fatalf("Update returned an error: %v", err)
	}

	read, err := f.groups.Get(ctx, group.ID)
	if err != nil {
		t.Fatalf("Get returned an error: %v", err)
	}
	if len(read.ServerIDs) != 1 || read.ServerIDs[0] != second.ID {
		t.Errorf("membership = %v, want only dns2", read.ServerIDs)
	}
}

func TestAServerMayBelongToSeveralGroups(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	record := f.mustCreate(t, "dns1")

	for _, name := range []string{"resolvers", "office"} {
		if _, err := f.groups.Create(ctx, server.Group{
			Name: name, ServerIDs: []int64{record.ID}}); err != nil {
			t.Fatalf("cannot create the group %s: %v", name, err)
		}
	}

	groups, err := f.groups.List(ctx)
	if err != nil {
		t.Fatalf("List returned an error: %v", err)
	}
	if len(groups) != 2 {
		t.Fatalf("got %d groups, want 2", len(groups))
	}
	for _, group := range groups {
		if len(group.ServerIDs) != 1 || group.ServerIDs[0] != record.ID {
			t.Errorf("group %s has membership %v", group.Name, group.ServerIDs)
		}
	}
}

func TestGroupNameIsUnique(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	if _, err := f.groups.Create(ctx, server.Group{Name: "resolvers"}); err != nil {
		t.Fatalf("Create returned an error: %v", err)
	}
	_, err := f.groups.Create(ctx, server.Group{Name: "resolvers"})
	if !errors.Is(err, server.ErrNameTaken) {
		t.Fatalf("got %v, want ErrNameTaken", err)
	}
}

func TestDeletingAGroupKeepsItsServers(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	record := f.mustCreate(t, "dns1")

	group, err := f.groups.Create(ctx, server.Group{
		Name: "resolvers", ServerIDs: []int64{record.ID}})
	if err != nil {
		t.Fatalf("Create returned an error: %v", err)
	}

	if err := f.groups.Delete(ctx, group.ID); err != nil {
		t.Fatalf("Delete returned an error: %v", err)
	}
	if _, err := f.servers.Get(ctx, record.ID); err != nil {
		t.Fatalf("the server was removed with its group: %v", err)
	}
}

func TestDeletingAServerRemovesItFromEveryGroup(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	first := f.mustCreate(t, "dns1")
	second := f.mustCreate(t, "dns2")

	group, err := f.groups.Create(ctx, server.Group{
		Name: "resolvers", ServerIDs: []int64{first.ID, second.ID}})
	if err != nil {
		t.Fatalf("Create returned an error: %v", err)
	}

	if err := f.servers.Delete(ctx, first.ID); err != nil {
		t.Fatalf("Delete returned an error: %v", err)
	}

	read, err := f.groups.Get(ctx, group.ID)
	if err != nil {
		t.Fatalf("Get returned an error: %v", err)
	}
	if len(read.ServerIDs) != 1 || read.ServerIDs[0] != second.ID {
		t.Errorf("membership = %v, want only dns2", read.ServerIDs)
	}
}

func TestGroupCreateRefusesAMemberThatDoesNotExist(t *testing.T) {
	f := newFixture(t)

	_, err := f.groups.Create(context.Background(), server.Group{
		Name: "resolvers", ServerIDs: []int64{404}})
	if err == nil {
		t.Fatal("Create accepted a member that does not exist")
	}
}
