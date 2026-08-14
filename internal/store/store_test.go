package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"unbound-web/internal/auth"
	"unbound-web/internal/dnsfile"
	"unbound-web/internal/fleet"
	"unbound-web/internal/server"
	"unbound-web/internal/store"
)

func TestAServerIsFoundByItsName(t *testing.T) {
	// The name is what an operator types and what the seed of a deployment
	// carries, so the lookup exists next to the one by identifier.
	f := newFixture(t)
	ctx := context.Background()
	created := f.mustCreate(t, "dns1")

	found, err := f.servers.GetByName(ctx, "dns1")
	if err != nil {
		t.Fatalf("cannot read the server: %v", err)
	}
	if found.ID != created.ID {
		t.Errorf("id = %d, want %d", found.ID, created.ID)
	}

	_, err = f.servers.GetByName(ctx, "dns9")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a name nobody registered returned %v, want ErrNotFound", err)
	}
}

func TestTheKeyPathIsStoredAfterTheRowExists(t *testing.T) {
	// The key file is named after the row, so the path is only known once the
	// row has an identifier.
	f := newFixture(t)
	ctx := context.Background()
	record := f.mustCreate(t, "dns1")

	if err := f.servers.SetKeyPath(ctx, record.ID, "keys/server-1.key"); err != nil {
		t.Fatalf("cannot store the key path: %v", err)
	}

	stored, err := f.servers.Get(ctx, record.ID)
	if err != nil {
		t.Fatalf("cannot read the server: %v", err)
	}
	if stored.SSHKeyPath != "keys/server-1.key" {
		t.Errorf("key path = %q, want keys/server-1.key", stored.SSHKeyPath)
	}

	if err := f.servers.SetKeyPath(ctx, 404, "keys/gone.key"); err == nil {
		t.Error("a row that does not exist accepted a key path")
	}
}

func TestAnEditCannotQuietlyTrustADifferentServer(t *testing.T) {
	// Approving a host key is its own action. An edit that carried the key
	// along would let a rename point the panel at another machine.
	f := newFixture(t)
	ctx := context.Background()
	record := f.mustCreate(t, "dns1")

	if err := f.servers.SetHostKey(ctx, record.ID, "ssh-ed25519 AAAAapproved"); err != nil {
		t.Fatalf("cannot approve the host key: %v", err)
	}

	record.Name = "dns1-renamed"
	record.Host = "10.0.0.9"
	record.HostKey = "ssh-ed25519 AAAAsomethingelse"
	record.Enabled = false
	if err := f.servers.Update(ctx, record); err != nil {
		t.Fatalf("cannot update the server: %v", err)
	}

	stored, err := f.servers.Get(ctx, record.ID)
	if err != nil {
		t.Fatalf("cannot read the server: %v", err)
	}
	if stored.HostKey != "ssh-ed25519 AAAAapproved" {
		t.Errorf("host key = %q, want the approved one", stored.HostKey)
	}
	if stored.Name != "dns1-renamed" || stored.Host != "10.0.0.9" || stored.Enabled {
		t.Errorf("the edit did not land: %+v", stored)
	}
}

func TestARenameOntoATakenNameIsRefused(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.mustCreate(t, "dns1")
	second := f.mustCreate(t, "dns2")

	second.Name = "dns1"
	if err := f.servers.Update(ctx, second); !errors.Is(err, server.ErrNameTaken) {
		t.Errorf("update returned %v, want ErrNameTaken", err)
	}
}

func TestAnUpdateOfAServerThatIsGoneIsRefused(t *testing.T) {
	// The row vanished between the read and the write, which is a conflict
	// rather than an update that happened to change nothing.
	f := newFixture(t)
	record := f.mustCreate(t, "dns1")

	if err := f.servers.Delete(context.Background(), record.ID); err != nil {
		t.Fatalf("cannot delete the server: %v", err)
	}
	if err := f.servers.Update(context.Background(), record); err == nil {
		t.Error("the update of a deleted server was accepted")
	}
}

func TestAGroupKeepsItsNewMembershipAndDropsTheOld(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	first := f.mustCreate(t, "dns1")
	second := f.mustCreate(t, "dns2")

	group, err := f.groups.Create(ctx, server.Group{
		Name: "resolvers", ServerIDs: []int64{first.ID}})
	if err != nil {
		t.Fatalf("cannot create the group: %v", err)
	}

	group.Name = "edge"
	group.Description = "the two that answer"
	group.ServerIDs = []int64{second.ID}
	if err := f.groups.Update(ctx, group); err != nil {
		t.Fatalf("cannot update the group: %v", err)
	}

	stored, err := f.groups.Get(ctx, group.ID)
	if err != nil {
		t.Fatalf("cannot read the group: %v", err)
	}
	if stored.Name != "edge" || stored.Description != "the two that answer" {
		t.Errorf("the edit did not land: %+v", stored)
	}
	if len(stored.ServerIDs) != 1 || stored.ServerIDs[0] != second.ID {
		t.Errorf("membership = %v, want only dns2", stored.ServerIDs)
	}
}

func TestAGroupThatIsGoneCannotBeUpdated(t *testing.T) {
	f := newFixture(t)

	err := f.groups.Update(context.Background(),
		server.Group{ID: 404, Name: "resolvers"})
	if err == nil {
		t.Error("the update of a group that does not exist was accepted")
	}
}

func TestDeletingAServerLeavesTheGroupBehind(t *testing.T) {
	// The membership row goes with the server. The group itself is the
	// operator's, so removing one machine may not remove it.
	f := newFixture(t)
	ctx := context.Background()
	first := f.mustCreate(t, "dns1")
	second := f.mustCreate(t, "dns2")

	group, err := f.groups.Create(ctx, server.Group{
		Name: "resolvers", ServerIDs: []int64{first.ID, second.ID}})
	if err != nil {
		t.Fatalf("cannot create the group: %v", err)
	}

	if err := f.servers.Delete(ctx, first.ID); err != nil {
		t.Fatalf("cannot delete the server: %v", err)
	}

	stored, err := f.groups.Get(ctx, group.ID)
	if err != nil {
		t.Fatalf("cannot read the group: %v", err)
	}
	if len(stored.ServerIDs) != 1 || stored.ServerIDs[0] != second.ID {
		t.Errorf("membership = %v, want only dns2", stored.ServerIDs)
	}
}

func TestTheCachedRecordsOfOneServerAreDropped(t *testing.T) {
	// A server that leaves the panel takes its cache with it, and the cache of
	// another server may not go with it.
	f := newCacheFixture(t)
	ctx := context.Background()

	first := []dnsfile.Record{cached(1, "www.example.local", "A", "10.0.0.1")}
	second := []dnsfile.Record{cached(1, "mail.example.local", "A", "10.0.0.2")}

	if err := f.records.Replace(ctx, f.first.ID, first); err != nil {
		t.Fatalf("cannot fill the cache: %v", err)
	}
	if err := f.records.Replace(ctx, f.second.ID, second); err != nil {
		t.Fatalf("cannot fill the cache: %v", err)
	}

	if err := f.records.Clear(ctx, f.first.ID); err != nil {
		t.Fatalf("cannot clear the cache: %v", err)
	}

	byServer, err := f.records.ByServer(ctx, fleet.Query{})
	if err != nil {
		t.Fatalf("cannot read the cache: %v", err)
	}
	if len(byServer[f.first.ID]) != 0 {
		t.Errorf("dns1 still holds %d records", len(byServer[f.first.ID]))
	}
	if len(byServer[f.second.ID]) != 1 {
		t.Errorf("dns2 holds %d records, want its own to survive",
			len(byServer[f.second.ID]))
	}
}

func TestTheDiffReadsWholeFilesRatherThanAPage(t *testing.T) {
	// The comparison is between files. A page limit here would report a
	// difference that is only the end of the page.
	f := newCacheFixture(t)
	ctx := context.Background()

	var many []dnsfile.Record
	for i := range fleet.DefaultPerPage + 5 {
		many = append(many, cached(i+1,
			"host"+strings.Repeat("x", i%3)+".example.local", "A", "10.0.0.1"))
	}
	if err := f.records.Replace(ctx, f.first.ID, many); err != nil {
		t.Fatalf("cannot fill the cache: %v", err)
	}

	byServer, err := f.records.ByServer(ctx, fleet.Query{})
	if err != nil {
		t.Fatalf("cannot read the cache: %v", err)
	}
	if len(byServer[f.first.ID]) != len(many) {
		t.Errorf("%d records came back, want all %d",
			len(byServer[f.first.ID]), len(many))
	}
}

func TestTheDiffCanBeNarrowedToOneGroup(t *testing.T) {
	f := newCacheFixture(t)
	ctx := context.Background()

	if err := f.records.Replace(ctx, f.first.ID,
		[]dnsfile.Record{cached(1, "www.example.local", "A", "10.0.0.1")}); err != nil {
		t.Fatalf("cannot fill the cache: %v", err)
	}
	if err := f.records.Replace(ctx, f.second.ID,
		[]dnsfile.Record{cached(1, "mail.example.local", "A", "10.0.0.2")}); err != nil {
		t.Fatalf("cannot fill the cache: %v", err)
	}

	byServer, err := f.records.ByServer(ctx,
		fleet.Query{Scope: fleet.ScopeGroup, GroupID: f.group.ID})
	if err != nil {
		t.Fatalf("cannot read the cache: %v", err)
	}
	if len(byServer) != 1 {
		t.Fatalf("%d servers came back, want the one in the group", len(byServer))
	}
	if len(byServer[f.first.ID]) != 1 {
		t.Errorf("the member of the group holds %d records, want 1",
			len(byServer[f.first.ID]))
	}
}

func TestASessionIsRemovedOnItsOwnAndByAccount(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	sessions := store.NewSessions(f.db)

	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	for _, id := range []string{"one", "two"} {
		err := sessions.Create(ctx, auth.Session{
			ID: id, UID: 1001, Username: "dnsadmin", Role: auth.RoleAdmin,
			Fingerprint: "fp", CSRFToken: "token",
			CreatedAt: now, LastActive: now, RegeneratedAt: now,
		})
		if err != nil {
			t.Fatalf("cannot create the session %s: %v", id, err)
		}
	}

	if err := sessions.Delete(ctx, "one"); err != nil {
		t.Fatalf("cannot delete the session: %v", err)
	}
	if _, err := sessions.Get(ctx, "one"); err == nil {
		t.Error("the deleted session still answers")
	}
	// Deleting a session that is already gone is what a second logout looks
	// like, and it is not a failure.
	if err := sessions.Delete(ctx, "one"); err != nil {
		t.Errorf("the second delete returned %v", err)
	}

	if _, err := sessions.DeleteByUIDExcept(ctx, 1001, "kept"); err != nil {
		t.Fatalf("cannot delete the sessions of the account: %v", err)
	}
	if _, err := sessions.Get(ctx, "two"); err == nil {
		t.Error("a session of the account survived")
	}
}
