package store_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"jbound/internal/audit"
	"jbound/internal/auth"
	"jbound/internal/database"
	"jbound/internal/dnsfile"
	"jbound/internal/fleet"
	"jbound/internal/server"
	"jbound/internal/store"
)

// A store method that cannot reach the database has to say so.
//
// Every one of these ends in a query, and a query can fail for reasons that
// have nothing to do with the caller: a full disk, a data directory that has
// been unmounted, a file whose permissions changed under a running process. The
// danger is not the failure, it is a method that answers "no rows" to a
// question it never got to ask. A caller reading that as an empty result acts
// on it: the diff page reports the fleet as agreeing, the settings page hands
// back defaults, the audit page shows a clean trail.
//
// Closing the database is the cheapest way to make every query fail at once.
func TestEveryReadSurfacesADeadDatabaseRatherThanAnEmptyAnswer(t *testing.T) {
	ctx := context.Background()

	// Each case gets its own database, because the first failing call must be
	// the one under test rather than a leftover from the previous one.
	reads := map[string]func(*testing.T, *dead) error{
		"servers.Get": func(_ *testing.T, d *dead) error {
			_, err := d.servers.Get(ctx, 1)
			return err
		},
		"servers.List": func(_ *testing.T, d *dead) error {
			_, err := d.servers.List(ctx)
			return err
		},
		"servers.ListEnabled": func(_ *testing.T, d *dead) error {
			_, err := d.servers.ListEnabled(ctx)
			return err
		},
		"groups.Get": func(_ *testing.T, d *dead) error {
			_, err := d.groups.Get(ctx, 1)
			return err
		},
		"groups.List": func(_ *testing.T, d *dead) error {
			_, err := d.groups.List(ctx)
			return err
		},
		"groups.Members": func(_ *testing.T, d *dead) error {
			_, err := d.groups.Members(ctx, 1)
			return err
		},
		"records.List": func(_ *testing.T, d *dead) error {
			_, err := d.records.List(ctx, fleet.Query{Page: 1, PerPage: 25})
			return err
		},
		"records.ByServer": func(_ *testing.T, d *dead) error {
			_, err := d.records.ByServer(ctx, fleet.Query{Scope: "server", ServerID: 1})
			return err
		},
		"states.Get": func(_ *testing.T, d *dead) error {
			_, err := d.states.Get(ctx, 1)
			return err
		},
		"states.List": func(_ *testing.T, d *dead) error {
			_, err := d.states.List(ctx)
			return err
		},
		"audit.List": func(_ *testing.T, d *dead) error {
			_, err := d.logs.List(ctx, audit.Query{Page: 1, PerPage: 25})
			return err
		},
		"sessions.Get": func(_ *testing.T, d *dead) error {
			_, err := d.sessions.Get(ctx, "abc")
			return err
		},
		"sessions.ListLive": func(_ *testing.T, d *dead) error {
			_, err := d.sessions.ListLive(ctx, time.Now())
			return err
		},
		"settings.Load": func(_ *testing.T, d *dead) error {
			_, err := d.settings.Load(ctx)
			return err
		},
		"backups.Get": func(_ *testing.T, d *dead) error {
			_, err := d.backups.Get(ctx, 1)
			return err
		},
		"backups.ServerIDs": func(_ *testing.T, d *dead) error {
			_, err := d.backups.ServerIDs(ctx)
			return err
		},
	}

	for name, read := range reads {
		t.Run(name, func(t *testing.T) {
			if err := read(t, newDead(t)); err == nil {
				t.Error("a read against a closed database reported success")
			}
		})
	}
}

func TestEveryWriteSurfacesADeadDatabase(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	writes := map[string]func(*dead) error{
		"servers.Create": func(d *dead) error {
			_, err := d.servers.Create(ctx, sampleServer("dns1"))
			return err
		},
		"servers.Update": func(d *dead) error {
			return d.servers.Update(ctx, sampleServer("dns1"))
		},
		"servers.SetKeyPath": func(d *dead) error {
			return d.servers.SetKeyPath(ctx, 1, "keys/1.key")
		},
		"servers.SetHostKey": func(d *dead) error {
			return d.servers.SetHostKey(ctx, 1, "ssh-ed25519 AAAA")
		},
		"servers.SetReachability": func(d *dead) error {
			return d.servers.SetReachability(ctx, 1, now, "")
		},
		"servers.Delete": func(d *dead) error {
			return d.servers.Delete(ctx, 1)
		},
		"groups.Create": func(d *dead) error {
			_, err := d.groups.Create(ctx, server.Group{Name: "resolvers"})
			return err
		},
		"groups.Update": func(d *dead) error {
			return d.groups.Update(ctx, server.Group{ID: 1, Name: "resolvers"})
		},
		"groups.Delete": func(d *dead) error {
			return d.groups.Delete(ctx, 1)
		},
		"records.Replace": func(d *dead) error {
			return d.records.Replace(ctx, 1, []dnsfile.Record{
				{FQDN: "a.example.net", Type: "A", Value: "10.0.0.1"},
			})
		},
		"states.SetFetched": func(d *dead) error {
			return d.states.SetFetched(ctx, fleet.State{ServerID: 1})
		},
		"states.SetUnreachable": func(d *dead) error {
			return d.states.SetUnreachable(ctx, 1, "no route")
		},
		"states.SetApplied": func(d *dead) error {
			return d.states.SetApplied(ctx, 1, "abc")
		},
		"audit.Write": func(d *dead) error {
			return d.logs.Write(ctx, audit.Entry{
				Username: "dnsadmin", Action: audit.ActionLogin}, now)
		},
		"sessions.Create": func(d *dead) error {
			return d.sessions.Create(ctx, auth.Session{ID: "abc", Username: "dnsadmin"})
		},
		"sessions.Touch": func(d *dead) error {
			return d.sessions.Touch(ctx, "abc", now)
		},
		"sessions.Delete": func(d *dead) error {
			return d.sessions.Delete(ctx, "abc")
		},
		"settings.Save": func(d *dead) error {
			return d.settings.Save(ctx, map[string]string{"panel_name": "JBound"})
		},
		"backups.Save": func(d *dead) error {
			return d.backups.Save(ctx, 1, []byte("content"), "abc", now)
		},
		"loginattempts.Admit": func(d *dead) error {
			_, err := d.attempts.Admit(ctx, "10.0.0.5", "dnsadmin",
				now.Add(-15*time.Minute), now, 10)
			return err
		},
	}

	for name, write := range writes {
		t.Run(name, func(t *testing.T) {
			if err := write(newDead(t)); err == nil {
				t.Error("a write against a closed database reported success")
			}
		})
	}
}

// dead is a set of stores over a database that has been closed.
type dead struct {
	servers  *store.Servers
	groups   *store.Groups
	records  *store.Records
	states   *store.States
	logs     *store.AuditLogs
	sessions *store.Sessions
	settings *store.Settings
	backups  *store.Backups
	attempts *store.LoginAttempts
}

func newDead(t *testing.T) *dead {
	t.Helper()

	db, err := database.Open(context.Background(),
		filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatalf("cannot open the test database: %v", err)
	}
	// The schema is built first, so what fails afterwards is the query and not
	// a table that was never there.
	if err := db.Close(); err != nil {
		t.Fatalf("cannot close the test database: %v", err)
	}

	return &dead{
		servers:  store.NewServers(db.DB),
		groups:   store.NewGroups(db.DB),
		records:  store.NewRecords(db.DB),
		states:   store.NewStates(db.DB),
		logs:     store.NewAuditLogs(db.DB),
		sessions: store.NewSessions(db.DB),
		settings: store.NewSettings(db.DB),
		backups:  store.NewBackups(db.DB),
		attempts: store.NewLoginAttempts(db.DB),
	}
}
