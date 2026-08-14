// Command devseed fills the development panel with the three targets of the
// stack, so a developer opens a working panel instead of typing the same three
// servers, three host key approvals and one group after every start.
//
// It is part of the development stack and never runs in production: the
// entrypoint of the panel container calls it, and nothing installs it. It
// takes the same path an operator takes, through the server service rather
// than through the tables, so a change to how a server is created reaches this
// as well.
//
// It does nothing when the panel already holds a server. The data is a
// starting point rather than a fixture the stack keeps enforcing, so anything
// a developer changes afterwards stays changed.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"jbound/internal/audit"
	"jbound/internal/database"
	"jbound/internal/server"
	"jbound/internal/settings"
	"jbound/internal/store"
	"jbound/internal/transport"
)

// targets are the three Unbound containers of the stack. The host is the
// service name, which is what the compose network resolves.
var targets = []string{"dns1", "dns2", "dns3"}

// groupName is the group a fleet operation is aimed at in the stack.
const groupName = "resolvers"

// scanAttempts and scanWait bound the wait for a target to answer.
//
// The panel container starts alongside the targets, so the first scan can
// arrive before their sshd is listening.
const (
	scanAttempts = 15
	scanWait     = 2 * time.Second
)

func main() {
	if err := run(); err != nil {
		slog.Error("cannot seed the development panel", "error", err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()

	dataDir := envOr("DATA_DIR", "/var/lib/jbound")
	dbPath := envOr("DB_PATH", filepath.Join(dataDir, "jbound.db"))

	db, err := database.Open(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("cannot open %s: %w", dbPath, err)
	}
	defer db.Close()

	servers := store.NewServers(db.DB)
	existing, err := servers.List(ctx)
	if err != nil {
		return fmt.Errorf("cannot read the servers: %w", err)
	}
	if len(existing) > 0 {
		slog.Info("the panel already holds servers, leaving them alone",
			"servers", len(existing))
		return nil
	}

	material, err := os.ReadFile(filepath.Join(dataDir, server.KeySubdir, "dev_ed25519"))
	if err != nil {
		return fmt.Errorf("cannot read the development key: %w", err)
	}

	keys, err := server.NewKeyStore(dataDir)
	if err != nil {
		return fmt.Errorf("cannot open the key store: %w", err)
	}

	timeouts := settings.Fixed(server.Timeouts{
		Connect: 5 * time.Second,
		Command: 15 * time.Second,
	})
	pool := transport.NewPool(ctx, settings.Fixed(30*time.Second))
	defer pool.Close()

	service := server.NewService(servers, store.NewGroups(db.DB), keys, pool,
		audit.NewLogger(store.NewAuditLogs(db.DB), nil), dataDir, timeouts)

	// The actor is the administrator of the stack, so the audit trail reads
	// the way it would if somebody had added these by hand.
	actor := server.Actor{UID: 1001, Username: "dnsadmin", IPAddress: "127.0.0.1"}

	var ids []int64
	for _, name := range targets {
		id, err := addTarget(ctx, service, actor, name, string(material))
		if err != nil {
			return err
		}
		ids = append(ids, id)
	}

	if _, err := service.CreateGroup(ctx, actor, server.Group{
		Name:        groupName,
		Description: "Every target of the development stack",
		ServerIDs:   ids,
	}); err != nil {
		return fmt.Errorf("cannot create the group: %w", err)
	}

	slog.Info("the development panel is seeded",
		"servers", len(ids), "group", groupName)
	return nil
}

// addTarget creates one server and approves the key it offers.
//
// Approving a key without looking at it is what the panel refuses an operator,
// and rightly so. Here the two ends of the connection are containers of the
// same stack, started from the same key pair a moment ago, so there is nothing
// for a person to compare against.
func addTarget(ctx context.Context, service *server.Service, actor server.Actor,
	name, material string) (int64, error) {

	record, _, err := service.Create(ctx, actor, server.CreateInput{
		Server: server.Server{
			Name: name, Host: name, SSHUser: "dnsops", Enabled: true,
			// The containers carry no systemd, so the init script answers.
			StatusCmd: "/usr/sbin/service unbound status",
		},
		PrivateKey: material,
	})
	if err != nil {
		return 0, fmt.Errorf("cannot create %s: %w", name, err)
	}

	offer, err := scan(ctx, service, record.ID, name)
	if err != nil {
		return 0, err
	}
	if err := service.TrustHostKey(ctx, actor, record.ID, offer.Fingerprint); err != nil {
		return 0, fmt.Errorf("cannot approve the host key of %s: %w", name, err)
	}
	return record.ID, nil
}

// scan waits for a target to offer its host key.
func scan(ctx context.Context, service *server.Service, id int64, name string) (server.HostKeyOffer, error) {
	var last error

	for attempt := 1; attempt <= scanAttempts; attempt++ {
		offer, err := service.ScanHostKey(ctx, id)
		if err == nil {
			return offer, nil
		}
		last = err

		slog.Info("waiting for a target to answer",
			"server", name, "attempt", attempt, "error", err)
		select {
		case <-ctx.Done():
			return server.HostKeyOffer{}, ctx.Err()
		case <-time.After(scanWait):
		}
	}
	return server.HostKeyOffer{}, fmt.Errorf("%s never offered a host key: %w",
		name, errors.Join(last))
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
