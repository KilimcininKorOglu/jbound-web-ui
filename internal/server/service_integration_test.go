//go:build integration

// Exercises the server service against the development targets.
//
// The host key flow is the part of this package that cannot be proven with a
// fake: whether a real server is refused until an operator approves the
// fingerprint it really offers, and whether a key that changes afterwards is
// refused again. All of that needs a real server and a real database.
//
// Run it with: make dev-itest

package server_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"unbound-web/internal/audit"
	"unbound-web/internal/database"
	"unbound-web/internal/server"
	"unbound-web/internal/store"
	"unbound-web/internal/transport"
)

const (
	testTarget  = "dns1"
	testUser    = "dnsops"
	testKeyPath = "/var/lib/unbound-web/keys/dev_ed25519"
)

type harness struct {
	service *server.Service
	servers *store.Servers
	dataDir string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	ctx := context.Background()

	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatalf("cannot open the test database: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	dataDir := t.TempDir()
	keys, err := server.NewKeyStore(dataDir)
	if err != nil {
		t.Fatalf("cannot create the key store: %v", err)
	}

	pool := transport.NewPool(ctx, 30*time.Second)
	t.Cleanup(pool.Close)

	servers := store.NewServers(db.DB)
	return &harness{
		service: server.NewService(servers, store.NewGroups(db.DB), keys, pool,
			audit.NewLogger(store.NewAuditLogs(db.DB)), dataDir,
			server.Timeouts{Connect: 10 * time.Second, Command: 30 * time.Second}),
		servers: servers,
		dataDir: dataDir,
	}
}

// addTarget stores a record for the development target, with the key that
// container already trusts.
func (h *harness) addTarget(t *testing.T) server.Server {
	t.Helper()

	material, err := os.ReadFile(testKeyPath)
	if err != nil {
		t.Fatalf("the development key is missing, run the tests inside the stack: %v", err)
	}

	record, _, err := h.service.Create(context.Background(), testActor(), server.CreateInput{
		Server: server.Server{
			Name:    testTarget,
			Host:    testTarget,
			SSHUser: testUser,
			Enabled: true,
			// The containers carry no systemd, so the init script answers
			// instead. Production uses systemctl, and both are per server.
			StatusCmd: "/usr/sbin/service unbound status",
		},
		PrivateKey: string(material),
	})
	if err != nil {
		t.Fatalf("cannot store the target: %v", err)
	}
	return record
}

func testActor() server.Actor {
	return server.Actor{UID: 1001, Username: "dnsadmin", IPAddress: "203.0.113.5"}
}

func TestANewServerIsRefusedUntilItsHostKeyIsApproved(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	record := h.addTarget(t)

	result, err := h.service.TestConnection(ctx, record.ID)
	if err != nil {
		t.Fatalf("TestConnection returned an error: %v", err)
	}
	if result.OK {
		t.Fatal("the panel talked to a server nobody has approved")
	}
	if result.HostKey == nil {
		t.Fatal("the result carries no fingerprint for the operator to approve")
	}
	if result.HostKeyChanged {
		t.Error("a first contact is reported as a changed key")
	}

	fingerprint := result.HostKey.Fingerprint
	if err := h.service.TrustHostKey(ctx, testActor(), record.ID, fingerprint); err != nil {
		t.Fatalf("TrustHostKey returned an error: %v", err)
	}

	result, err = h.service.TestConnection(ctx, record.ID)
	if err != nil {
		t.Fatalf("the second TestConnection returned an error: %v", err)
	}
	if !result.OK {
		t.Fatalf("the test failed at the %s step after approval: %s", result.Step, result.Message)
	}

	stored, err := h.servers.Get(ctx, record.ID)
	if err != nil {
		t.Fatalf("Get returned an error: %v", err)
	}
	if !stored.Trusted() {
		t.Error("the approved key was not stored")
	}
	if stored.LastSeenAt == nil || stored.LastError != "" {
		t.Errorf("reachability = %v / %q, want a successful contact", stored.LastSeenAt, stored.LastError)
	}
}

func TestApprovingAFingerprintTheServerNoLongerOffersIsRefused(t *testing.T) {
	// Without this check, a server that changed between the display and the
	// click would be trusted unseen.
	h := newHarness(t)
	record := h.addTarget(t)

	err := h.service.TrustHostKey(context.Background(), testActor(), record.ID,
		"SHA256:0000000000000000000000000000000000000000000")
	if !errors.Is(err, server.ErrValidation) {
		t.Fatalf("got %v, want ErrValidation", err)
	}

	stored, err := h.servers.Get(context.Background(), record.ID)
	if err != nil {
		t.Fatalf("Get returned an error: %v", err)
	}
	if stored.Trusted() {
		t.Error("a fingerprint nobody saw was approved")
	}
}

func TestAChangedHostKeyIsRefusedAndAsksForApprovalAgain(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	record := h.addTarget(t)

	// Approve the key the server really offers, then replace it with another
	// one. That is what a reinstalled server, or an impostor, looks like.
	offer, err := h.service.ScanHostKey(ctx, record.ID)
	if err != nil {
		t.Fatalf("ScanHostKey returned an error: %v", err)
	}
	if err := h.service.TrustHostKey(ctx, testActor(), record.ID, offer.Fingerprint); err != nil {
		t.Fatalf("TrustHostKey returned an error: %v", err)
	}
	if err := h.servers.SetHostKey(ctx, record.ID, strangerKey(t)); err != nil {
		t.Fatalf("SetHostKey returned an error: %v", err)
	}

	result, err := h.service.TestConnection(ctx, record.ID)
	if err != nil {
		t.Fatalf("TestConnection returned an error: %v", err)
	}
	if result.OK {
		t.Fatal("the panel talked to a server whose key does not match the approved one")
	}
	if !result.HostKeyChanged {
		t.Error("the changed key is not reported as such")
	}
	if result.HostKey == nil {
		t.Fatal("the operator is not offered the new fingerprint to decide on")
	}
	if result.HostKey.Fingerprint != offer.Fingerprint {
		t.Errorf("fingerprint = %q, want the one the server offers", result.HostKey.Fingerprint)
	}

	// Approving what the server now offers puts it back in service, which is
	// what a reinstall needs.
	if err := h.service.TrustHostKey(ctx, testActor(), record.ID, result.HostKey.Fingerprint); err != nil {
		t.Fatalf("the re-approval returned an error: %v", err)
	}
	result, err = h.service.TestConnection(ctx, record.ID)
	if err != nil {
		t.Fatalf("the second TestConnection returned an error: %v", err)
	}
	if !result.OK {
		t.Fatalf("the test failed at the %s step after re-approval: %s", result.Step, result.Message)
	}
}

// strangerKey returns an authorized_keys line for a key the target does not
// have, so the stored one and the offered one disagree.
func strangerKey(t *testing.T) string {
	t.Helper()

	keys, err := server.NewKeyStore(t.TempDir())
	if err != nil {
		t.Fatalf("cannot create the key store: %v", err)
	}
	pair, err := keys.Generate(1)
	if err != nil {
		t.Fatalf("cannot generate a key: %v", err)
	}
	return pair.PublicKey
}
