//go:build integration

// Exercises Apply Rules and the name query against a development target.
//
// This is the one path no fake can prove: that a record written to the file
// stays invisible to a client until the resolver is reloaded, and that it
// resolves afterwards.
//
// Run it with: make dev-itest

package fleet_test

import (
	"context"
	"strings"
	"testing"

	"unbound-web/internal/dnsfile"
	"unbound-web/internal/fleet"
	"unbound-web/internal/server"
)

// gateRecord is what the test writes and cleans up again.
var gateRecord = dnsfile.Record{
	FQDN: "applygate.example.local", Type: "A", Value: "10.99.99.99",
}

func gateActor() server.Actor {
	return server.Actor{UID: 1001, Username: "dnsadmin", IPAddress: "203.0.113.5"}
}

// resolve asks the target what it answers for the gate record.
func (h *harness) resolve(t *testing.T) []string {
	t.Helper()

	report, err := h.service.Query(context.Background(), gateActor(),
		fleet.Target{Scope: fleet.ScopeServer, ServerID: h.record.ID},
		gateRecord.FQDN, gateRecord.Type)
	if err != nil {
		t.Fatalf("Query returned an error: %v", err)
	}
	if len(report.Results) != 1 {
		t.Fatalf("got %d answers, want 1", len(report.Results))
	}
	if report.Results[0].Err != nil {
		t.Fatalf("the target could not be asked: %v", report.Results[0].Err)
	}
	return report.Results[0].Records
}

// change runs one operation against the target and fails the test if a server
// refused it.
func (h *harness) change(t *testing.T, op fleet.Operation) {
	t.Helper()

	report, err := h.service.Apply(context.Background(), gateActor(),
		fleet.Target{Scope: fleet.ScopeServer, ServerID: h.record.ID}, op)
	if err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	if !report.OK() {
		t.Fatalf("the change failed: %+v", report.Results)
	}
}

// reload applies the rules and fails the test if the target refused.
func (h *harness) reload(t *testing.T) {
	t.Helper()

	report, err := h.service.Reload(context.Background(), gateActor(),
		fleet.Target{Scope: fleet.ScopeServer, ServerID: h.record.ID})
	if err != nil {
		t.Fatalf("Reload returned an error: %v", err)
	}
	if !report.OK() {
		t.Fatalf("the reload failed: %+v", report.Results)
	}
}

func TestGateARecordResolvesOnlyAfterTheRulesAreApplied(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	if result, err := h.refresher.One(ctx, h.record.ID); err != nil || !result.OK() {
		t.Fatalf("the first refresh failed: %v %v", err, result.Err)
	}

	// A previous run may have left the record behind, and the assertion below
	// only means something against a resolver that does not hold it.
	_, _ = h.service.Apply(ctx, gateActor(),
		fleet.Target{Scope: fleet.ScopeServer, ServerID: h.record.ID},
		fleet.Operation{Kind: fleet.OpDelete, Record: gateRecord})
	h.reload(t)

	if answers := h.resolve(t); len(answers) != 0 {
		t.Fatalf("the resolver already holds the record: %v", answers)
	}

	h.change(t, fleet.Operation{Kind: fleet.OpAdd, Record: gateRecord})
	t.Cleanup(func() {
		_, _ = h.service.Apply(context.Background(), gateActor(),
			fleet.Target{Scope: fleet.ScopeServer, ServerID: h.record.ID},
			fleet.Operation{Kind: fleet.OpDelete, Record: gateRecord})
		_, _ = h.service.Reload(context.Background(), gateActor(),
			fleet.Target{Scope: fleet.ScopeServer, ServerID: h.record.ID})
	})

	// The file holds it, the resolver does not. This is the gap Apply Rules
	// exists to close, and the state has to say so.
	state, err := h.states.Get(ctx, h.record.ID)
	if err != nil {
		t.Fatalf("Get returned an error: %v", err)
	}
	if !state.Pending() {
		t.Error("a written file does not read as unapplied")
	}
	if answers := h.resolve(t); len(answers) != 0 {
		t.Errorf("the record resolved before the rules were applied: %v", answers)
	}

	h.reload(t)

	answers := h.resolve(t)
	if len(answers) != 1 || !strings.Contains(answers[0], gateRecord.Value) {
		t.Fatalf("the record does not resolve after the reload: %v", answers)
	}

	state, err = h.states.Get(ctx, h.record.ID)
	if err != nil {
		t.Fatalf("Get returned an error: %v", err)
	}
	if state.Pending() {
		t.Errorf("the unapplied marker survived the reload: file %q applied %q",
			state.FileSHA256, state.AppliedSHA256)
	}
}
