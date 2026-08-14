package fleet

import (
	"context"
	"errors"
	"strings"
	"testing"

	"jbound/internal/audit"
	"jbound/internal/transport"
)

func TestReloadReachesEveryMemberOfTheGroup(t *testing.T) {
	h := newWriteHarness(t, 3)

	report, err := h.writer.Reload(context.Background(), testActor(), groupTarget())
	if err != nil {
		t.Fatalf("Reload returned an error: %v", err)
	}
	if !report.OK() {
		t.Fatalf("got %+v", report.Results)
	}

	for name, target := range h.targets {
		if target.reloads != 1 {
			t.Errorf("%s was reloaded %d times", name, target.reloads)
		}
	}
}

func TestAFailedReloadDoesNotStopTheOthers(t *testing.T) {
	h := newWriteHarness(t, 3)
	h.targets["dns2"].reloadErr = transport.ErrCommandFailed

	report, err := h.writer.Reload(context.Background(), testActor(), groupTarget())
	if err != nil {
		t.Fatalf("Reload returned an error: %v", err)
	}

	success, failed, _ := report.Counts()
	if success != 2 || failed != 1 {
		t.Fatalf("counts = %d success and %d failed", success, failed)
	}
	if !report.Partial() {
		t.Error("a mixed outcome is not reported as partial")
	}
}

func TestASuccessfulReloadClearsTheUnappliedMarker(t *testing.T) {
	h := newWriteHarness(t, 1)

	// A write leaves the file ahead of what the resolver holds, which is the
	// state the marker exists for.
	if _, err := h.writer.Apply(context.Background(), testActor(), groupTarget(), addOperation()); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}

	before, _ := h.states.Get(context.Background(), 1)
	if !before.Pending() {
		t.Fatal("a written file does not read as unapplied")
	}

	if _, err := h.writer.Reload(context.Background(), testActor(), groupTarget()); err != nil {
		t.Fatalf("Reload returned an error: %v", err)
	}

	after, _ := h.states.Get(context.Background(), 1)
	if after.Pending() {
		t.Errorf("the marker survived the reload: file %q applied %q",
			after.FileSHA256, after.AppliedSHA256)
	}
}

func TestAFailedReloadLeavesTheMarkerUp(t *testing.T) {
	// The safe direction. The operator sees work still to do rather than a
	// change that never went live.
	h := newWriteHarness(t, 1)
	h.targets["dns1"].reloadErr = transport.ErrCommandFailed

	if _, err := h.writer.Apply(context.Background(), testActor(), groupTarget(), addOperation()); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	if _, err := h.writer.Reload(context.Background(), testActor(), groupTarget()); err != nil {
		t.Fatalf("Reload returned an error: %v", err)
	}

	state, _ := h.states.Get(context.Background(), 1)
	if !state.Pending() {
		t.Error("a failed reload cleared the unapplied marker")
	}
}

func TestADisabledServerIsSkippedByAReload(t *testing.T) {
	h := newWriteHarness(t, 2)

	record := h.servers.records[2]
	record.Enabled = false
	h.servers.records[2] = record
	h.groups.members[1][1] = record

	report, err := h.writer.Reload(context.Background(), testActor(), groupTarget())
	if err != nil {
		t.Fatalf("Reload returned an error: %v", err)
	}

	success, failed, skipped := report.Counts()
	if success != 1 || failed != 0 || skipped != 1 {
		t.Fatalf("counts = %d/%d/%d, want one skipped", success, failed, skipped)
	}
	if h.targets["dns2"].reloads != 0 {
		t.Error("a disabled server was reloaded")
	}
}

func TestAReloadAgainstEveryServerIsRefused(t *testing.T) {
	h := newWriteHarness(t, 2)

	_, err := h.writer.Reload(context.Background(), testActor(), Target{Scope: ScopeAll})
	if !errors.Is(err, ErrScope) {
		t.Fatalf("got %v, want ErrScope", err)
	}
	if h.targets["dns1"].reloads != 0 {
		t.Error("a refused target still reached a server")
	}
}

func TestTheReloadAuditRowCarriesTheOutput(t *testing.T) {
	h := newWriteHarness(t, 1)
	h.targets["dns1"].reloadOut = "unbound-control reload\nok\n"

	if _, err := h.writer.Reload(context.Background(), testActor(), groupTarget()); err != nil {
		t.Fatalf("Reload returned an error: %v", err)
	}

	entries := h.audit.all()
	if len(entries) != 1 {
		t.Fatalf("got %d audit rows, want 1", len(entries))
	}
	if entries[0].Action != audit.ActionDNSRestart {
		t.Errorf("action = %q", entries[0].Action)
	}
	if !strings.HasPrefix(entries[0].Details, "Unbound service reloaded. Output: ") {
		t.Errorf("details = %q", entries[0].Details)
	}
	if !strings.Contains(entries[0].Details, "unbound-control reload ok") {
		t.Errorf("the output was not folded into one line: %q", entries[0].Details)
	}
	if entries[0].ServerID == nil || *entries[0].ServerID != 1 {
		t.Error("the row does not name the server")
	}
}

func TestASilentReloadStillReadsAsOne(t *testing.T) {
	// A reload that prints nothing is the usual case, and an audit row ending
	// in "Output:" would read as a truncated entry.
	h := newWriteHarness(t, 1)

	if _, err := h.writer.Reload(context.Background(), testActor(), groupTarget()); err != nil {
		t.Fatalf("Reload returned an error: %v", err)
	}

	entries := h.audit.all()
	if len(entries) != 1 || !strings.Contains(entries[0].Details, "Output: none") {
		t.Fatalf("details = %+v", entries)
	}
}

func TestALongReloadOutputIsCut(t *testing.T) {
	h := newWriteHarness(t, 1)
	h.targets["dns1"].reloadOut = strings.Repeat("a", maxReloadOutput*2)

	if _, err := h.writer.Reload(context.Background(), testActor(), groupTarget()); err != nil {
		t.Fatalf("Reload returned an error: %v", err)
	}

	entries := h.audit.all()
	if len(entries) != 1 {
		t.Fatalf("got %d audit rows, want 1", len(entries))
	}
	if len(entries[0].Details) > maxReloadOutput+64 {
		t.Errorf("the details run to %d characters", len(entries[0].Details))
	}
}

func TestNoAuditRowForAServerThatDidNotReload(t *testing.T) {
	h := newWriteHarness(t, 2)
	h.targets["dns2"].reloadErr = transport.ErrCommandFailed

	if _, err := h.writer.Reload(context.Background(), testActor(), groupTarget()); err != nil {
		t.Fatalf("Reload returned an error: %v", err)
	}

	entries := h.audit.all()
	if len(entries) != 1 {
		t.Fatalf("got %d audit rows, want one per server that reloaded", len(entries))
	}
	if entries[0].ServerID == nil || *entries[0].ServerID != 1 {
		t.Errorf("the row names the wrong server: %+v", entries[0])
	}
}
