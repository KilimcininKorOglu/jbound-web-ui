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
	h.targets["dns2"].failEveryRung(transport.ErrCommandFailed)

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
	h.targets["dns1"].failEveryRung(transport.ErrCommandFailed)

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

func TestAReloadAgainstNoTargetIsRefused(t *testing.T) {
	h := newWriteHarness(t, 2)

	_, err := h.writer.Reload(context.Background(), testActor(), Target{})
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
	if !strings.HasPrefix(entries[0].Details, "Unbound service reloaded through the reload. Output: ") {
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
	// The framing names the rung that ran and the group, so the slack is
	// wider than the sentence it replaced.
	if len(entries[0].Details) > maxReloadOutput+128 {
		t.Errorf("the details run to %d characters", len(entries[0].Details))
	}
}

func TestNoAuditRowForAServerThatDidNotReload(t *testing.T) {
	h := newWriteHarness(t, 2)
	h.targets["dns2"].failEveryRung(transport.ErrCommandFailed)

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

func TestTheFirstRungThatWorksIsTheOnlyOneThatRuns(t *testing.T) {
	// The first rung preserves the cache. Running the others after it worked
	// would drop the cache the first one was chosen to keep.
	h := newWriteHarness(t, 1)
	target := h.targets["dns1"]

	report, err := h.writer.Reload(context.Background(), testActor(), groupTarget())
	if err != nil {
		t.Fatalf("Reload returned an error: %v", err)
	}
	if !report.OK() {
		t.Fatalf("got %+v", report.Results)
	}

	if target.reloads != 1 {
		t.Errorf("the first rung ran %d times", target.reloads)
	}
	if target.fallbacks != 0 || target.restarts != 0 {
		t.Errorf("a later rung ran anyway: %d fallbacks, %d restarts",
			target.fallbacks, target.restarts)
	}
}

func TestAFailedRungEscalatesToTheNextOne(t *testing.T) {
	h := newWriteHarness(t, 1)
	target := h.targets["dns1"]
	target.reloadErr = transport.ErrCommandFailed

	report, err := h.writer.Reload(context.Background(), testActor(), groupTarget())
	if err != nil {
		t.Fatalf("Reload returned an error: %v", err)
	}
	if !report.OK() {
		t.Fatalf("the reload failed although the fallback works: %+v", report.Results)
	}

	if target.fallbacks != 1 {
		t.Errorf("the fallback ran %d times", target.fallbacks)
	}
	if target.restarts != 0 {
		t.Error("the restart ran although the fallback worked")
	}
}

func TestARungThatLeavesTheResolverStoppedIsNotSuccess(t *testing.T) {
	// This is the failure the ladder exists for. A configuration Unbound
	// accepts at start but not on SIGHUP stops the daemon, and the command
	// that sent the signal exits zero, so the exit code says everything is
	// fine while the resolver answers nothing.
	h := newWriteHarness(t, 1)
	target := h.targets["dns1"]
	target.activeAfter = map[string]bool{"reload": false, "restart": true}

	report, err := h.writer.Reload(context.Background(), testActor(), groupTarget())
	if err != nil {
		t.Fatalf("Reload returned an error: %v", err)
	}
	if !report.OK() {
		t.Fatalf("got %+v", report.Results)
	}

	if target.restarts != 1 {
		t.Errorf("the resolver was left stopped and restarted %d times", target.restarts)
	}
	if !strings.Contains(report.Results[0].Message, "restarted") {
		t.Errorf("the result does not say what brought it back: %q",
			report.Results[0].Message)
	}
}

func TestAReloadThatLeavesTheResolverStoppedEverywhereFails(t *testing.T) {
	h := newWriteHarness(t, 1)
	h.targets["dns1"].activeAfter = map[string]bool{
		"reload": false, "fallback": false, "restart": false}

	report, err := h.writer.Reload(context.Background(), testActor(), groupTarget())
	if err != nil {
		t.Fatalf("Reload returned an error: %v", err)
	}
	if report.OK() {
		t.Fatalf("a stopped resolver was reported as reloaded: %+v", report.Results)
	}
	if len(h.audit.all()) != 0 {
		t.Error("the trail records a reload the resolver never took")
	}
}

func TestAReloadThatNeverTookLeavesTheMarkerUp(t *testing.T) {
	h := newWriteHarness(t, 1)
	h.targets["dns1"].activeAfter = map[string]bool{
		"reload": false, "fallback": false, "restart": false}

	if _, err := h.writer.Apply(context.Background(), testActor(),
		groupTarget(), addOperation()); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	if _, err := h.writer.Reload(context.Background(), testActor(), groupTarget()); err != nil {
		t.Fatalf("Reload returned an error: %v", err)
	}

	state, _ := h.states.Get(context.Background(), 1)
	if !state.Pending() {
		t.Error("the panel called the change applied while the resolver was stopped")
	}
}

func TestARungTheServerNamesNoCommandForIsSkipped(t *testing.T) {
	// A target whose sudoers rules do not reach a command keeps working. The
	// rung is passed over rather than counted as a failure.
	h := newWriteHarness(t, 1)
	target := h.targets["dns1"]
	target.reloadErr = transport.ErrStepSkipped
	target.fallbackErr = transport.ErrStepSkipped

	report, err := h.writer.Reload(context.Background(), testActor(), groupTarget())
	if err != nil {
		t.Fatalf("Reload returned an error: %v", err)
	}
	if !report.OK() {
		t.Fatalf("got %+v", report.Results)
	}
	if target.restarts != 1 {
		t.Errorf("the restart ran %d times", target.restarts)
	}
}

func TestAServerThatNamesNoReloadCommandAtAllFails(t *testing.T) {
	h := newWriteHarness(t, 1)
	target := h.targets["dns1"]
	target.reloadErr = transport.ErrStepSkipped
	target.fallbackErr = transport.ErrStepSkipped
	target.restartErr = transport.ErrStepSkipped

	report, err := h.writer.Reload(context.Background(), testActor(), groupTarget())
	if err != nil {
		t.Fatalf("Reload returned an error: %v", err)
	}
	if report.OK() {
		t.Fatalf("a server with nothing to run reported a reload: %+v", report.Results)
	}
}

func TestTheAuditRowNamesTheRungThatWorked(t *testing.T) {
	// A fleet whose first rung always fails is dropping its cache on every
	// change, and the trail is where that shows.
	h := newWriteHarness(t, 1)
	h.targets["dns1"].reloadErr = transport.ErrCommandFailed

	if _, err := h.writer.Reload(context.Background(), testActor(), groupTarget()); err != nil {
		t.Fatalf("Reload returned an error: %v", err)
	}

	entries := h.audit.all()
	if len(entries) != 1 {
		t.Fatalf("got %d audit rows, want 1", len(entries))
	}
	if !strings.Contains(entries[0].Details, "reload fallback") {
		t.Errorf("details = %q", entries[0].Details)
	}
}
