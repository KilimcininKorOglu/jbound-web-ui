package fleet

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"jbound/internal/audit"
	"jbound/internal/transport"
)

func TestTheResolverIsMadeToReadTheFileBeforeItIsRead(t *testing.T) {
	// Order is the whole point. The file the panel reads has to be the one the
	// resolver will load, and the repair puts the clause header in place. A
	// step that ran after the write would leave a rollback writing content
	// from before the repair.
	h := newWriteHarness(t, 1)
	target := h.targets["dns1"]

	if _, err := h.writer.Apply(context.Background(), testActor(),
		Target{Scope: ScopeServer, ServerID: 1}, addOperation()); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}

	calls := target.callOrder()
	if len(calls) == 0 {
		t.Fatal("the target was never called")
	}
	if calls[0] != "ensure-include" {
		t.Errorf("the first call was %q, want the include repair:\n%v", calls[0], calls)
	}

	read := slices.Index(calls, "read")
	if read < 0 {
		t.Fatalf("the file was never read:\n%v", calls)
	}
	if read < slices.Index(calls, "ensure-include") {
		t.Errorf("the file was read before the include was confirmed:\n%v", calls)
	}
}

func TestARepairedResolverConfigurationIsWrittenDown(t *testing.T) {
	// The panel edited a file it does not manage, on a server somebody else
	// set up. An operator who never sees that has no way to know their
	// resolver was misconfigured.
	h := newWriteHarness(t, 1)
	h.targets["dns1"].includeOutput = transport.IncludeAdded

	if _, err := h.writer.Apply(context.Background(), testActor(),
		Target{Scope: ScopeServer, ServerID: 1}, addOperation()); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}

	var found *audit.Entry
	for _, entry := range h.audit.all() {
		if entry.Action == audit.ActionConfigInclude {
			found = &entry
			break
		}
	}
	if found == nil {
		t.Fatalf("no row records the repair:\n%+v", h.audit.all())
	}
	if found.ServerName != "dns1" {
		t.Errorf("the row names %q", found.ServerName)
	}
	if !strings.Contains(found.Details, "dns1") {
		t.Errorf("the row does not say which server: %q", found.Details)
	}
}

func TestAConfigurationThatWasAlreadyRightIsNotWrittenDown(t *testing.T) {
	// Every change would otherwise leave a second row saying nothing happened,
	// and a trail nobody can skim is a trail nobody reads.
	h := newWriteHarness(t, 1)

	if _, err := h.writer.Apply(context.Background(), testActor(),
		Target{Scope: ScopeServer, ServerID: 1}, addOperation()); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}

	for _, entry := range h.audit.all() {
		if entry.Action == audit.ActionConfigInclude {
			t.Errorf("a row was written for a configuration nothing was wrong with: %+v", entry)
		}
	}
}

func TestAServerThatCannotRepairItsConfigurationStillTakesTheChange(t *testing.T) {
	// A target prepared with an older setup script has neither the script nor
	// the sudoers rule for it. Refusing every change on those servers would be
	// a worse answer than writing the file and carrying on.
	h := newWriteHarness(t, 1)
	target := h.targets["dns1"]
	target.includeErr = transport.ErrCommandFailed

	report, err := h.writer.Apply(context.Background(), testActor(),
		Target{Scope: ScopeServer, ServerID: 1}, addOperation())
	if err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	if !report.OK() {
		t.Fatalf("the change was refused: %+v", report.Results)
	}
	if !strings.Contains(target.file(), "new.example.net") {
		t.Errorf("the record was not written:\n%s", target.file())
	}
}

func TestAServerWithNoRepairCommandTakesTheChange(t *testing.T) {
	// An empty command is a target whose record names none, the same way an
	// empty reload rung is skipped rather than failed.
	h := newWriteHarness(t, 1)
	target := h.targets["dns1"]
	target.includeErr = transport.ErrStepSkipped

	report, err := h.writer.Apply(context.Background(), testActor(),
		Target{Scope: ScopeServer, ServerID: 1}, addOperation())
	if err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	if !report.OK() {
		t.Fatalf("the change was refused: %+v", report.Results)
	}
	for _, entry := range h.audit.all() {
		if entry.Action == audit.ActionConfigInclude {
			t.Errorf("a skipped step was written down as a repair: %+v", entry)
		}
	}
}

func TestAWriteCarriesTheClauseHeaderEvenWhenTheTargetHadNone(t *testing.T) {
	// A target set up by hand holds bare local-data lines. Writing them back
	// without a header would keep the file dependent on where the include sits
	// in the main configuration, which is the thing the header removes.
	h := newWriteHarness(t, 1)
	target := h.targets["dns1"]
	target.content = []byte("local-data: \"www.example.net. A 192.0.2.10\"\n")

	if _, err := h.writer.Apply(context.Background(), testActor(),
		Target{Scope: ScopeServer, ServerID: 1}, addOperation()); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}

	if !strings.HasPrefix(target.file(), "server:\n") {
		t.Errorf("the written file opens no clause:\n%s", target.file())
	}
}

func TestARollbackPutsBackAFileTheResolverCanLoad(t *testing.T) {
	// The rollback writes what the file held before the change. On a target
	// that had no header, that content on its own is not loadable from where
	// the include now sits, so the rollback carries one too.
	h := newWriteHarness(t, 1)
	target := h.targets["dns1"]
	target.content = []byte("local-data: \"www.example.net. A 192.0.2.10\"\n")
	target.checkErr = transport.ErrCommandFailed

	report, err := h.writer.Apply(context.Background(), testActor(),
		Target{Scope: ScopeServer, ServerID: 1}, addOperation())
	if err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	if report.OK() {
		t.Fatalf("the refused change was reported as applied: %+v", report.Results)
	}

	restored := target.file()
	if strings.Contains(restored, "new.example.net") {
		t.Errorf("the refused change stayed on the server:\n%s", restored)
	}
	if !strings.HasPrefix(restored, "server:\n") {
		t.Errorf("the rollback opens no clause:\n%s", restored)
	}
}

func TestTheRepairIsNotAskedToWriteAnythingItWasGiven(t *testing.T) {
	// The command takes no arguments, so nothing the panel holds can decide
	// which file a managed server writes. This is what keeps a server record
	// from becoming a way to write /etc/unbound/unbound.conf on the fleet.
	h := newWriteHarness(t, 1)
	record := h.servers.records[1]

	if !strings.HasPrefix(record.EnsureIncludeCmd, "sudo /") {
		t.Fatalf("the repair command is %q", record.EnsureIncludeCmd)
	}
	if fields := strings.Fields(record.EnsureIncludeCmd); len(fields) != 2 {
		t.Errorf("the repair command carries arguments: %q", record.EnsureIncludeCmd)
	}
}

func TestARepairFailureIsNotMistakenForAnAddedInclude(t *testing.T) {
	// The target says "added" and nothing else means a repair happened. A
	// failure that returned output would otherwise write a row about a change
	// that never landed.
	h := newWriteHarness(t, 1)
	target := h.targets["dns1"]
	target.includeOutput = transport.IncludeAdded
	target.includeErr = errors.New("sudo: a password is required")

	if _, err := h.writer.Apply(context.Background(), testActor(),
		Target{Scope: ScopeServer, ServerID: 1}, addOperation()); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}

	for _, entry := range h.audit.all() {
		if entry.Action == audit.ActionConfigInclude {
			t.Errorf("a failed repair was written down as one: %+v", entry)
		}
	}
}
