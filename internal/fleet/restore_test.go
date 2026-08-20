package fleet

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"jbound/internal/audit"
	"jbound/internal/transport"
)

// fakeBackups keeps the stored files in memory, one per server, exactly as the
// table does.
type fakeBackups struct {
	mu      sync.Mutex
	saved   map[int64]FileBackup
	saveErr error
	saves   int
}

func (f *fakeBackups) Save(_ context.Context, serverID int64, content []byte,
	digest string, at time.Time) error {

	f.mu.Lock()
	defer f.mu.Unlock()

	f.saves++
	if f.saveErr != nil {
		return f.saveErr
	}
	f.saved[serverID] = FileBackup{
		ServerID: serverID,
		Content:  append([]byte(nil), content...),
		SHA256:   digest,
		SavedAt:  at,
	}
	return nil
}

func (f *fakeBackups) Get(_ context.Context, serverID int64) (FileBackup, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	backup, ok := f.saved[serverID]
	if !ok {
		return FileBackup{}, ErrNoBackup
	}
	return backup, nil
}

func (f *fakeBackups) ServerIDs(context.Context) (map[int64]bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	held := map[int64]bool{}
	for id := range f.saved {
		held[id] = true
	}
	return held, nil
}

func (f *fakeBackups) content(serverID int64) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return string(f.saved[serverID].Content)
}

func (f *fakeBackups) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.saves
}

func TestAWriteKeepsTheFileItReplaced(t *testing.T) {
	h := newWriteHarness(t, 1)

	target := Target{Scope: ScopeServer, ServerID: 1}
	if _, err := h.writer.Apply(context.Background(), testActor(), target, addOperation()); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}

	if kept := h.backups.content(1); kept != seeded {
		t.Errorf("the stored file is not what the server held before the write:\n%s", kept)
	}
	if strings.Contains(h.backups.content(1), "new.example.net") {
		t.Error("the stored file already carries the change it should protect against")
	}
}

func TestARepairKeepsTheFileItReplaced(t *testing.T) {
	h := newWriteHarness(t, 2)
	h.targets["dns2"].content = []byte("# empty on purpose\n")

	want := record("www.example.net", "A", "192.0.2.10")
	if _, err := h.writer.Repair(context.Background(), testActor(), groupTarget(), want); err != nil {
		t.Fatalf("Repair returned an error: %v", err)
	}

	if kept := h.backups.content(2); kept != "# empty on purpose\n" {
		t.Errorf("the stored file is not what the server held before the repair: %q", kept)
	}
}

func TestAMirrorKeepsTheFileItReplaced(t *testing.T) {
	// A mirror deletes as well as adds, so it is the change with the most to
	// undo and the one a wrong source ruins outright.
	h := newWriteHarness(t, 2)
	before := seeded + "local-data: \"stray.example.net. A 192.0.2.77\"\n"
	h.targets["dns2"].content = []byte(before)

	if _, err := h.writer.Mirror(context.Background(), testActor(), groupTarget()); err != nil {
		t.Fatalf("Mirror returned an error: %v", err)
	}
	if strings.Contains(h.targets["dns2"].file(), "stray.example.net") {
		t.Fatal("the mirror did not remove the record the source lacks")
	}

	if kept := h.backups.content(2); kept != before {
		t.Errorf("the stored file is not what the server held before the mirror:\n%s", kept)
	}
}

func TestARestoreBringsTheFileBack(t *testing.T) {
	h := newWriteHarness(t, 1)
	ctx := context.Background()
	target := Target{Scope: ScopeServer, ServerID: 1}

	if _, err := h.writer.Apply(ctx, testActor(), target, addOperation()); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	if !strings.Contains(h.targets["dns1"].file(), "new.example.net") {
		t.Fatal("the record was not written in the first place")
	}

	result, err := h.writer.RestoreFile(ctx, testActor(), 1)
	if err != nil {
		t.Fatalf("RestoreFile returned an error: %v", err)
	}
	if result.Status != StatusSuccess {
		t.Fatalf("got %+v", result)
	}
	if h.targets["dns1"].file() != seeded {
		t.Errorf("the file was not restored:\n%s", h.targets["dns1"].file())
	}

	// The cache has to follow the file, or the panel keeps showing the record
	// the operator has just taken off the server.
	if h.states.states[1].RecordCount != 2 {
		t.Errorf("the cache holds %d records after the restore, want 2",
			h.states.states[1].RecordCount)
	}
}

func TestARestoreCanItselfBeUndone(t *testing.T) {
	h := newWriteHarness(t, 1)
	ctx := context.Background()
	target := Target{Scope: ScopeServer, ServerID: 1}

	if _, err := h.writer.Apply(ctx, testActor(), target, addOperation()); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	changed := h.targets["dns1"].file()

	if _, err := h.writer.RestoreFile(ctx, testActor(), 1); err != nil {
		t.Fatalf("the first restore returned an error: %v", err)
	}
	if _, err := h.writer.RestoreFile(ctx, testActor(), 1); err != nil {
		t.Fatalf("the second restore returned an error: %v", err)
	}

	if h.targets["dns1"].file() != changed {
		t.Errorf("restoring twice did not return to the changed file:\n%s",
			h.targets["dns1"].file())
	}
}

func TestARestoreWithNothingStoredSaysSo(t *testing.T) {
	h := newWriteHarness(t, 1)

	_, err := h.writer.RestoreFile(context.Background(), testActor(), 1)
	if !errors.Is(err, ErrNoBackup) {
		t.Fatalf("error = %v, want ErrNoBackup", err)
	}
}

func TestARestoreOfAnUnchangedFileWritesNothing(t *testing.T) {
	h := newWriteHarness(t, 1)
	ctx := context.Background()
	target := Target{Scope: ScopeServer, ServerID: 1}

	if _, err := h.writer.Apply(ctx, testActor(), target, addOperation()); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}

	// Somebody else has already put the file back, by hand or through another
	// panel, so the copy and the server now say the same thing.
	h.targets["dns1"].mu.Lock()
	h.targets["dns1"].content = []byte(seeded)
	writes := len(h.targets["dns1"].expectations)
	h.targets["dns1"].mu.Unlock()

	result, err := h.writer.RestoreFile(ctx, testActor(), 1)
	if err != nil {
		t.Fatalf("RestoreFile returned an error: %v", err)
	}
	if result.Status != StatusSkipped {
		t.Fatalf("got %+v, want a skipped result", result)
	}
	if len(h.targets["dns1"].expectations) != writes {
		t.Error("the skipped restore still wrote to the server")
	}
	if h.backups.content(1) != seeded {
		t.Error("the skipped restore replaced the copy it was meant to keep")
	}
}

func TestAFailedCopyDoesNotStopTheWrite(t *testing.T) {
	h := newWriteHarness(t, 1)
	h.backups.saveErr = errors.New("the database is locked")

	target := Target{Scope: ScopeServer, ServerID: 1}
	report, err := h.writer.Apply(context.Background(), testActor(), target, addOperation())
	if err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	if !report.OK() {
		t.Fatalf("got %+v", report.Results)
	}
	if !strings.Contains(h.targets["dns1"].file(), "new.example.net") {
		t.Error("the record was not written")
	}
	if h.backups.count() == 0 {
		t.Error("the write did not try to keep a copy at all")
	}
}

func TestARestoreOfADisabledServerIsSkipped(t *testing.T) {
	h := newWriteHarness(t, 1)

	record := h.servers.records[1]
	record.Enabled = false
	h.servers.records[1] = record

	result, err := h.writer.RestoreFile(context.Background(), testActor(), 1)
	if err != nil {
		t.Fatalf("RestoreFile returned an error: %v", err)
	}
	if result.Status != StatusSkipped {
		t.Fatalf("got %+v, want a skipped result", result)
	}
}

func TestARestoreIsWrittenToTheAuditTrail(t *testing.T) {
	h := newWriteHarness(t, 1)
	ctx := context.Background()
	target := Target{Scope: ScopeServer, ServerID: 1}

	if _, err := h.writer.Apply(ctx, testActor(), target, addOperation()); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	if _, err := h.writer.RestoreFile(ctx, testActor(), 1); err != nil {
		t.Fatalf("RestoreFile returned an error: %v", err)
	}

	var found bool
	for _, entry := range h.audit.all() {
		if entry.Action == audit.ActionFileRestore {
			found = true
			if entry.ServerName != "dns1" || entry.Username != "dnsadmin" {
				t.Errorf("got %+v", entry)
			}
		}
	}
	if !found {
		t.Error("the restore left no audit row")
	}
}

func TestARestoreThatCannotReachTheServerFails(t *testing.T) {
	h := newWriteHarness(t, 1)
	ctx := context.Background()
	target := Target{Scope: ScopeServer, ServerID: 1}

	if _, err := h.writer.Apply(ctx, testActor(), target, addOperation()); err != nil {
		t.Fatalf("Apply returned an error: %v", err)
	}
	h.targets["dns1"].readErr = transport.ErrUnreachable

	result, err := h.writer.RestoreFile(ctx, testActor(), 1)
	if err != nil {
		t.Fatalf("RestoreFile returned an error: %v", err)
	}
	if result.Status != StatusFailed {
		t.Fatalf("got %+v, want a failed result", result)
	}
}
