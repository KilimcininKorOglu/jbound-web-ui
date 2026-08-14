package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"unbound-web/internal/fleet"
	"unbound-web/internal/store"
)

func TestTheStoredFileIsReadBackAsItWasWritten(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	backups := store.NewBackups(f.db)

	record := f.mustCreate(t, "dns1")
	content := []byte("local-data: \"www.example.net. A 192.0.2.10\"\n")
	saved := time.Date(2026, 4, 9, 11, 30, 0, 0, time.UTC)

	if err := backups.Save(ctx, record.ID, content, "abc123", saved); err != nil {
		t.Fatalf("Save returned an error: %v", err)
	}

	backup, err := backups.Get(ctx, record.ID)
	if err != nil {
		t.Fatalf("Get returned an error: %v", err)
	}
	if string(backup.Content) != string(content) {
		t.Errorf("content = %q, want %q", backup.Content, content)
	}
	if backup.SHA256 != "abc123" {
		t.Errorf("digest = %q, want abc123", backup.SHA256)
	}
	if !backup.SavedAt.Equal(saved) {
		t.Errorf("saved at = %s, want %s", backup.SavedAt, saved)
	}
}

func TestASecondCopyReplacesTheFirst(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	backups := store.NewBackups(f.db)

	record := f.mustCreate(t, "dns1")
	at := time.Date(2026, 4, 9, 11, 30, 0, 0, time.UTC)

	if err := backups.Save(ctx, record.ID, []byte("first\n"), "one", at); err != nil {
		t.Fatalf("the first Save returned an error: %v", err)
	}
	if err := backups.Save(ctx, record.ID, []byte("second\n"), "two", at.Add(time.Hour)); err != nil {
		t.Fatalf("the second Save returned an error: %v", err)
	}

	var rows int
	if err := f.db.QueryRow(
		"SELECT COUNT(*) FROM file_backups WHERE server_id = ?", record.ID).Scan(&rows); err != nil {
		t.Fatalf("cannot count the stored files: %v", err)
	}
	if rows != 1 {
		t.Errorf("%d rows are stored for one server, want 1", rows)
	}

	backup, err := backups.Get(ctx, record.ID)
	if err != nil {
		t.Fatalf("Get returned an error: %v", err)
	}
	if string(backup.Content) != "second\n" {
		t.Errorf("content = %q, want the second copy", backup.Content)
	}
}

func TestAServerWithNoCopyReportsSo(t *testing.T) {
	f := newFixture(t)
	record := f.mustCreate(t, "dns1")

	_, err := store.NewBackups(f.db).Get(context.Background(), record.ID)
	if !errors.Is(err, fleet.ErrNoBackup) {
		t.Fatalf("error = %v, want ErrNoBackup", err)
	}
}

func TestTheStoredFileGoesWithItsServer(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	backups := store.NewBackups(f.db)

	record := f.mustCreate(t, "dns1")
	at := time.Date(2026, 4, 9, 11, 30, 0, 0, time.UTC)
	if err := backups.Save(ctx, record.ID, []byte("first\n"), "one", at); err != nil {
		t.Fatalf("Save returned an error: %v", err)
	}

	if err := f.servers.Delete(ctx, record.ID); err != nil {
		t.Fatalf("cannot delete the server: %v", err)
	}

	if _, err := backups.Get(ctx, record.ID); !errors.Is(err, fleet.ErrNoBackup) {
		t.Errorf("the copy of a deleted server is still readable: %v", err)
	}
}

func TestOnlyTheServersWithACopyAreNamed(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	backups := store.NewBackups(f.db)

	first := f.mustCreate(t, "dns1")
	second := f.mustCreate(t, "dns2")
	at := time.Date(2026, 4, 9, 11, 30, 0, 0, time.UTC)

	if err := backups.Save(ctx, first.ID, []byte("first\n"), "one", at); err != nil {
		t.Fatalf("Save returned an error: %v", err)
	}

	held, err := backups.ServerIDs(ctx)
	if err != nil {
		t.Fatalf("ServerIDs returned an error: %v", err)
	}
	if !held[first.ID] {
		t.Error("the server with a copy is missing")
	}
	if held[second.ID] {
		t.Error("a server with no copy is named")
	}
}
