package store_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"unbound-web/internal/auth"
	"unbound-web/internal/database"
	"unbound-web/internal/store"
)

func newSessionStore(t *testing.T) *store.Sessions {
	t.Helper()

	db, err := database.Open(context.Background(), filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatalf("cannot open the test database: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	return store.NewSessions(db.DB)
}

func sampleSession() auth.Session {
	// Whole seconds, because that is the resolution the schema stores. A value
	// with nanoseconds would fail the round trip for the wrong reason.
	now := time.Date(2026, 8, 13, 12, 30, 0, 0, time.UTC)
	return auth.Session{
		ID:            "session-id-1",
		UID:           1001,
		Username:      "dnsadmin",
		Role:          auth.RoleAdmin,
		Fingerprint:   "fingerprint-1",
		CSRFToken:     "csrf-1",
		LastActive:    now,
		RegeneratedAt: now,
		CreatedAt:     now,
	}
}

func TestSessionRoundTrip(t *testing.T) {
	sessions := newSessionStore(t)
	ctx := context.Background()
	want := sampleSession()

	if err := sessions.Create(ctx, want); err != nil {
		t.Fatalf("Create returned an error: %v", err)
	}

	got, err := sessions.Get(ctx, want.ID)
	if err != nil {
		t.Fatalf("Get returned an error: %v", err)
	}
	if got.Username != want.Username || got.Role != want.Role ||
		got.UID != want.UID || got.CSRFToken != want.CSRFToken ||
		got.Fingerprint != want.Fingerprint {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if !got.LastActive.Equal(want.LastActive) {
		t.Errorf("last_active = %s, want %s", got.LastActive, want.LastActive)
	}
	if got.LastActive.Location() != time.UTC {
		t.Errorf("last_active came back in %s, want UTC", got.LastActive.Location())
	}
}

func TestGetReportsAMissingSession(t *testing.T) {
	sessions := newSessionStore(t)

	_, err := sessions.Get(context.Background(), "no-such-session")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestTouchUpdatesActivity(t *testing.T) {
	sessions := newSessionStore(t)
	ctx := context.Background()
	session := sampleSession()

	if err := sessions.Create(ctx, session); err != nil {
		t.Fatalf("Create returned an error: %v", err)
	}

	later := session.LastActive.Add(90 * time.Second)
	if err := sessions.Touch(ctx, session.ID, later); err != nil {
		t.Fatalf("Touch returned an error: %v", err)
	}

	got, err := sessions.Get(ctx, session.ID)
	if err != nil {
		t.Fatalf("Get returned an error: %v", err)
	}
	if !got.LastActive.Equal(later) {
		t.Errorf("last_active = %s, want %s", got.LastActive, later)
	}
}

func TestRotateKeepsTheSessionContents(t *testing.T) {
	sessions := newSessionStore(t)
	ctx := context.Background()
	session := sampleSession()

	if err := sessions.Create(ctx, session); err != nil {
		t.Fatalf("Create returned an error: %v", err)
	}

	at := session.RegeneratedAt.Add(5 * time.Minute)
	if err := sessions.Rotate(ctx, session.ID, "session-id-2", at); err != nil {
		t.Fatalf("Rotate returned an error: %v", err)
	}

	if _, err := sessions.Get(ctx, session.ID); !errors.Is(err, store.ErrNotFound) {
		t.Error("the old identifier still resolves")
	}

	got, err := sessions.Get(ctx, "session-id-2")
	if err != nil {
		t.Fatalf("Get returned an error: %v", err)
	}
	if got.Username != session.Username || got.CSRFToken != session.CSRFToken {
		t.Error("the rotation lost the session contents")
	}
	if !got.RegeneratedAt.Equal(at) {
		t.Errorf("regenerated_at = %s, want %s", got.RegeneratedAt, at)
	}
}

func TestTouchAndRotateReportAMissingRow(t *testing.T) {
	// A no op update means the row vanished between the read and the write.
	// Reporting success would hand the caller a session that no longer exists.
	sessions := newSessionStore(t)
	ctx := context.Background()

	if err := sessions.Touch(ctx, "no-such-session", time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Touch returned %v, want ErrNotFound", err)
	}
	if err := sessions.Rotate(ctx, "no-such-session", "new-id", time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Rotate returned %v, want ErrNotFound", err)
	}
}

func TestDeleteByUIDRemovesEverySessionOfAnAccount(t *testing.T) {
	sessions := newSessionStore(t)
	ctx := context.Background()

	first := sampleSession()
	second := sampleSession()
	second.ID = "session-id-2"

	for _, session := range []auth.Session{first, second} {
		if err := sessions.Create(ctx, session); err != nil {
			t.Fatalf("Create returned an error: %v", err)
		}
	}

	if err := sessions.DeleteByUID(ctx, first.UID); err != nil {
		t.Fatalf("DeleteByUID returned an error: %v", err)
	}
	for _, id := range []string{first.ID, second.ID} {
		if _, err := sessions.Get(ctx, id); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("session %s survived", id)
		}
	}
}
