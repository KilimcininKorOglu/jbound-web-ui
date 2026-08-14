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

func TestRevokingAnAccountLeavesTheCallersOwnSessionAlone(t *testing.T) {
	// The administrator who signs an attacker out of an account must not be
	// signed out by the same click, or they cannot see whether it worked.
	sessions := newSessionStore(t)
	ctx := context.Background()

	mine := sampleSession()
	theirs := sampleSession()
	theirs.ID = "session-id-2"
	other := sampleSession()
	other.ID = "session-id-3"
	other.UID = mine.UID + 1
	other.Username = "someone-else"

	for _, session := range []auth.Session{mine, theirs, other} {
		if err := sessions.Create(ctx, session); err != nil {
			t.Fatalf("Create returned an error: %v", err)
		}
	}

	removed, err := sessions.DeleteByUIDExcept(ctx, mine.UID, mine.ID)
	if err != nil {
		t.Fatalf("DeleteByUIDExcept returned an error: %v", err)
	}
	if removed != 1 {
		t.Errorf("removed = %d, want 1", removed)
	}

	if _, err := sessions.Get(ctx, mine.ID); err != nil {
		t.Errorf("the caller's own session was removed: %v", err)
	}
	if _, err := sessions.Get(ctx, theirs.ID); !errors.Is(err, store.ErrNotFound) {
		t.Error("the other session of the account survived")
	}
	if _, err := sessions.Get(ctx, other.ID); err != nil {
		t.Errorf("a session of another account was removed: %v", err)
	}
}

func TestRevokingEverythingLeavesTheCallersOwnSessionAlone(t *testing.T) {
	sessions := newSessionStore(t)
	ctx := context.Background()

	mine := sampleSession()
	other := sampleSession()
	other.ID = "session-id-2"
	other.UID = mine.UID + 1
	other.Username = "someone-else"

	for _, session := range []auth.Session{mine, other} {
		if err := sessions.Create(ctx, session); err != nil {
			t.Fatalf("Create returned an error: %v", err)
		}
	}

	removed, err := sessions.DeleteAllExcept(ctx, mine.ID)
	if err != nil {
		t.Fatalf("DeleteAllExcept returned an error: %v", err)
	}
	if removed != 1 {
		t.Errorf("removed = %d, want 1", removed)
	}

	if _, err := sessions.Get(ctx, mine.ID); err != nil {
		t.Errorf("the caller's own session was removed: %v", err)
	}
	if _, err := sessions.Get(ctx, other.ID); !errors.Is(err, store.ErrNotFound) {
		t.Error("a session survived the revocation")
	}
}

func TestListLiveGroupsTheSessionsOfOneAccount(t *testing.T) {
	sessions := newSessionStore(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)

	first := sampleSession()
	first.CreatedAt = now.Add(-2 * time.Hour)
	first.LastActive = now.Add(-time.Minute)

	second := sampleSession()
	second.ID = "session-id-2"
	second.CreatedAt = now.Add(-time.Hour)
	second.LastActive = now

	// Past the cutoff below, so it is a row nobody can use any more.
	stale := sampleSession()
	stale.ID = "session-id-3"
	stale.UID = first.UID + 1
	stale.Username = "gone"
	stale.CreatedAt = now.Add(-5 * time.Hour)
	stale.LastActive = now.Add(-4 * time.Hour)

	for _, session := range []auth.Session{first, second, stale} {
		if err := sessions.Create(ctx, session); err != nil {
			t.Fatalf("Create returned an error: %v", err)
		}
	}

	live, err := sessions.ListLive(ctx, now.Add(-30*time.Minute))
	if err != nil {
		t.Fatalf("ListLive returned an error: %v", err)
	}
	if len(live) != 1 {
		t.Fatalf("got %d accounts, want the one with live sessions: %+v", len(live), live)
	}

	summary := live[0]
	if summary.Username != first.Username || summary.Count != 2 {
		t.Errorf("got %+v", summary)
	}
	if !summary.FirstSeen.Equal(first.CreatedAt) {
		t.Errorf("FirstSeen = %v, want the earlier login %v", summary.FirstSeen, first.CreatedAt)
	}
	if !summary.LastActive.Equal(second.LastActive) {
		t.Errorf("LastActive = %v, want the latest activity %v", summary.LastActive, second.LastActive)
	}
}
