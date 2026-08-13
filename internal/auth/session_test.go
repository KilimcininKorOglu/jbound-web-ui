package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"unbound-web/internal/settings"
)

// fakeSessionRepo keeps sessions in memory so the timing rules can be tested
// without a database.
type fakeSessionRepo struct {
	sessions  map[string]Session
	createErr error
}

func newFakeSessionRepo() *fakeSessionRepo {
	return &fakeSessionRepo{sessions: map[string]Session{}}
}

func (f *fakeSessionRepo) Create(_ context.Context, session Session) error {
	if f.createErr != nil {
		return f.createErr
	}
	f.sessions[session.ID] = session
	return nil
}

func (f *fakeSessionRepo) Get(_ context.Context, id string) (Session, error) {
	session, ok := f.sessions[id]
	if !ok {
		return Session{}, errors.New("not found")
	}
	return session, nil
}

func (f *fakeSessionRepo) Touch(_ context.Context, id string, at time.Time) error {
	session, ok := f.sessions[id]
	if !ok {
		return errors.New("not found")
	}
	session.LastActive = at
	f.sessions[id] = session
	return nil
}

func (f *fakeSessionRepo) Rotate(_ context.Context, oldID, newID string, at time.Time) error {
	session, ok := f.sessions[oldID]
	if !ok {
		return errors.New("not found")
	}
	delete(f.sessions, oldID)
	session.ID = newID
	session.RegeneratedAt = at
	session.LastActive = at
	f.sessions[newID] = session
	return nil
}

func (f *fakeSessionRepo) Delete(_ context.Context, id string) error {
	delete(f.sessions, id)
	return nil
}

const testUserAgent = "Mozilla/5.0 (test)"

func testUser() User {
	return User{
		Account: Account{UID: 1001, GID: 1001, Username: "dnsadmin", Shell: "/bin/bash"},
		Role:    RoleAdmin,
	}
}

func testRequest(userAgent, remoteAddr string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r.Header.Set("User-Agent", userAgent)
	r.RemoteAddr = remoteAddr
	return r
}

// startSession logs a user in and returns the manager, the session and a
// request that carries its cookie.
func startSession(t *testing.T, manager *SessionManager) (Session, *http.Cookie) {
	t.Helper()

	recorder := httptest.NewRecorder()
	session, err := manager.Start(context.Background(), recorder,
		testRequest(testUserAgent, "203.0.113.5:44321"), testUser())
	if err != nil {
		t.Fatalf("Start returned an error: %v", err)
	}

	cookie := findCookie(t, recorder.Result().Cookies(), SessionCookieName)
	return session, cookie
}

func findCookie(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("the response carries no %s cookie", name)
	return nil
}

func TestStartCreatesASessionAndSetsAHardenedCookie(t *testing.T) {
	repo := newFakeSessionRepo()
	manager := NewSessionManager(repo, settings.Fixed(30*time.Minute), true)

	session, cookie := startSession(t, manager)

	if _, ok := repo.sessions[session.ID]; !ok {
		t.Fatal("the session was not stored")
	}
	if session.CSRFToken == "" {
		t.Error("the session carries no CSRF token")
	}
	if session.ID == session.CSRFToken {
		t.Error("the session identifier and the CSRF token are the same value")
	}
	if !cookie.HttpOnly {
		t.Error("the cookie is readable from JavaScript")
	}
	if !cookie.Secure {
		t.Error("the cookie is not marked Secure")
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("SameSite = %v, want Strict", cookie.SameSite)
	}
	// A session that survives the browser would outlive the person at the
	// keyboard.
	if cookie.MaxAge != 0 || !cookie.Expires.IsZero() {
		t.Error("the cookie is persistent, it must last for the browser session only")
	}
}

func TestLoadReturnsTheSessionAndRecordsActivity(t *testing.T) {
	repo := newFakeSessionRepo()
	manager := NewSessionManager(repo, settings.Fixed(30*time.Minute), false)
	session, cookie := startSession(t, manager)

	later := session.LastActive.Add(time.Minute)
	manager.now = func() time.Time { return later }

	r := testRequest(testUserAgent, "203.0.113.5:55000")
	r.AddCookie(cookie)
	recorder := httptest.NewRecorder()

	loaded, err := manager.Load(context.Background(), recorder, r)
	if err != nil {
		t.Fatalf("Load returned an error: %v", err)
	}
	if loaded.Username != "dnsadmin" || loaded.Role != RoleAdmin {
		t.Errorf("got %+v, want dnsadmin as admin", loaded)
	}
	if !repo.sessions[session.ID].LastActive.Equal(later) {
		t.Error("last_active was not updated")
	}
}

func TestLoadRejectsAMissingOrUnknownSession(t *testing.T) {
	repo := newFakeSessionRepo()
	manager := NewSessionManager(repo, settings.Fixed(30*time.Minute), false)

	t.Run("no cookie", func(t *testing.T) {
		_, err := manager.Load(context.Background(), httptest.NewRecorder(),
			testRequest(testUserAgent, "203.0.113.5:1000"))
		if !errors.Is(err, ErrNoSession) {
			t.Fatalf("got %v, want ErrNoSession", err)
		}
	})

	t.Run("unknown identifier", func(t *testing.T) {
		r := testRequest(testUserAgent, "203.0.113.5:1000")
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "does-not-exist"})

		_, err := manager.Load(context.Background(), httptest.NewRecorder(), r)
		if !errors.Is(err, ErrNoSession) {
			t.Fatalf("got %v, want ErrNoSession", err)
		}
	})
}

func TestLoadExpiresAnIdleSession(t *testing.T) {
	repo := newFakeSessionRepo()
	manager := NewSessionManager(repo, settings.Fixed(30*time.Minute), false)
	session, cookie := startSession(t, manager)

	manager.now = func() time.Time { return session.LastActive.Add(31 * time.Minute) }

	r := testRequest(testUserAgent, "203.0.113.5:1000")
	r.AddCookie(cookie)

	_, err := manager.Load(context.Background(), httptest.NewRecorder(), r)
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("got %v, want ErrSessionExpired", err)
	}
	if _, ok := repo.sessions[session.ID]; ok {
		t.Error("the expired session is still stored")
	}
}

func TestLoadDropsTheSessionWhenTheUserAgentChanges(t *testing.T) {
	repo := newFakeSessionRepo()
	manager := NewSessionManager(repo, settings.Fixed(30*time.Minute), false)
	session, cookie := startSession(t, manager)

	r := testRequest("curl/8.0 (stolen cookie)", "203.0.113.5:1000")
	r.AddCookie(cookie)

	_, err := manager.Load(context.Background(), httptest.NewRecorder(), r)
	if !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatalf("got %v, want ErrFingerprintMismatch", err)
	}
	if _, ok := repo.sessions[session.ID]; ok {
		t.Error("the session survived a fingerprint mismatch")
	}
}

func TestLoadDropsTheSessionWhenTheAddressChanges(t *testing.T) {
	repo := newFakeSessionRepo()
	manager := NewSessionManager(repo, settings.Fixed(30*time.Minute), false)
	_, cookie := startSession(t, manager)

	r := testRequest(testUserAgent, "198.51.100.9:1000")
	r.AddCookie(cookie)

	_, err := manager.Load(context.Background(), httptest.NewRecorder(), r)
	if !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatalf("got %v, want ErrFingerprintMismatch", err)
	}
}

func TestLoadRotatesTheIdentifierAfterFiveMinutes(t *testing.T) {
	repo := newFakeSessionRepo()
	manager := NewSessionManager(repo, settings.Fixed(30*time.Minute), false)
	session, cookie := startSession(t, manager)

	manager.now = func() time.Time { return session.RegeneratedAt.Add(rotateInterval) }

	r := testRequest(testUserAgent, "203.0.113.5:1000")
	r.AddCookie(cookie)
	recorder := httptest.NewRecorder()

	rotated, err := manager.Load(context.Background(), recorder, r)
	if err != nil {
		t.Fatalf("Load returned an error: %v", err)
	}
	if rotated.ID == session.ID {
		t.Fatal("the identifier was not rotated")
	}
	if _, ok := repo.sessions[session.ID]; ok {
		t.Error("the old identifier still resolves to a session")
	}
	newCookie := findCookie(t, recorder.Result().Cookies(), SessionCookieName)
	if newCookie.Value != rotated.ID {
		t.Error("the cookie still carries the old identifier")
	}
	// The user data must survive the rotation, otherwise every rotation would
	// look like a logout.
	if rotated.Username != session.Username || rotated.CSRFToken != session.CSRFToken {
		t.Error("the rotation lost the session contents")
	}
}

func TestDestroyRemovesTheSession(t *testing.T) {
	repo := newFakeSessionRepo()
	manager := NewSessionManager(repo, settings.Fixed(30*time.Minute), false)
	session, cookie := startSession(t, manager)

	r := testRequest(testUserAgent, "203.0.113.5:1000")
	r.AddCookie(cookie)
	recorder := httptest.NewRecorder()

	if err := manager.Destroy(context.Background(), recorder, r); err != nil {
		t.Fatalf("Destroy returned an error: %v", err)
	}
	if _, ok := repo.sessions[session.ID]; ok {
		t.Error("the session was not removed")
	}
	cleared := findCookie(t, recorder.Result().Cookies(), SessionCookieName)
	if cleared.MaxAge >= 0 {
		t.Errorf("MaxAge = %d, want a negative value that clears the cookie", cleared.MaxAge)
	}
}

func TestFingerprintIgnoresTheSourcePort(t *testing.T) {
	// A browser opens several connections, each from a different port. Binding
	// to the port would end the session on the second request.
	first := Fingerprint(testRequest(testUserAgent, "203.0.113.5:1000"))
	second := Fingerprint(testRequest(testUserAgent, "203.0.113.5:2000"))

	if first != second {
		t.Error("the fingerprint changes with the source port")
	}
}

func TestClientIPIgnoresForwardingHeaders(t *testing.T) {
	// Trusting the header would let anyone reset the login rate limit and
	// forge the address half of the fingerprint.
	r := testRequest(testUserAgent, "203.0.113.5:1000")
	r.Header.Set("X-Forwarded-For", "10.0.0.1")

	if got := ClientIP(r); got != "203.0.113.5" {
		t.Errorf("ClientIP = %q, want 203.0.113.5", got)
	}
}
