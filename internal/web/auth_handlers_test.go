package web

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"unbound-web/internal/audit"
	"unbound-web/internal/auth"
	"unbound-web/internal/config"
	"unbound-web/internal/database"
	"unbound-web/internal/fleet"
	"unbound-web/internal/server"
	"unbound-web/internal/siem"
	"unbound-web/internal/store"
	"unbound-web/internal/transport"
)

const (
	browserAgent  = "Mozilla/5.0 (test)"
	clientAddress = "192.0.2.1:1234"
)

// stubAuthenticator stands in for the setuid helper. The helper itself is
// covered by the auth package tests and by the Docker integration gate.
type stubAuthenticator struct {
	accounts map[string]auth.Account
}

func (s *stubAuthenticator) Authenticate(_ context.Context,
	username, password string) (auth.Account, error) {

	account, ok := s.accounts[username]
	if !ok || password != "correct-horse" {
		return auth.Account{}, auth.ErrBadPassword
	}
	return account, nil
}

type testEnv struct {
	app       *App
	db        *sql.DB
	sessions  *store.Sessions
	servers   *server.Service
	serverDB  *store.Servers
	records   *fleet.Service
	connector *stubConnector
	recordDB  *store.Records
	stateDB   *store.States
	dataDir   string
	keyDir    string
	// transport lets a test choose what a managed server answers.
	transport *stubTransport
	// forwarder holds what was sent to the SIEM.
	forwarder *recordingForwarder
	siemDir   string
	// queries lets a test choose what a resolver replies to a name query.
	queries *stubQuerier
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	ctx := context.Background()

	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatalf("cannot open the test database: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	authenticator := &stubAuthenticator{accounts: map[string]auth.Account{
		"dnsadmin": {UID: 1001, GID: 1001, Username: "dnsadmin",
			Shell: "/bin/bash", Groups: []string{"dnsadmin", "sudo"}},
		"dnsuser": {UID: 1002, GID: 1002, Username: "dnsuser",
			Shell: "/bin/bash", Groups: []string{"dnsuser"}},
	}}

	cfg := &config.Config{
		SessionTimeout: 30 * time.Minute,
		CookieSecure:   false,
		MinUID:         1000,
		AdminGroup:     "sudo",
	}
	sessions := store.NewSessions(db.DB)
	forwarder := &recordingForwarder{}
	auditLog := audit.NewLogger(store.NewAuditLogs(db.DB), forwarder)

	dataDir := t.TempDir()
	keys, err := server.NewKeyStore(dataDir)
	if err != nil {
		t.Fatalf("cannot create the key store: %v", err)
	}

	// The first server keeps the shared transport, so a test can set what it
	// answers without looking the server up. The rest get their own file.
	remote := &stubTransport{}
	connector := &stubConnector{
		transport: remote,
		byID:      map[int64]*stubTransport{1: remote},
	}
	timeouts := server.Timeouts{Connect: time.Second, Command: time.Second}

	serverStore := store.NewServers(db.DB)
	servers := server.NewService(
		serverStore, store.NewGroups(db.DB), keys, connector, auditLog, dataDir, timeouts)

	recordStore := store.NewRecords(db.DB)
	stateStore := store.NewStates(db.DB)
	refresher := fleet.NewRefresher(serverStore, recordStore, stateStore,
		connector, dataDir, timeouts, 2)
	writer := fleet.NewWriter(serverStore, servers, connector, refresher,
		auditLog, dataDir, timeouts, 2)
	queries := &stubQuerier{answers: map[string][]string{}}
	records := fleet.NewService(recordStore, stateStore, writer, refresher,
		queries, auditLog, 15*time.Minute)

	siemDir := t.TempDir()
	rsyslog := siem.NewManager(
		filepath.Join(siemDir, "60-panel.conf"), filepath.Join(siemDir, "panel.log"),
		[]string{"true"}, []string{"true"}, []string{"true"})

	app, err := NewApp(Deps{
		Config: cfg,
		Auth: auth.NewService(authenticator, auth.Policy{
			MinUID: cfg.MinUID, AdminGroup: cfg.AdminGroup,
		}),
		Sessions: auth.NewSessionManager(sessions, cfg.SessionTimeout, cfg.CookieSecure),
		Limiter: auth.NewRateLimiter(store.NewLoginAttempts(db.DB),
			auth.DefaultRateWindow, auth.DefaultRateMaxTries),
		Audit:     auditLog,
		Servers:   servers,
		Records:   records,
		SIEM:      rsyslog,
		Forwarder: forwarder,
	})
	if err != nil {
		t.Fatalf("cannot build the application: %v", err)
	}

	return &testEnv{
		app:       app,
		db:        db.DB,
		sessions:  sessions,
		servers:   servers,
		serverDB:  serverStore,
		records:   records,
		connector: connector,
		recordDB:  recordStore,
		stateDB:   stateStore,
		dataDir:   dataDir,
		keyDir:    keys.Dir(),
		transport: remote,
		queries:   queries,
		forwarder: forwarder,
		siemDir:   siemDir,
	}
}

// recordingForwarder keeps what the panel sent to the SIEM.
type recordingForwarder struct {
	mu      sync.Mutex
	entries []audit.Entry
	err     error
}

func (f *recordingForwarder) Forward(entry audit.Entry) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.err != nil {
		return f.err
	}
	f.entries = append(f.entries, entry)
	return nil
}

func (f *recordingForwarder) sent() []audit.Entry {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]audit.Entry(nil), f.entries...)
}

// stubQuerier answers a name query, so the record page can be covered without
// a dns client on the host running the tests.
type stubQuerier struct {
	mu      sync.Mutex
	answers map[string][]string
	err     error
	asked   []string
}

func (s *stubQuerier) Ask(_ context.Context, host, domain, recordType string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.asked = append(s.asked, strings.TrimSpace(host+" "+domain+" "+recordType))
	if s.err != nil {
		return nil, s.err
	}
	return s.answers[host], nil
}

// answer sets what one server replies.
func (s *stubQuerier) answer(host string, records ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.answers[host] = records
}

// questions returns what was asked, in the order the queries were made.
func (s *stubQuerier) questions() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.asked...)
}

// stubTransport stands in for a managed server. The transport itself is
// covered by its own integration tests against the development targets.
type stubTransport struct {
	mu       sync.Mutex
	probeErr error

	// content is the host entries file this server holds, so a record change
	// can be checked the way an operator would check it.
	content  []byte
	readErr  error
	writeErr error

	// reloads counts how often the resolver was asked to re-read its files,
	// which is what Apply Rules is checked against.
	reloads   int
	reloadErr error
}

func (s *stubTransport) ReadHostEntries(context.Context) ([]byte, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.readErr != nil {
		return nil, "", s.readErr
	}
	return append([]byte(nil), s.content...), digestOf(s.content), nil
}

func (s *stubTransport) WriteHostEntries(_ context.Context, data []byte, expect string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.writeErr != nil {
		return s.writeErr
	}
	if expect != digestOf(s.content) {
		return transport.ErrConflict
	}
	s.content = append([]byte(nil), data...)
	return nil
}

func (s *stubTransport) file() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return string(s.content)
}

func (s *stubTransport) setFile(content string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.content = []byte(content)
}

func (s *stubTransport) Reload(context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.reloads++
	if s.reloadErr != nil {
		return "", s.reloadErr
	}
	return "", nil
}

func (s *stubTransport) reloadCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reloads
}

func (s *stubTransport) failReload(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reloadErr = err
}

func (s *stubTransport) ServiceStatus(context.Context) (bool, string, error) { return true, "", nil }
func (s *stubTransport) Probe(context.Context) error                         { return s.probeErr }
func (s *stubTransport) Close() error                                        { return nil }

// digestOf is the digest the optimistic write is checked against.
func digestOf(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// stubConnector hands out one transport per server, so a fleet operation can
// be checked server by server.
type stubConnector struct {
	mu        sync.Mutex
	transport *stubTransport
	byID      map[int64]*stubTransport
}

func (s *stubConnector) Get(cfg transport.Config) (transport.Transport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if cfg.ID == 0 {
		return s.transport, nil
	}
	if s.byID == nil {
		s.byID = map[int64]*stubTransport{}
	}
	client, ok := s.byID[cfg.ID]
	if !ok {
		client = &stubTransport{}
		s.byID[cfg.ID] = client
	}
	return client, nil
}

func (s *stubConnector) Remove(int64) {}

// do serves one request and returns the recorder.
// target returns the transport of one server, creating it the way the
// connector would.
func (e *testEnv) target(id int64) *stubTransport {
	client, _ := e.connector.Get(transport.Config{ID: id})
	return client.(*stubTransport)
}

func (e *testEnv) do(t *testing.T, r *http.Request, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	r.Header.Set("User-Agent", browserAgent)
	r.RemoteAddr = clientAddress
	for _, cookie := range cookies {
		r.AddCookie(cookie)
	}

	recorder := httptest.NewRecorder()
	e.app.Router().ServeHTTP(recorder, r)
	return recorder
}

func postForm(target, body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

// login signs a user in and returns the session cookie.
func (e *testEnv) login(t *testing.T, username string) *http.Cookie {
	t.Helper()

	recorder := e.do(t, postForm("/login", "username="+username+"&password=correct-horse"))
	if recorder.Code != http.StatusOK {
		t.Fatalf("login as %s returned %d, want 200", username, recorder.Code)
	}
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == auth.SessionCookieName && cookie.Value != "" {
			return cookie
		}
	}
	t.Fatalf("login as %s set no session cookie", username)
	return nil
}

// csrfTokenOf reads the token the panel issued for a session.
func (e *testEnv) csrfTokenOf(t *testing.T, cookie *http.Cookie) string {
	t.Helper()
	session, err := e.sessions.Get(context.Background(), cookie.Value)
	if err != nil {
		t.Fatalf("cannot read the session: %v", err)
	}
	return session.CSRFToken
}

func TestLoginRejectsMissingFields(t *testing.T) {
	env := newTestEnv(t)

	cases := map[string]string{
		"no username": "username=&password=correct-horse",
		"no password": "username=dnsadmin&password=",
		"neither":     "username=&password=",
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			recorder := env.do(t, postForm("/login", body))
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", recorder.Code)
			}
			if !strings.Contains(recorder.Body.String(), "Please fill in all fields.") {
				t.Error("the response does not carry the missing field message")
			}
		})
	}
}

func TestLoginRejectsAWrongPassword(t *testing.T) {
	env := newTestEnv(t)

	recorder := env.do(t, postForm("/login", "username=dnsadmin&password=wrong"))

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", recorder.Code)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "Invalid username or password.") {
		t.Error("the response does not carry the generic failure message")
	}
	// The message must not reveal which half was wrong.
	if strings.Contains(body, "password is") || strings.Contains(body, "no such user") {
		t.Error("the response distinguishes a bad password from an unknown account")
	}
}

func TestLoginSucceedsAndRecordsAnAuditRow(t *testing.T) {
	env := newTestEnv(t)

	recorder := env.do(t, postForm("/login", "username=dnsadmin&password=correct-horse"))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if got := recorder.Header().Get("HX-Redirect"); got != "/dns" {
		t.Errorf("HX-Redirect = %q, want /dns", got)
	}
	if !strings.Contains(recorder.Body.String(), "admin") {
		t.Error("the response does not report the role")
	}

	var count int
	err := env.db.QueryRow(
		"SELECT COUNT(*) FROM audit_logs WHERE action = ? AND username = ?",
		audit.ActionLogin, "dnsadmin").Scan(&count)
	if err != nil {
		t.Fatalf("cannot read the audit table: %v", err)
	}
	if count != 1 {
		t.Errorf("%d audit rows, want 1", count)
	}
}

func TestAFailedLoginIsAudited(t *testing.T) {
	// A failed login is what a break-in attempt looks like from here, so it is
	// recorded and forwarded like any other event.
	env := newTestEnv(t)

	env.do(t, postForm("/login", "username=dnsadmin&password=wrong"))

	var action, username, ip, details string
	row := env.db.QueryRow(
		"SELECT action, username, ip_address, details FROM audit_logs ORDER BY id DESC LIMIT 1")
	if err := row.Scan(&action, &username, &ip, &details); err != nil {
		t.Fatalf("cannot read the audit table: %v", err)
	}

	if action != "login_failed" || username != "dnsadmin" || ip != "192.0.2.1" {
		t.Errorf("got %s by %s from %s", action, username, ip)
	}
	if strings.Contains(details, "wrong") {
		t.Errorf("the submitted password reached the audit trail: %q", details)
	}
}

func TestLoginRefusesTheEleventhAttempt(t *testing.T) {
	env := newTestEnv(t)

	for i := 1; i <= auth.DefaultRateMaxTries; i++ {
		recorder := env.do(t, postForm("/login", "username=dnsadmin&password=wrong"))
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d returned %d, want 401", i, recorder.Code)
		}
	}

	recorder := env.do(t, postForm("/login", "username=dnsadmin&password=wrong"))
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt %d returned %d, want 429",
			auth.DefaultRateMaxTries+1, recorder.Code)
	}

	// The correct password must not slip past the limit either.
	recorder = env.do(t, postForm("/login", "username=dnsadmin&password=correct-horse"))
	if recorder.Code != http.StatusTooManyRequests {
		t.Errorf("a correct password returned %d while limited, want 429", recorder.Code)
	}
}

func TestProtectedRoutesRedirectWithoutASession(t *testing.T) {
	env := newTestEnv(t)

	recorder := env.do(t, httptest.NewRequest(http.MethodGet, "/dns", nil))

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", recorder.Code)
	}
	if got := recorder.Header().Get("Location"); got != "/" {
		t.Errorf("Location = %q, want /", got)
	}
}

func TestExpiredSessionRedirectsToTheTimeoutPage(t *testing.T) {
	env := newTestEnv(t)

	// The row is written directly with an old timestamp. Waiting out a real
	// thirty minute timeout would be the only alternative.
	probe := httptest.NewRequest(http.MethodGet, "/dns", nil)
	probe.Header.Set("User-Agent", browserAgent)
	probe.RemoteAddr = clientAddress

	stale := time.Now().UTC().Add(-31 * time.Minute)
	session := auth.Session{
		ID: "expired-session-id", UID: 1001, Username: "dnsadmin", Role: auth.RoleAdmin,
		Fingerprint: auth.Fingerprint(probe), CSRFToken: "token",
		LastActive: stale, RegeneratedAt: stale, CreatedAt: stale,
	}
	if err := env.sessions.Create(context.Background(), session); err != nil {
		t.Fatalf("cannot create the stale session: %v", err)
	}

	recorder := env.do(t, httptest.NewRequest(http.MethodGet, "/dns", nil),
		&http.Cookie{Name: auth.SessionCookieName, Value: session.ID})

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", recorder.Code)
	}
	if got := recorder.Header().Get("Location"); got != "/?timeout=1" {
		t.Errorf("Location = %q, want /?timeout=1", got)
	}

	if _, err := env.sessions.Get(context.Background(), session.ID); err == nil {
		t.Error("the expired session row survived")
	}
}

func TestSessionDropsWhenTheUserAgentChanges(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")

	r := httptest.NewRequest(http.MethodGet, "/dns", nil)
	r.AddCookie(cookie)
	r.Header.Set("User-Agent", "curl/8.0 (stolen cookie)")
	r.RemoteAddr = clientAddress

	recorder := httptest.NewRecorder()
	env.app.Router().ServeHTTP(recorder, r)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", recorder.Code)
	}
	if got := recorder.Header().Get("Location"); got != "/" {
		t.Errorf("Location = %q, want /", got)
	}
}

func TestLogoutNeedsACSRFToken(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")

	recorder := env.do(t, postForm("/logout", ""), cookie)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", recorder.Code)
	}

	recorder = env.do(t, postForm("/logout", "csrf_token=not-the-right-token"), cookie)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("a wrong token returned %d, want 403", recorder.Code)
	}

	token := env.csrfTokenOf(t, cookie)
	recorder = env.do(t, postForm("/logout", "csrf_token="+token), cookie)
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", recorder.Code)
	}

	// The session must be gone, otherwise the cookie still works after logout.
	recorder = env.do(t, httptest.NewRequest(http.MethodGet, "/dns", nil), cookie)
	if got := recorder.Header().Get("Location"); got != "/" {
		t.Errorf("the session survived the logout, Location = %q", got)
	}
}

func TestCSRFTokenAlsoArrivesInTheHeader(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")
	token := env.csrfTokenOf(t, cookie)

	r := postForm("/logout", "")
	r.Header.Set(auth.CSRFHeader, token)

	if recorder := env.do(t, r, cookie); recorder.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", recorder.Code)
	}
}

func TestCrossOriginPostIsRefused(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")
	token := env.csrfTokenOf(t, cookie)

	r := postForm("/logout", "csrf_token="+token)
	r.Header.Set("Origin", "https://attacker.example")

	if recorder := env.do(t, r, cookie); recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", recorder.Code)
	}
}

func TestAdminRoutesRefuseAPlainUser(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.login(t, "dnsuser")

	for _, path := range []string{"/servers", "/siem"} {
		t.Run(path, func(t *testing.T) {
			recorder := env.do(t, httptest.NewRequest(http.MethodGet, path, nil), cookie)
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", recorder.Code)
			}
		})
	}
}

func TestAdminRoutesAcceptAnAdmin(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")

	for _, path := range []string{"/servers", "/siem"} {
		t.Run(path, func(t *testing.T) {
			recorder := env.do(t, httptest.NewRequest(http.MethodGet, path, nil), cookie)
			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", recorder.Code)
			}
		})
	}
}

func TestLoginPageSendsALiveSessionToTheRecordsPage(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.login(t, "dnsuser")

	recorder := env.do(t, httptest.NewRequest(http.MethodGet, "/", nil), cookie)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", recorder.Code)
	}
	if got := recorder.Header().Get("Location"); got != "/dns" {
		t.Errorf("Location = %q, want /dns", got)
	}
}

func TestLoginPageShowsTheTimeoutNotice(t *testing.T) {
	env := newTestEnv(t)

	recorder := env.do(t, httptest.NewRequest(http.MethodGet, "/?timeout=1", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "session has expired") {
		t.Error("the login page does not explain the timeout")
	}
}

func TestHtmxRequestsGetTheRedirectHeader(t *testing.T) {
	// A 303 inside an htmx swap would paint the login page into the current
	// layout instead of navigating to it.
	env := newTestEnv(t)

	r := httptest.NewRequest(http.MethodGet, "/dns", nil)
	r.Header.Set("HX-Request", "true")

	recorder := env.do(t, r)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", recorder.Code)
	}
	if got := recorder.Header().Get("HX-Redirect"); got != "/" {
		t.Errorf("HX-Redirect = %q, want /", got)
	}
}

func TestEveryResponseCarriesTheSecurityHeaders(t *testing.T) {
	env := newTestEnv(t)

	recorder := env.do(t, httptest.NewRequest(http.MethodGet, "/", nil))

	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "same-origin",
	}
	for header, value := range want {
		if got := recorder.Header().Get(header); got != value {
			t.Errorf("%s = %q, want %q", header, got, value)
		}
	}
	if !strings.Contains(recorder.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Error("the content security policy allows framing")
	}
}
