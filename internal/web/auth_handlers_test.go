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
	"unbound-web/internal/settings"
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
	// settingsStore is the same store the application reads, so a test can
	// build a second service over it and see what a restart would.
	settingsStore *store.Settings
	// settingsCookie caches the administrator session of the settings tests.
	settingsCookie *http.Cookie
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	ctx := context.Background()

	dbPath := filepath.Join(t.TempDir(), "panel.db")
	db, err := database.Open(ctx, dbPath)
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
		CookieSecure: false,
		MinUID:       1000,
		AdminGroup:   "sudo",
		DBPath:       dbPath,
	}

	// The panel reads its timing and its limits through this service, so the
	// harness builds the real one over the test database rather than faking it.
	settingsStore := store.NewSettings(db.DB)
	options := settings.NewService(settingsStore)
	if err := options.Load(context.Background()); err != nil {
		t.Fatalf("cannot load the settings: %v", err)
	}

	sessions := store.NewSessions(db.DB)
	forwarder := &recordingForwarder{}
	auditLog := audit.NewLogger(store.NewAuditLogs(db.DB), forwarder).
		WithForwarding(options.BoolOf(settings.SIEMForwardingEnabled))

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
	timeouts := settings.Fixed(server.Timeouts{Connect: time.Second, Command: time.Second})

	serverStore := store.NewServers(db.DB)
	servers := server.NewService(
		serverStore, store.NewGroups(db.DB), keys, connector, auditLog, dataDir, timeouts)

	recordStore := store.NewRecords(db.DB)
	stateStore := store.NewStates(db.DB)
	refresher := fleet.NewRefresher(serverStore, recordStore, stateStore,
		connector, dataDir, timeouts, settings.Fixed(2))
	writer := fleet.NewWriter(serverStore, servers, connector, refresher,
		auditLog, dataDir, timeouts, settings.Fixed(2))
	queries := &stubQuerier{answers: map[string][]string{}}
	records := fleet.NewService(recordStore, stateStore, writer, refresher,
		queries, auditLog, settings.Fixed(15*time.Minute),
		options.IntOf(settings.RecordsPerPage))

	siemDir := t.TempDir()
	rsyslog := siem.NewManager(
		filepath.Join(siemDir, "60-panel.conf"), filepath.Join(siemDir, "panel.log"),
		[]string{"true"}, []string{"true"}, []string{"true"})

	app, err := NewApp(Deps{
		Config: cfg,
		Auth: auth.NewService(authenticator, auth.Policy{
			MinUID: cfg.MinUID, AdminGroup: cfg.AdminGroup,
		}),
		Settings: options,
		Sessions: auth.NewSessionManager(sessions,
			options.DurationOf(settings.SessionIdleTimeout),
			options.DurationOf(settings.SessionLifetime), cfg.CookieSecure),
		Limiter: auth.NewRateLimiter(store.NewLoginAttempts(db.DB),
			options.DurationOf(settings.LoginRateWindow),
			options.IntOf(settings.LoginRateMaxAttempts)),
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

		settingsStore: settingsStore,
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

	// delay is how long every operation on this server takes. A real machine
	// that answers slowly is the only way to reach the deadline of a fleet
	// operation, and this stands in for one.
	delay time.Duration

	// deadlineSeen says whether the last operation arrived with a deadline,
	// which is how a route that has to carry one is checked.
	deadlineSeen bool

	// afterWrite runs once the file has been replaced. It stands in for
	// everything that can happen to the request after the panel has already
	// changed a production resolver.
	afterWrite func()
}

func (s *stubTransport) ReadHostEntries(ctx context.Context) ([]byte, string, error) {
	if err := s.wait(ctx); err != nil {
		return nil, "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.readErr != nil {
		return nil, "", s.readErr
	}
	return append([]byte(nil), s.content...), digestOf(s.content), nil
}

func (s *stubTransport) WriteHostEntries(ctx context.Context, data []byte, expect string) error {
	if err := s.wait(ctx); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.writeErr != nil {
		return s.writeErr
	}
	if expect != digestOf(s.content) {
		return transport.ErrConflict
	}
	s.content = append([]byte(nil), data...)

	if s.afterWrite != nil {
		s.afterWrite()
	}
	return nil
}

func (s *stubTransport) file() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return string(s.content)
}

// failReads makes this server answer every read with a failure, which is what
// a machine that is off looks like from the panel.
func (s *stubTransport) failReads(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.readErr = err
}

func (s *stubTransport) setFile(content string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.content = []byte(content)
}

// hadDeadline reports whether the last operation carried one.
func (s *stubTransport) hadDeadline() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deadlineSeen
}

// onWrite runs the given function right after the file is replaced.
func (s *stubTransport) onWrite(after func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.afterWrite = after
}

// slowDown makes every operation on this server take the given time.
func (s *stubTransport) slowDown(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.delay = d
}

// wait holds the caller for the configured delay, or until the operation ends,
// whichever comes first. It reports what the context says either way, so a
// server that is still working when the deadline passes fails the way a real
// one does.
func (s *stubTransport) wait(ctx context.Context) error {
	_, hasDeadline := ctx.Deadline()

	s.mu.Lock()
	s.deadlineSeen = hasDeadline
	delay := s.delay
	s.mu.Unlock()

	if delay == 0 {
		return ctx.Err()
	}

	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-timer.C:
	case <-ctx.Done():
	}
	return ctx.Err()
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

	// handed counts how often a transport was asked for, which is how a page
	// that must not reach any server is checked.
	handed int
}

func (s *stubConnector) Get(cfg transport.Config) (transport.Transport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.handed++
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

// connections is how many transports the connector has handed out.
func (s *stubConnector) connections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.handed
}

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

	// The limit is a setting now, so the test asks the panel what it is rather
	// than restating a number that can move.
	settingsMaxLoginAttempts := env.app.Settings.Int(settings.LoginRateMaxAttempts)

	for i := 1; i <= settingsMaxLoginAttempts; i++ {
		recorder := env.do(t, postForm("/login", "username=dnsadmin&password=wrong"))
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d returned %d, want 401", i, recorder.Code)
		}
	}

	recorder := env.do(t, postForm("/login", "username=dnsadmin&password=wrong"))
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt %d returned %d, want 429",
			settingsMaxLoginAttempts+1, recorder.Code)
	}

	// The correct password must not slip past the limit either.
	recorder = env.do(t, postForm("/login", "username=dnsadmin&password=correct-horse"))
	if recorder.Code != http.StatusTooManyRequests {
		t.Errorf("a correct password returned %d while limited, want 429", recorder.Code)
	}
}

func TestABurstOfLoginsGetsNoMoreAttemptsThanTheLimit(t *testing.T) {
	// A limiter that checked the count and wrote the row separately would let
	// every request of a burst read the same pre-burst number and pass, so the
	// limit would bound sequential attempts only.
	env := newTestEnv(t)
	limit := env.app.Settings.Int(settings.LoginRateMaxAttempts)
	burst := limit * 3

	var mu sync.Mutex
	codes := map[int]int{}

	var wg sync.WaitGroup
	start := make(chan struct{})

	for range burst {
		wg.Go(func() {
			<-start

			recorder := env.do(t, postForm("/login", "username=dnsadmin&password=wrong"))

			mu.Lock()
			codes[recorder.Code]++
			mu.Unlock()
		})
	}
	close(start)
	wg.Wait()

	if codes[http.StatusUnauthorized] != limit {
		t.Errorf("%d attempts reached the password check, want %d (%v)",
			codes[http.StatusUnauthorized], limit, codes)
	}
	if codes[http.StatusTooManyRequests] != burst-limit {
		t.Errorf("%d attempts were refused, want %d (%v)",
			codes[http.StatusTooManyRequests], burst-limit, codes)
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
		"Cache-Control":          "no-store",
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

func TestAnAuthenticatedPageIsNeverStored(t *testing.T) {
	// The pages carry records, audit rows, the server inventory and a CSRF
	// token. A copy in the disk cache outlives the session that produced it.
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")

	for _, path := range []string{"/dns", "/servers", "/logs", "/settings"} {
		t.Run(path, func(t *testing.T) {
			recorder := env.do(t, httptest.NewRequest(http.MethodGet, path, nil), cookie)

			if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store", got)
			}
		})
	}
}

func TestAStaticAssetKeepsItsOwnCacheDirective(t *testing.T) {
	// The assets are neither private nor different between readers, and
	// refusing to store them would refetch every stylesheet on every page.
	env := newTestEnv(t)

	recorder := env.do(t, httptest.NewRequest(http.MethodGet, "/static/css/panel.css", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-cache" {
		t.Errorf("Cache-Control = %q, want no-cache", got)
	}
}

// dueForRotation ages a session so the next request through it rotates.
func (e *testEnv) dueForRotation(t *testing.T, cookie *http.Cookie) {
	t.Helper()

	past := time.Now().UTC().Add(-10 * time.Minute)
	if _, err := e.db.Exec(
		"UPDATE sessions SET regenerated_at = ? WHERE id = ?",
		past.Format("2006-01-02 15:04:05"), cookie.Value); err != nil {
		t.Fatalf("cannot age the session: %v", err)
	}
}

func TestTwoRequestsThatMeetOnARotationBothSucceed(t *testing.T) {
	// The panel polls its own pages, so a status refresh landing at the same
	// instant as a user action is routine. Both requests carry the identifier
	// the browser has, one of them replaces it, and the other used to be told
	// its session is unknown: an expiring Set-Cookie that destroys a live
	// session, or an internal error page.
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")
	env.dueForRotation(t, cookie)

	var wait sync.WaitGroup
	answers := make([]*httptest.ResponseRecorder, 2)
	for i := range answers {
		wait.Go(func() {
			answers[i] = env.do(t, httptest.NewRequest(http.MethodGet, "/dns", nil), cookie)
		})
	}
	wait.Wait()

	var cleared int
	for i, answer := range answers {
		if answer.Code != http.StatusOK {
			t.Errorf("request %d = %d, want 200", i, answer.Code)
		}
		for _, set := range answer.Result().Cookies() {
			if set.Name == auth.SessionCookieName && set.MaxAge < 0 {
				cleared++
			}
		}
	}
	if cleared > 0 {
		t.Errorf("%d of the two responses cleared the session cookie", cleared)
	}

	// Whatever identifier the browser ends up with, it still names the session.
	session, err := env.sessions.Find(context.Background(), cookie.Value,
		time.Now().UTC().Add(-10*time.Second))
	if err != nil {
		t.Fatalf("the session is gone after the rotation: %v", err)
	}
	if session.Username != "dnsadmin" {
		t.Errorf("the session belongs to %q", session.Username)
	}
}

func TestARequestStillCarryingTheOldIdentifierIsKept(t *testing.T) {
	// The deterministic half of the race above: one request has already
	// rotated, and the one that was in flight beside it arrives afterwards
	// with the identifier the browser had. Clearing its cookie would sign the
	// user out of a session that is alive.
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")
	env.dueForRotation(t, cookie)

	first := env.do(t, httptest.NewRequest(http.MethodGet, "/dns", nil), cookie)
	if first.Code != http.StatusOK {
		t.Fatalf("the first request = %d, want 200", first.Code)
	}
	var rotated *http.Cookie
	for _, set := range first.Result().Cookies() {
		if set.Name == auth.SessionCookieName {
			rotated = set
		}
	}
	if rotated == nil || rotated.Value == cookie.Value {
		t.Fatal("the first request did not rotate the session")
	}

	late := env.do(t, httptest.NewRequest(http.MethodGet, "/dns", nil), cookie)
	if late.Code != http.StatusOK {
		t.Fatalf("the late request = %d, want 200", late.Code)
	}
	for _, set := range late.Result().Cookies() {
		if set.Name == auth.SessionCookieName {
			t.Errorf("the late request rewrote the cookie to %q, want it left alone", set.Value)
		}
	}
}
