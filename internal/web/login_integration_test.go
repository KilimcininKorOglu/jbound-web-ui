//go:build integration

// The phase gate of Faz 3. It runs inside the development container against
// the real setuid helper and the real PAM stack, because a mock cannot prove
// that a locked account, an expired account or a service shell behaves the way
// the policy assumes.
//
// Run it with: make dev-itest

package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"unbound-web/internal/audit"
	"unbound-web/internal/auth"
	"unbound-web/internal/config"
	"unbound-web/internal/database"
	"unbound-web/internal/dnsquery"
	"unbound-web/internal/fleet"
	"unbound-web/internal/preflight"
	"unbound-web/internal/server"
	"unbound-web/internal/settings"
	"unbound-web/internal/siem"
	"unbound-web/internal/store"
	"unbound-web/internal/transport"
)

// roleField reads the role out of the login response.
var roleField = regexp.MustCompile(`data-field="role">([a-z]*)<`)

// loginCase is one row of the gate matrix.
type loginCase struct {
	name       string
	username   string
	passwordFn func() string
	wantStatus int
	wantRole   string
	rule       string
}

func envPassword(key string) func() string {
	return func() string { return os.Getenv(key) }
}

func gateMatrix() []loginCase {
	return []loginCase{
		{"root", "root", envPassword("DEV_PASSWORD_ROOT"),
			http.StatusOK, auth.RoleAdmin, "uid 0 becomes an admin"},
		{"admin group member", "dnsadmin", envPassword("DEV_PASSWORD_DNSADMIN"),
			http.StatusOK, auth.RoleAdmin, "ADMIN_GROUP membership grants admin"},
		{"plain account", "dnsuser", envPassword("DEV_PASSWORD_DNSUSER"),
			http.StatusOK, auth.RoleUser, "a normal account may sign in"},
		{"service shell", "svcacct", envPassword("DEV_PASSWORD_SVCACCT"),
			http.StatusUnauthorized, "", "the shell is on the denied list"},
		{"uid below the floor", "lowuid", envPassword("DEV_PASSWORD_LOWUID"),
			http.StatusUnauthorized, "", "the uid is below MIN_UID"},
		{"locked account", "lockeduser", envPassword("DEV_PASSWORD_LOCKEDUSER"),
			http.StatusUnauthorized, "", "the helper exits 1"},
		{"expired account", "expireduser", envPassword("DEV_PASSWORD_EXPIREDUSER"),
			http.StatusUnauthorized, "", "the helper exits 2 from pam_acct_mgmt"},
		{"empty password", "nopwuser", func() string { return "" },
			http.StatusBadRequest, "", "an empty password never reaches the helper"},
		{"wrong password", "dnsuser", func() string { return "definitely-not-the-password" },
			http.StatusUnauthorized, "", "a wrong password is refused"},
	}
}

// newLiveApp builds the panel with the real helper behind it.
//
// Each call gets its own database, so the rate limiter of one row cannot
// influence the next.
func newLiveApp(t *testing.T) *App {
	t.Helper()

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("cannot load the configuration: %v", err)
	}
	if err := preflight.AuthHelper(cfg.AuthHelperPath); err != nil {
		t.Fatalf("the setuid helper is not usable: %v", err)
	}

	db, err := database.Open(context.Background(), filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatalf("cannot open the database: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	authenticator, err := auth.NewHelperAuthenticator(cfg.AuthHelperPath, cfg.AuthMaxConcurrent)
	if err != nil {
		t.Fatalf("cannot build the authenticator: %v", err)
	}

	options := settings.NewService(store.NewSettings(db.DB))
	if err := options.Load(context.Background()); err != nil {
		t.Fatalf("cannot load the settings: %v", err)
	}

	forwarder := siem.NewForwarder("panel.test")
	t.Cleanup(func() { forwarder.Close() })
	auditLog := audit.NewLogger(store.NewAuditLogs(db.DB), forwarder).
		WithForwarding(options.BoolOf(settings.SIEMForwardingEnabled))

	// The login path does not reach a managed server, so the service is here
	// only because the application needs one to build.
	dataDir := t.TempDir()
	keys, err := server.NewKeyStore(dataDir)
	if err != nil {
		t.Fatalf("cannot create the key store: %v", err)
	}
	pool := transport.NewPool(context.Background(),
		options.DurationOf(settings.SSHIdleTimeout))
	t.Cleanup(pool.Close)

	timeouts := func() server.Timeouts {
		return server.Timeouts{
			Connect: options.Duration(settings.SSHConnectTimeout),
			Command: options.Duration(settings.SSHCommandTimeout),
		}
	}
	serverStore := store.NewServers(db.DB)
	servers := server.NewService(serverStore, store.NewGroups(db.DB), keys, pool,
		auditLog, dataDir, timeouts)

	recordStore := store.NewRecords(db.DB)
	stateStore := store.NewStates(db.DB)
	refresher := fleet.NewRefresher(serverStore, recordStore, stateStore, pool,
		dataDir, timeouts, options.IntOf(settings.FleetMaxConcurrent))
	records := fleet.NewService(recordStore, stateStore,
		fleet.NewWriter(serverStore, servers, pool, refresher, auditLog,
			dataDir, timeouts, options.IntOf(settings.FleetMaxConcurrent)),
		refresher, dnsquery.New(cfg.DigPath, options.DurationOf(settings.DNSQueryTimeout)),
		auditLog, options.DurationOf(settings.CacheStaleAfter),
		options.IntOf(settings.RecordsPerPage))

	app, err := NewApp(Deps{
		Config: cfg,
		Auth: auth.NewService(authenticator, auth.Policy{
			MinUID:       cfg.MinUID,
			AdminGroup:   cfg.AdminGroup,
			AllowedGroup: cfg.AllowedGroup,
		}),
		Settings: options,
		Sessions: auth.NewSessionManager(store.NewSessions(db.DB),
			options.DurationOf(settings.SessionIdleTimeout),
			options.DurationOf(settings.SessionLifetime), cfg.CookieSecure),
		Limiter: auth.NewRateLimiter(store.NewLoginAttempts(db.DB),
			options.DurationOf(settings.LoginRateWindow),
			options.IntOf(settings.LoginRateMaxAttempts)),
		Audit:   auditLog,
		Servers: servers,
		Records: records,
		SIEM: siem.NewManager(cfg.RsyslogConfPath, cfg.SyslogLogPath,
			cfg.RsyslogValidateCmd, cfg.RsyslogRestartCmd, cfg.RsyslogStatusCmd),
		Forwarder: forwarder,
	})
	if err != nil {
		t.Fatalf("cannot build the application: %v", err)
	}
	return app
}

// liveServer serves the panel over a real socket, so the request travels the
// same path a browser would take.
func liveServer(t *testing.T, app *App) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(app.Router())
	t.Cleanup(server.Close)
	return server
}

// postLogin sends one login request and returns the status and the body.
func postLogin(t *testing.T, app *App, username, password string) (int, string) {
	t.Helper()

	server := liveServer(t, app)
	form := url.Values{"username": {username}, "password": {password}}

	response, err := server.Client().PostForm(server.URL+"/login", form)
	if err != nil {
		t.Fatalf("the login request failed: %v", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("cannot read the response body: %v", err)
	}
	return response.StatusCode, string(body)
}

func TestGateLoginMatrix(t *testing.T) {
	for _, tc := range gateMatrix() {
		t.Run(tc.name, func(t *testing.T) {
			// Only the empty password row is expected to carry no password.
			// A missing environment value elsewhere would make the row pass
			// for the wrong reason.
			if tc.wantStatus != http.StatusBadRequest && tc.passwordFn() == "" {
				t.Fatalf("no password configured for %s, check .env.dev", tc.username)
			}

			status, body := postLogin(t, newLiveApp(t), tc.username, tc.passwordFn())

			if status != tc.wantStatus {
				t.Fatalf("%s: status = %d, want %d (%s)",
					tc.username, status, tc.wantStatus, tc.rule)
			}
			if tc.wantRole == "" {
				return
			}

			match := roleField.FindStringSubmatch(body)
			if match == nil {
				t.Fatalf("%s: the response carries no role", tc.username)
			}
			if match[1] != tc.wantRole {
				t.Errorf("%s: role = %q, want %q (%s)",
					tc.username, match[1], tc.wantRole, tc.rule)
			}
		})
	}
}

func TestGateRejectionsShareOneMessage(t *testing.T) {
	// Every refused account must look identical from outside. An account that
	// is locked, one that has no such name and one that merely mistyped the
	// password would otherwise be distinguishable.
	//
	// The empty password row is not part of this set. It never reaches the
	// authenticator, and its own message asks the user to fill the form in.
	seen := map[string][]string{}

	for _, tc := range gateMatrix() {
		if tc.wantStatus != http.StatusUnauthorized {
			continue
		}
		_, body := postLogin(t, newLiveApp(t), tc.username, tc.passwordFn())
		message := extractAlert(t, body)
		seen[message] = append(seen[message], tc.username)
	}

	if len(seen) != 1 {
		t.Fatalf("the refused accounts produced %d different messages: %v", len(seen), seen)
	}
	for message := range seen {
		if !strings.Contains(message, "Invalid username or password.") {
			t.Errorf("the shared message is %q", message)
		}
	}
}

func TestGateNoPasswordReachesTheLogs(t *testing.T) {
	// A password in a log file survives log rotation, backups and the SIEM.
	var (
		mu     sync.Mutex
		buffer strings.Builder
	)
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&lockedWriter{mu: &mu, w: &buffer}, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	app := newLiveApp(t)
	for _, tc := range gateMatrix() {
		password := tc.passwordFn()
		postLogin(t, app, tc.username, password)
	}

	mu.Lock()
	logged := buffer.String()
	mu.Unlock()

	for _, tc := range gateMatrix() {
		password := tc.passwordFn()
		if password == "" {
			continue
		}
		if strings.Contains(logged, password) {
			t.Errorf("the password of %s appears in the log output", tc.username)
		}
	}
}

func TestGateNoPasswordReachesTheProcessTable(t *testing.T) {
	// The password travels on stdin. Command lines are world readable on
	// Linux, so a password in argv would be visible to every local account
	// for as long as the helper runs.
	//
	// This test process holds the fixture passwords in its own environment,
	// because it has to send them. The panel process is checked separately
	// below and must not.
	password := os.Getenv("DEV_PASSWORD_DNSUSER")
	if password == "" {
		t.Fatal("DEV_PASSWORD_DNSUSER is not set, check .env.dev")
	}

	app := newLiveApp(t)
	done := make(chan struct{})

	go func() {
		defer close(done)
		// A wrong password makes pam_unix sleep for about two seconds, which
		// is the window this test inspects. The sent value starts with the
		// real password, so searching for the prefix catches both.
		postLogin(t, app, "dnsuser", password+"-wrong")
	}()

	var (
		found      bool
		sawHelper  bool
		helperPath = os.Getenv("AUTH_HELPER_PATH")
	)
poll:
	for {
		output, err := exec.Command("ps", "-eo", "args").CombinedOutput()
		if err != nil {
			t.Fatalf("cannot run ps: %v", err)
		}
		if strings.Contains(string(output), password) {
			found = true
			break
		}
		if helperPath != "" && strings.Contains(string(output), helperPath) {
			sawHelper = true
		}
		select {
		case <-done:
			break poll
		case <-time.After(50 * time.Millisecond):
		}
	}
	<-done

	if found {
		t.Error("the password is visible in the command line of a process")
	}
	// Without this the test would pass just as happily if the helper never
	// ran at all.
	if !sawHelper {
		t.Error("the helper was never observed in the process table")
	}
}

func TestGateNoPasswordReachesThePanelEnvironment(t *testing.T) {
	// The panel runs for weeks. A password in its environment would sit in
	// /proc for that whole time, readable by every account in the same uid.
	password := os.Getenv("DEV_PASSWORD_DNSUSER")
	if password == "" {
		t.Fatal("DEV_PASSWORD_DNSUSER is not set, check .env.dev")
	}

	pid := findPanelProcess(t)
	environ, err := os.ReadFile(filepath.Join("/proc", pid, "environ"))
	if err != nil {
		t.Fatalf("cannot read the environment of the panel process: %v", err)
	}

	if strings.Contains(string(environ), password) {
		t.Error("a fixture password is in the environment of the panel process")
	}
}

// findPanelProcess returns the pid of the running panel.
func findPanelProcess(t *testing.T) string {
	t.Helper()

	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatalf("cannot read /proc: %v", err)
	}

	self := strconv.Itoa(os.Getpid())
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == self {
			continue
		}
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		cmdline, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err != nil {
			// The process ended between the listing and the read.
			continue
		}
		// cmdline is NUL separated. The first field is the binary path, which
		// air rebuilds under tmp/ inside the bind mounted source.
		arg0, _, _ := strings.Cut(string(cmdline), "\x00")
		if strings.HasSuffix(arg0, "/tmp/unbound-web") {
			return entry.Name()
		}
	}

	t.Fatal("the panel process is not running, start the stack with make dev-up")
	return ""
}

func TestGatePanelDoesNotRunAsRoot(t *testing.T) {
	// The panel holds an SSH key to every managed server. Running it as root
	// would mean one HTTP flaw hands over the whole fleet.
	if os.Geteuid() == 0 {
		t.Fatal("the tests run as root, run them as the unbound-web account")
	}
	if err := preflight.NotRoot(); err != nil {
		t.Fatalf("the root check failed: %v", err)
	}
}

// lockedWriter serialises the log output the test collects.
type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// extractAlert pulls the message out of the login response.
func extractAlert(t *testing.T, body string) string {
	t.Helper()

	const marker = `data-alert="error">`
	start := strings.Index(body, marker)
	if start < 0 {
		t.Fatalf("the response carries no alert: %s", body)
	}
	rest := body[start+len(marker):]
	end := strings.Index(rest, "<")
	if end < 0 {
		t.Fatalf("the alert is not closed: %s", body)
	}
	return rest[:end]
}
