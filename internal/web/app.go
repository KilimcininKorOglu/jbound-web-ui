// Package web wires the HTTP surface of the panel.
package web

import (
	"context"
	"embed"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"jbound/internal/audit"
	"jbound/internal/auth"
	"jbound/internal/config"
	"jbound/internal/fleet"
	"jbound/internal/i18n"
	"jbound/internal/logging"
	"jbound/internal/server"
	"jbound/internal/settings"
	"jbound/internal/siem"
)

//go:embed templates
var templateFS embed.FS

// Deps is everything the handlers need.
//
// A struct rather than a parameter list, because the list grew past the point
// where a caller could tell two adjacent arguments apart.
type Deps struct {
	Config   *config.Config
	Settings *settings.Service
	Auth     *auth.Service
	Sessions *auth.SessionManager
	Limiter  *auth.RateLimiter
	Audit    *audit.Logger
	Servers  *server.Service
	Records  *fleet.Service

	// Receiver is the collector the panel sends its trail to, and Backlog is
	// how far behind that collector is. Both are nil on a panel built without
	// them, which is what the handler tests do, and the page then reports a
	// receiver that is off.
	Receiver *siem.Sender
	Backlog  *siem.Queue

	// Health answers whether the process can still serve. It is what the
	// public status route reports, so it has to reach the database rather than
	// describe the goroutine that answers the request.
	Health func(ctx context.Context) error

	// Hostname is the panel host as the system page reports it. NewApp reads
	// it when the caller leaves it empty.
	Hostname string

	// Started is when the process came up, which is what the uptime counts
	// from. NewApp stamps it when the caller leaves it zero.
	Started time.Time
}

// App holds everything the handlers need.
type App struct {
	Deps

	// Catalogs holds the interface texts of every language the panel was built
	// with, and tmpl holds one parsed template set per language.
	Catalogs *i18n.Catalogs
	tmpl     map[string]*templateSet
}

// NewApp parses the templates and returns the application.
func NewApp(deps Deps) (*App, error) {
	if deps.Health == nil {
		// Without a probe the status route can only report that a process
		// answered, which is what it used to do and what a monitor reads as a
		// working panel. A missing probe is a wiring mistake, so it stops the
		// panel here rather than at the first outage nobody was told about.
		return nil, errors.New("the health check needs a probe")
	}

	catalogs, err := i18n.Load()
	if err != nil {
		return nil, err
	}

	tmpl, err := parseTemplates(catalogs)
	if err != nil {
		return nil, err
	}

	if deps.Started.IsZero() {
		deps.Started = time.Now()
	}
	if deps.Hostname == "" {
		// A host that cannot name itself is not a reason to refuse to start,
		// so the system page says so instead.
		name, err := os.Hostname()
		if err != nil {
			name = "unknown"
		}
		deps.Hostname = name
	}

	return &App{Deps: deps, Catalogs: catalogs, tmpl: tmpl}, nil
}

// Router builds the panel handler.
//
// Every state changing route sits behind requireAuth and requireCSRF. Login is
// the exception, since it has no session yet, and it carries its own origin
// check instead.
func (a *App) Router() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", a.handleHealth)
	mux.Handle("GET /static/", staticHandler())

	mux.HandleFunc("GET /{$}", a.handleLoginPage)
	mux.HandleFunc("POST /login", a.handleLogin)
	mux.Handle("POST /logout", a.requireAuth(a.requireCSRF(
		http.HandlerFunc(a.handleLogout))))

	// Records are open to every signed in user. Which machines they land on is
	// admin territory, which the map below covers.
	records := map[string]http.HandlerFunc{
		"POST /theme":    a.handleThemeChange,
		"POST /language": a.handleLanguageChange,

		"GET /system":        a.handleSystemPage,
		"GET /system/status": a.handleSystemStatus,

		"GET /dns":              a.handleDNSPage,
		"GET /dns/records":      a.handleDNSRecords,
		"GET /dns/records/new":  a.handleRecordForm,
		"GET /dns/records/edit": a.handleRecordForm,
		// Every route below that reaches more than one server carries the
		// panel's own deadline, so a slow machine cannot push the response
		// past the transport write timeout and take the per-server report
		// with it.
		"POST /dns/records": a.withFleetDeadline(a.handleRecordCreate),
		"PUT /dns/records":  a.withFleetDeadline(a.handleRecordUpdate),
		// The answer to a name that already answers: make the target hold this
		// value, whatever each server held before. It is its own route rather
		// than a field on the edit, because it replaces a record the operator
		// never named and a form field could ask for that by accident.
		"PUT /dns/records/set": a.withFleetDeadline(a.handleRecordSet),
		"DELETE /dns/records":  a.withFleetDeadline(a.handleRecordDelete),
		"POST /dns/refresh":    a.withFleetDeadline(a.handleRecordRefresh),
		"POST /dns/apply":      a.withFleetDeadline(a.handleRecordApply),
		"GET /dns/query":       a.handleQueryForm,
		"POST /dns/query":      a.withFleetDeadline(a.handleQuery),

		"GET /diff":             a.handleDiffPage,
		"GET /diff/table":       a.handleDiffTable,
		"POST /diff/repair":     a.withFleetDeadline(a.handleDiffRepair),
		"POST /diff/repair-all": a.withFleetDeadline(a.handleDiffRepairAll),
	}
	for pattern, handler := range records {
		if strings.HasPrefix(pattern, "GET ") {
			mux.Handle(pattern, a.requireAuth(handler))
			continue
		}
		mux.Handle(pattern, a.requireAuth(a.requireCSRF(handler)))
	}

	// Fleet configuration is admin territory. A plain user may manage records
	// but not the machines they land on.
	admin := map[string]http.HandlerFunc{
		"GET /servers":                  a.handleServersPage,
		"GET /servers/table":            a.handleServerTable,
		"GET /servers/new":              a.handleServerForm,
		"POST /servers":                 a.handleServerCreate,
		"GET /servers/{id}/edit":        a.handleServerForm,
		"POST /servers/{id}":            a.handleServerUpdate,
		"DELETE /servers/{id}":          a.handleServerDelete,
		"GET /servers/{id}/key":         a.handleServerKey,
		"POST /servers/{id}/rotate-key": a.handleServerRotateKey,
		"POST /servers/{id}/test":       a.handleServerTest,
		"POST /servers/{id}/trust":      a.handleServerTrust,

		// The restore reaches one server, so it needs no fleet deadline, but it
		// is a write to a resolver and belongs with the rest of them here.
		"POST /servers/{id}/restore-file": a.handleServerRestoreFile,

		// The trail carries every account's sign ins with their source
		// addresses, and the details of a failed login hold the exact string
		// that was typed into the user name box. The SIEM page, which shows
		// the same events read back from syslog, is admin territory for the
		// same reason.
		"GET /logs":       a.handleLogsPage,
		"GET /logs/table": a.handleLogsTable,

		"GET /settings":  a.handleSettingsPage,
		"POST /settings": a.handleSettingsSave,

		"GET /sessions":             a.handleSessionsPage,
		"GET /sessions/table":       a.handleSessionsTable,
		"POST /sessions/revoke":     a.handleSessionRevoke,
		"POST /sessions/revoke-all": a.handleSessionRevokeAll,

		"GET /siem":       a.handleSIEMPage,
		"GET /siem/panel": a.handleSIEMPanel,
		"POST /siem/test": a.handleSIEMTest,
		"POST /diff/sync": a.withFleetDeadline(a.handleDiffSync),

		"POST /siem/forwarding": a.handleSIEMForwarding,
		"POST /siem/receiver":   a.handleSIEMReceiver,

		"GET /groups/new":       a.handleGroupForm,
		"POST /groups":          a.handleGroupCreate,
		"GET /groups/{id}/edit": a.handleGroupForm,
		"POST /groups/{id}":     a.handleGroupUpdate,
		"DELETE /groups/{id}":   a.handleGroupDelete,
	}
	for pattern, handler := range admin {
		mux.Handle(pattern, a.requireAuth(a.requireAdmin(a.requireCSRF(handler))))
	}

	return requestLog(recoverPanic(securityHeaders(mux)))
}

// healthTimeout bounds the probe behind the status route.
//
// A database that has stopped answering is exactly the state the route exists
// to report, so the probe must come back with an answer rather than wait for
// one until the monitor gives up.
const healthTimeout = 5 * time.Second

// handleHealth reports whether the panel can still serve.
//
// The probe reaches the database, because a process that is running and a panel
// that works are two different things: an unreadable database, a full disk or an
// unmounted data directory leaves every page failing while the process itself is
// perfectly alive.
//
// The reason stays in the log. The route is the one status surface open without
// a session, so the body says whether the panel serves and nothing about why it
// does not.
func (a *App) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), healthTimeout)
	defer cancel()

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	if err := a.Health(ctx); err != nil {
		logging.From(r.Context()).Error("the health check failed", "error", err)

		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("unavailable\n"))
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}
