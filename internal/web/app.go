// Package web wires the HTTP surface of the panel.
package web

import (
	"embed"
	"net/http"
	"os"
	"strings"
	"time"

	"unbound-web/internal/audit"
	"unbound-web/internal/auth"
	"unbound-web/internal/config"
	"unbound-web/internal/fleet"
	"unbound-web/internal/i18n"
	"unbound-web/internal/server"
	"unbound-web/internal/settings"
	"unbound-web/internal/siem"
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

	// SIEM manages the panel's own rsyslog configuration, and Forwarder is
	// what the test events go out through.
	SIEM      *siem.Manager
	Forwarder audit.Forwarder

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
		"POST /dns/records":     a.handleRecordCreate,
		"PUT /dns/records":      a.handleRecordUpdate,
		"DELETE /dns/records":   a.handleRecordDelete,
		"POST /dns/refresh":     a.handleRecordRefresh,
		"POST /dns/apply":       a.handleRecordApply,
		"GET /dns/query":        a.handleQueryForm,
		"POST /dns/query":       a.handleQuery,

		"GET /logs":       a.handleLogsPage,
		"GET /logs/table": a.handleLogsTable,

		"GET /diff":         a.handleDiffPage,
		"GET /diff/table":   a.handleDiffTable,
		"POST /diff/repair": a.handleDiffRepair,
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
		"GET /servers":             a.handleServersPage,
		"GET /servers/table":       a.handleServerTable,
		"GET /servers/new":         a.handleServerForm,
		"POST /servers":            a.handleServerCreate,
		"GET /servers/{id}/edit":   a.handleServerForm,
		"POST /servers/{id}":       a.handleServerUpdate,
		"DELETE /servers/{id}":     a.handleServerDelete,
		"GET /servers/{id}/key":    a.handleServerKey,
		"POST /servers/{id}/test":  a.handleServerTest,
		"POST /servers/{id}/trust": a.handleServerTrust,

		"GET /settings":  a.handleSettingsPage,
		"POST /settings": a.handleSettingsSave,

		"GET /siem":             a.handleSIEMPage,
		"GET /siem/panel":       a.handleSIEMPanel,
		"POST /siem":            a.handleSIEMSave,
		"POST /siem/test":       a.handleSIEMTest,
		"POST /siem/forwarding": a.handleSIEMForwarding,

		"GET /groups/new":       a.handleGroupForm,
		"POST /groups":          a.handleGroupCreate,
		"GET /groups/{id}/edit": a.handleGroupForm,
		"POST /groups/{id}":     a.handleGroupUpdate,
		"DELETE /groups/{id}":   a.handleGroupDelete,
	}
	for pattern, handler := range admin {
		mux.Handle(pattern, a.requireAuth(a.requireAdmin(a.requireCSRF(handler))))
	}

	return requestLog(securityHeaders(mux))
}

func (a *App) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}
