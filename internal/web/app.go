// Package web wires the HTTP surface of the panel.
package web

import (
	"embed"
	"net/http"
	"strings"

	"unbound-web/internal/audit"
	"unbound-web/internal/auth"
	"unbound-web/internal/config"
	"unbound-web/internal/fleet"
	"unbound-web/internal/server"
)

//go:embed templates
var templateFS embed.FS

// App holds everything the handlers need.
type App struct {
	cfg      *config.Config
	auth     *auth.Service
	sessions *auth.SessionManager
	limiter  *auth.RateLimiter
	audit    *audit.Logger
	servers  *server.Service
	records  *fleet.Service
	tmpl     *templateSet
}

// NewApp parses the templates and returns the application.
func NewApp(cfg *config.Config, authService *auth.Service,
	sessions *auth.SessionManager, limiter *auth.RateLimiter,
	auditLog *audit.Logger, servers *server.Service,
	records *fleet.Service) (*App, error) {

	tmpl, err := parseTemplates()
	if err != nil {
		return nil, err
	}

	return &App{
		cfg:      cfg,
		auth:     authService,
		sessions: sessions,
		limiter:  limiter,
		audit:    auditLog,
		servers:  servers,
		records:  records,
		tmpl:     tmpl,
	}, nil
}

// pendingPage describes a page whose behaviour lands in a later phase.
type pendingPage struct {
	Heading string
	Note    string
}

// pending lists the pages that exist for their layout and access rules only.
// Each entry disappears when its phase fills the page in.
var pending = map[string]pendingPage{
	"diff": {"Record Diff",
		"The drift view across servers arrives with the diff phase."},
	"logs": {"Audit Logs",
		"The audit log view arrives with the log phase."},
	"siem": {"SIEM Config",
		"The syslog forwarding settings arrive with the SIEM phase."},
	"system": {"System Info",
		"The read only host information arrives with the fleet status phase."},
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

	for _, path := range []string{"/diff", "/logs", "/system"} {
		mux.Handle("GET "+path, a.requireAuth(a.pendingHandler(path)))
	}
	mux.Handle("GET /siem", a.requireAuth(a.requireAdmin(a.pendingHandler("/siem"))))

	// Records are open to every signed in user. Which machines they land on is
	// admin territory, which the map below covers.
	records := map[string]http.HandlerFunc{
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

// pendingHandler renders the stand in page of one route.
func (a *App) pendingHandler(path string) http.Handler {
	name := path[1:]

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page, ok := pending[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		a.Render(w, r, http.StatusOK, name, PageData{
			Title: page.Heading,
			Data:  page,
		})
	})
}
