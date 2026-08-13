// Package web wires the HTTP surface of the panel.
package web

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"

	"unbound-web/internal/audit"
	"unbound-web/internal/auth"
	"unbound-web/internal/config"
)

//go:embed templates/*.html
var templateFS embed.FS

// App holds everything the handlers need.
type App struct {
	cfg      *config.Config
	auth     *auth.Service
	sessions *auth.SessionManager
	limiter  *auth.RateLimiter
	audit    *audit.Logger
	tmpl     *template.Template
}

// NewApp parses the templates and returns the application.
func NewApp(cfg *config.Config, authService *auth.Service,
	sessions *auth.SessionManager, limiter *auth.RateLimiter,
	auditLog *audit.Logger) (*App, error) {

	tmpl, err := template.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("cannot parse the templates: %w", err)
	}

	return &App{
		cfg:      cfg,
		auth:     authService,
		sessions: sessions,
		limiter:  limiter,
		audit:    auditLog,
		tmpl:     tmpl,
	}, nil
}

// Router builds the panel handler.
//
// Every state changing route sits behind RequireAuth and RequireCSRF. Login is
// the exception, since it has no session yet, and it carries its own origin
// check instead.
func (a *App) Router() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", a.handleHealth)
	mux.HandleFunc("GET /{$}", a.handleLoginPage)
	mux.HandleFunc("POST /login", a.handleLogin)

	mux.Handle("POST /logout", a.requireAuth(a.requireCSRF(
		http.HandlerFunc(a.handleLogout))))

	mux.Handle("GET /dashboard", a.requireAuth(
		http.HandlerFunc(a.placeholder("Dashboard"))))

	// Faz 6 and Faz 10 replace these. They exist now so the admin rule has
	// routes to guard and the phase gate can prove it works.
	mux.Handle("GET /servers", a.requireAuth(a.requireAdmin(
		http.HandlerFunc(a.placeholder("Servers")))))
	mux.Handle("GET /siem", a.requireAuth(a.requireAdmin(
		http.HandlerFunc(a.placeholder("SIEM")))))

	return requestLog(securityHeaders(mux))
}

func (a *App) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// placeholderData feeds the stand in pages of Faz 3.
type placeholderData struct {
	Title     string
	Session   auth.Session
	CSRFToken string
}

func (a *App) placeholder(title string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, ok := SessionFrom(r.Context())
		if !ok {
			// requireAuth runs first, so this can only mean the chain was
			// wired wrong.
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		a.render(w, http.StatusOK, "placeholder", placeholderData{
			Title:     title,
			Session:   session,
			CSRFToken: session.CSRFToken,
		})
	}
}

// render writes a template with the given status.
//
// The template runs into a buffer first, so a failure halfway through does not
// leave a half written page behind a 200.
func (a *App) render(w http.ResponseWriter, status int, name string, data any) {
	var buf bytes.Buffer

	if err := a.tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		slog.Error("cannot render the template", "template", name, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if _, err := w.Write(buf.Bytes()); err != nil {
		slog.Error("cannot write the response", "template", name, "error", err)
	}
}
