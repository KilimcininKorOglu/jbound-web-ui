package web

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"runtime/debug"
	"sync"
	"time"

	"jbound/internal/auth"
	"jbound/internal/logging"
	"jbound/internal/settings"
)

// contextKey keeps the session out of the string keyed context namespace, so
// no other package can overwrite it by accident.
type contextKey struct{ name string }

var (
	sessionKey = &contextKey{name: "session"}
	stateKey   = &contextKey{name: "request-state"}
)

// SessionFrom returns the session of the current request.
func SessionFrom(ctx context.Context) (auth.Session, bool) {
	session, ok := ctx.Value(sessionKey).(auth.Session)
	return session, ok
}

// requestState is what the request log learns while the request runs.
//
// The log line is written by the outermost middleware, and the session is
// attached by requireAuth further in, on a context that outer layer never
// sees. The state travels by pointer so the answer reaches the line that has
// to carry it.
type requestState struct {
	id string

	mu       sync.Mutex
	username string
}

func (s *requestState) setUsername(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.username = name
}

func (s *requestState) Username() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.username
}

// stateFrom returns the state of the current request, or nil outside one.
func stateFrom(ctx context.Context) *requestState {
	state, _ := ctx.Value(stateKey).(*requestState)
	return state
}

// RequestID names the request in the log.
//
// It is answered for a context with no request as well, so a caller never has
// to ask whether it is inside one.
func RequestID(ctx context.Context) string {
	if state := stateFrom(ctx); state != nil {
		return state.id
	}
	return "unknown"
}

// serverError answers a failure the operator can look up in the log.
//
// The reference is the identifier of this request, which is what turns "it
// failed" into one line somebody can find.
func serverError(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "internal error (reference "+RequestID(r.Context())+")",
		http.StatusInternalServerError)
}

// withFleetDeadline bounds a handler that reaches several servers at once.
//
// One operation runs several SSH commands per server, each bounded by
// ssh_command_timeout, in batches of fleet_max_concurrent, so a slow machine
// can push the response past the server's write deadline. That deadline
// belongs to the transport: it cancels nothing and produces no status, so the
// browser sees a failed request while the write has already landed on some of
// the servers, and the per-server report is lost exactly when it matters.
//
// The deadline is read per request, so a change on the settings page applies
// without a restart. When it expires the fan-out finishes with the servers it
// could not reach marked failed, which is a report the operator can act on.
func (a *App) withFleetDeadline(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(),
			a.Settings.Duration(settings.FleetOperationTimeout))
		defer cancel()

		next(w, r.WithContext(ctx))
	}
}

// requireAuth rejects requests without a valid session.
//
// It also renews the session, so no handler can serve a request on a session
// that just passed its timeout.
func (a *App) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := a.Sessions.Load(r.Context(), w, r)
		if err != nil {
			switch {
			case errors.Is(err, auth.ErrSessionExpired):
				redirect(w, r, "/?timeout=1")
			case errors.Is(err, auth.ErrNoSession):
				redirect(w, r, "/")
			case errors.Is(err, auth.ErrFingerprintMismatch):
				logging.From(r.Context()).Warn("session rejected",
					"reason", "fingerprint mismatch", "ip", auth.ClientIP(r))
				redirect(w, r, "/")
			default:
				logging.From(r.Context()).Error("cannot load the session", "error", err)
				serverError(w, r)
			}
			return
		}

		// The request line names who made the request, and this is where the
		// panel first knows.
		if state := stateFrom(r.Context()); state != nil {
			state.setUsername(session.Username)
		}

		ctx := context.WithValue(r.Context(), sessionKey, session)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// requireAdmin rejects a session whose role is not admin.
func (a *App) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, ok := SessionFrom(r.Context())
		if !ok {
			serverError(w, r)
			return
		}
		if !session.IsAdmin() {
			logging.From(r.Context()).Warn("admin route refused",
				"username", session.Username, "path", r.URL.Path)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireCSRF validates the token of a state changing request.
func (a *App) requireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !auth.CSRFRequired(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		if !sameOrigin(r) {
			logging.From(r.Context()).Warn("cross origin request refused",
				"path", r.URL.Path, "origin", r.Header.Get("Origin"))
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		session, ok := SessionFrom(r.Context())
		if !ok {
			serverError(w, r)
			return
		}
		if !auth.ValidCSRF(session.CSRFToken, auth.CSRFToken(r)) {
			logging.From(r.Context()).Warn("csrf token refused",
				"username", session.Username, "path", r.URL.Path)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// sameOrigin checks the Origin header when the client sends one.
//
// Browsers always send it on a state changing request, so a mismatch is a
// cross site attempt. Command line clients send nothing, and rejecting those
// would break the integration tests without adding any protection.
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return parsed.Host == r.Host
}

// redirect sends the client to another page.
//
// htmx replaces a page fragment with whatever comes back, so a 303 to the
// login page would land inside the current layout. The HX-Redirect header
// makes htmx navigate instead.
func redirect(w http.ResponseWriter, r *http.Request, target string) {
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", target)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// securityHeaders sets the response headers that apply to every route.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		// Nothing the panel produces may be written to a disk cache or handed
		// back by the history mechanism. Every page carries records, audit
		// rows, the server inventory or a CSRF token, and a shared workstation
		// would otherwise give the next person the previous one's pages with
		// the back button. The asset handler replaces this with its own
		// directive, because those files are neither private nor changing
		// between requests.
		h.Set("Cache-Control", "no-store")
		// script-src stays strict. No inline script, no eval, which is why the
		// vendor bundles that wrap every module in eval were replaced.
		//
		// style-src allows inline. The layout helper of the template measures
		// the navbar and writes the resulting padding into a style element,
		// and the layout collapses without it. Injected CSS cannot reach
		// another host either, because default-src and img-src permit none.
		h.Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "+
				"script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

// statusRecorder captures the response status for the request log.
type statusRecorder struct {
	http.ResponseWriter
	status int

	// written says the response has started, which is what decides whether a
	// recovered panic can still answer with a status of its own.
	written bool
}

func (s *statusRecorder) WriteHeader(status int) {
	s.status = status
	s.written = true
	s.ResponseWriter.WriteHeader(status)
}

func (s *statusRecorder) Write(body []byte) (int, error) {
	s.written = true
	return s.ResponseWriter.Write(body)
}

// requestLog records one line per request.
//
// Only the path is logged, never the query string or the body, because both
// can carry a password typed into the wrong field.
func requestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

		// The identifier is the panel's own. An inbound X-Request-ID is
		// client supplied, and this panel already refuses to trust client
		// supplied headers about who a request is.
		state := &requestState{id: logging.NewID()}
		ctx := context.WithValue(r.Context(), stateKey, state)
		ctx = logging.NewContext(ctx, slog.Default().With(logging.Field, state.id))
		r = r.WithContext(ctx)

		// The header travels with every response, so a failure that produced
		// no error page can still be looked up.
		w.Header().Set("X-Request-Id", state.id)

		// Deferred, so the request that crashed is not the one request that
		// leaves no line behind.
		defer func() {
			fields := []any{
				logging.Field, state.id,
				"method", r.Method,
				"path", r.URL.Path,
				"status", recorder.status,
				"duration_ms", time.Since(started).Milliseconds(),
				"ip", auth.ClientIP(r),
			}
			// The login page and the assets have no session. An empty field
			// there would read as a user whose name is missing.
			if username := state.Username(); username != "" {
				fields = append(fields, "username", username)
			}
			slog.Info("request", fields...)
		}()

		next.ServeHTTP(recorder, r)
	})
}

// recoverPanic turns a crashed handler into a logged failure and a 500.
//
// Without it the panic reaches the per connection recovery of net/http, which
// drops the connection with no response and writes the stack through the
// server's error logger rather than through the structured stream.
func recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			cause := recover()
			if cause == nil {
				return
			}
			if cause == http.ErrAbortHandler {
				// A deliberate abort, not a fault. net/http knows what to do
				// with it and logs nothing.
				panic(cause)
			}

			logging.From(r.Context()).Error("handler panicked",
				"method", r.Method,
				"path", r.URL.Path,
				"panic", fmt.Sprint(cause),
				"stack", string(debug.Stack()),
			)

			if recorder, ok := w.(*statusRecorder); ok && recorder.written {
				// The response already started. Adding a status now would only
				// produce a superfluous header warning.
				return
			}
			serverError(w, r)
		}()

		next.ServeHTTP(w, r)
	})
}
