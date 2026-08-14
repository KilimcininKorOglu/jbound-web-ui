package web

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"unbound-web/internal/audit"
	"unbound-web/internal/auth"
)

// Messages shown on the login page.
//
// Every rejection shares one message. Telling the user which accounts exist,
// which are locked and which merely typed the wrong password would turn the
// form into an account directory.
const (
	msgMissingFields = "Please fill in all fields."
	msgLoginFailed   = "Invalid username or password."
	msgRateLimited   = "Too many login attempts. Try again later."
	msgInternalError = "The panel could not process the request."
)

// handleLoginPage serves the login form.
func (a *App) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	// A live session belongs on the records page rather than on the login
	// form. Load renews the session, which is why it runs even here.
	if _, err := a.Sessions.Load(r.Context(), w, r); err == nil {
		redirect(w, r, "/dns")
		return
	}

	data := PageData{Title: "login.title"}
	if r.URL.Query().Get("timeout") == "1" {
		data.Alert = &Alert{
			Severity: ToastWarning,
			Message:  "Your session has expired. Please sign in again.",
		}
	}
	a.Render(w, r, http.StatusOK, "login", data)
}

// handleLogin authenticates a user.
//
// The order of the checks matters. The attempt is recorded before the password
// is verified, so a request that never returns still counts against the rate
// limit.
func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := auth.ClientIP(r)

	if !sameOrigin(r) {
		slog.Warn("cross origin login refused", "ip", ip,
			"origin", r.Header.Get("Origin"))
		a.loginFailure(w, r, http.StatusForbidden, msgLoginFailed)
		return
	}

	if err := r.ParseForm(); err != nil {
		a.loginFailure(w, r, http.StatusBadRequest, msgMissingFields)
		return
	}
	username := r.PostFormValue("username")
	password := r.PostFormValue("password")

	if username == "" || password == "" {
		a.loginFailure(w, r, http.StatusBadRequest, msgMissingFields)
		return
	}

	allowed, err := a.Limiter.Allow(r.Context(), ip)
	if err != nil {
		slog.Error("rate limit check failed", "ip", ip, "error", err)
		a.loginFailure(w, r, http.StatusInternalServerError, msgInternalError)
		return
	}
	if !allowed {
		slog.Warn("login rate limited", "ip", ip, "username", username)
		a.loginFailure(w, r, http.StatusTooManyRequests, msgRateLimited)
		return
	}

	if err := a.Limiter.Record(r.Context(), ip, username); err != nil {
		// Continuing here would let an attacker defeat the limiter by making
		// the insert fail, so the request stops instead.
		slog.Error("cannot record the login attempt", "ip", ip, "error", err)
		a.loginFailure(w, r, http.StatusInternalServerError, msgInternalError)
		return
	}

	user, err := a.Auth.Login(r.Context(), username, password)
	if err != nil {
		if !errors.Is(err, auth.ErrLoginFailed) {
			slog.Error("login could not be processed", "ip", ip, "error", err)
			a.loginFailure(w, r, http.StatusInternalServerError, msgInternalError)
			return
		}
		// A failed login is what a break-in attempt looks like from here, so it
		// is recorded and forwarded like any other event. The submitted name is
		// stored; the password never is.
		if auditErr := a.Audit.Write(r.Context(), audit.Entry{
			Username:  username,
			Action:    audit.ActionLoginFailed,
			Details:   fmt.Sprintf("Failed login attempt for '%s' from %s", username, ip),
			IPAddress: ip,
		}); auditErr != nil {
			slog.Error("failed login was not audited", "error", auditErr)
		}

		slog.Warn("login_failed", "username", username, "ip", ip)
		a.loginFailure(w, r, http.StatusUnauthorized, msgLoginFailed)
		return
	}

	session, err := a.Sessions.Start(r.Context(), w, r, user)
	if err != nil {
		slog.Error("cannot start the session", "username", user.Username, "error", err)
		a.loginFailure(w, r, http.StatusInternalServerError, msgInternalError)
		return
	}

	if err := a.Audit.Write(r.Context(), audit.Entry{
		UID:       user.UID,
		Username:  user.Username,
		Action:    audit.ActionLogin,
		Details:   fmt.Sprintf("User '%s' logged in from %s", user.Username, ip),
		IPAddress: ip,
	}); err != nil {
		// The session is already live. Refusing the login now would lock every
		// user out of a working panel over a log write, so the failure is
		// reported and the login stands.
		slog.Error("login was not audited", "username", user.Username, "error", err)
	}

	slog.Info("login", "username", user.Username, "role", user.Role, "ip", ip)

	w.Header().Set("HX-Redirect", "/dns")
	a.RenderPartial(w, r, http.StatusOK, "loggedin", loggedInData{
		Username: session.Username,
		Role:     session.Role,
	})
}

// loggedInData is the body of a successful login.
//
// htmx navigates on the HX-Redirect header, so this body is what a client
// without htmx sees. It carries the role, which is what the phase gate reads.
type loggedInData struct {
	Username string
	Role     string
}

// handleLogout ends the session.
func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	session, ok := SessionFrom(r.Context())
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	ip := auth.ClientIP(r)

	if err := a.Sessions.Destroy(r.Context(), w, session.ID); err != nil {
		slog.Error("cannot destroy the session", "username", session.Username, "error", err)
	}

	if err := a.Audit.Write(r.Context(), audit.Entry{
		UID:       session.UID,
		Username:  session.Username,
		Action:    audit.ActionLogout,
		Details:   fmt.Sprintf("User '%s' logged out from %s", session.Username, ip),
		IPAddress: ip,
	}); err != nil {
		slog.Error("logout was not audited", "username", session.Username, "error", err)
	}

	redirect(w, r, "/")
}

// loginFailure answers a rejected login.
//
// htmx swaps the alert fragment into the form, so the response is the fragment
// rather than the whole page. A client without htmx gets the page back with the
// same message inside it.
func (a *App) loginFailure(w http.ResponseWriter, r *http.Request, status int, message string) {
	alert := &Alert{Severity: ToastError, Message: message}

	if r.Header.Get("HX-Request") == "true" {
		a.RenderPartial(w, r, status, "alert", alert)
		return
	}
	a.Render(w, r, status, "login", PageData{Title: "login.title", Alert: alert})
}
