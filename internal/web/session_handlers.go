package web

import (
	"fmt"
	"log/slog"
	"net/http"
	"strconv"

	"unbound-web/internal/audit"
	"unbound-web/internal/auth"
)

// sessionsPageData feeds the sessions page and its table fragment.
type sessionsPageData struct {
	Accounts []sessionRow

	// Total counts the sessions the revoke-all button would end, which is
	// every one of them but the caller's own.
	Total int
}

// sessionRow is one account with something open.
//
// No session identifier reaches this row. The identifier is the credential the
// browser presents, so a page that carried one would be handing it out.
type sessionRow struct {
	auth.SessionSummary

	// Self marks the account of the reader. Their own session is never ended
	// by a revocation, so the row says so instead of offering a button that
	// would only partly work.
	Self bool
}

func (a *App) handleSessionsPage(w http.ResponseWriter, r *http.Request) {
	data, err := a.sessionsPageData(r)
	if err != nil {
		a.internalError(w, "cannot load the sessions", err)
		return
	}
	a.Render(w, r, http.StatusOK, "sessions", PageData{Title: "nav.sessions", Data: data})
}

// handleSessionsTable re-renders the table after a revocation.
func (a *App) handleSessionsTable(w http.ResponseWriter, r *http.Request) {
	data, err := a.sessionsPageData(r)
	if err != nil {
		a.internalError(w, "cannot load the sessions", err)
		return
	}
	a.RenderPartial(w, r, http.StatusOK, "session-table", data)
}

// handleSessionRevoke ends every session of one account.
//
// The whole account rather than one session. The reason to press this is that
// an account is compromised, and the attacker's own session is not the one an
// administrator can point at from a list.
func (a *App) handleSessionRevoke(w http.ResponseWriter, r *http.Request) {
	session, _ := SessionFrom(r.Context())

	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	uid, err := strconv.Atoi(r.PostFormValue("uid"))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	username := r.PostFormValue("username")

	removed, err := a.Sessions.RevokeAccount(r.Context(), uid, session.ID)
	if err != nil {
		a.internalError(w, "cannot revoke the sessions of an account", err)
		return
	}

	a.auditRevoke(r, fmt.Sprintf("Ended %d session(s) of %s", removed, username))
	SetToast(w, ToastSuccess, a.catalog(r).Tf("toast.sessions_revoked", removed))
	a.handleSessionsTable(w, r)
}

// handleSessionRevokeAll ends every session but the caller's own.
func (a *App) handleSessionRevokeAll(w http.ResponseWriter, r *http.Request) {
	session, _ := SessionFrom(r.Context())

	removed, err := a.Sessions.RevokeAll(r.Context(), session.ID)
	if err != nil {
		a.internalError(w, "cannot revoke the sessions", err)
		return
	}

	a.auditRevoke(r, fmt.Sprintf("Ended %d session(s) across the panel", removed))
	SetToast(w, ToastSuccess, a.catalog(r).Tf("toast.sessions_revoked", removed))
	a.handleSessionsTable(w, r)
}

func (a *App) sessionsPageData(r *http.Request) (sessionsPageData, error) {
	session, _ := SessionFrom(r.Context())

	summaries, err := a.Sessions.Live(r.Context())
	if err != nil {
		return sessionsPageData{}, err
	}

	data := sessionsPageData{Accounts: make([]sessionRow, 0, len(summaries))}
	for _, summary := range summaries {
		self := summary.UID == session.UID
		data.Accounts = append(data.Accounts, sessionRow{SessionSummary: summary, Self: self})

		data.Total += summary.Count
		if self {
			// The reader's own session survives every revocation, so it is not
			// part of the number the confirmation quotes.
			data.Total--
		}
	}
	return data, nil
}

// auditRevoke records that somebody was signed out by somebody else.
func (a *App) auditRevoke(r *http.Request, details string) {
	actor := a.actor(r)

	err := a.Audit.Write(r.Context(), audit.Entry{
		UID:       actor.UID,
		Username:  actor.Username,
		Action:    audit.ActionSessionRevoke,
		Details:   details,
		IPAddress: actor.IPAddress,
	})
	if err != nil {
		slog.Error("cannot record a session revocation", "error", err)
	}
}
