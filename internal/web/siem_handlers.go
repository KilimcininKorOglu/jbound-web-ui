package web

import (
	"errors"
	"net/http"
	"strings"

	"unbound-web/internal/audit"
	"unbound-web/internal/siem"
)

// defaultLogLines is what the viewer shows without being asked.
const defaultLogLines = 50

// siemPageData feeds the SIEM page and its fragments.
type siemPageData struct {
	Settings siem.Settings

	// Rules is what the form shows. It differs from the stored rules while a
	// refused submission is being corrected.
	Rules string

	Lines   []string
	Problem string
	Notice  string
}

func (a *App) handleSIEMPage(w http.ResponseWriter, r *http.Request) {
	data, err := a.siemPageData(r)
	if err != nil {
		a.internalError(w, "cannot read the syslog configuration", err)
		return
	}
	a.Render(w, r, http.StatusOK, "siem", PageData{Title: "SIEM Config", Data: data})
}

// handleSIEMPanel re-renders the configuration card, which is what a save and
// a test both swap back into the page.
func (a *App) handleSIEMPanel(w http.ResponseWriter, r *http.Request) {
	data, err := a.siemPageData(r)
	if err != nil {
		a.internalError(w, "cannot read the syslog configuration", err)
		return
	}
	a.RenderPartial(w, http.StatusOK, "siem-panel", data)
}

func (a *App) siemPageData(r *http.Request) (siemPageData, error) {
	settings, err := a.SIEM.Settings(r.Context())
	if err != nil {
		return siemPageData{}, err
	}

	lines, err := a.SIEM.Recent(defaultLogLines)
	if err != nil {
		// The log file is a view. A panel whose log cannot be read still has to
		// show its configuration, which is what an operator fixes it with.
		lines = nil
	}

	return siemPageData{Settings: settings, Rules: settings.ForwardingRules, Lines: lines}, nil
}

// handleSIEMSave writes the forwarding rules and restarts the daemon.
func (a *App) handleSIEMSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.siemProblem(w, r, "", "The form could not be read.", http.StatusBadRequest)
		return
	}
	rules := strings.ReplaceAll(strings.TrimSpace(r.PostFormValue("rules")), "\r\n", "\n")

	if err := a.SIEM.Save(r.Context(), rules); err != nil {
		a.siemProblem(w, r, rules, siemMessage(err), siemStatus(err))
		return
	}

	a.auditSIEM(r, audit.ActionSIEMConfig, "SIEM forwarding configuration updated")
	SetToast(w, ToastSuccess, "The forwarding rules were saved and rsyslog was restarted.")
	a.handleSIEMPanel(w, r)
}

// handleSIEMTest sends the test events.
func (a *App) handleSIEMTest(w http.ResponseWriter, r *http.Request) {
	actor := a.actor(r)
	message, err := siem.SendTestEvents(r.Context(), a.Forwarder, audit.Entry{
		UID: actor.UID, Username: actor.Username, IPAddress: actor.IPAddress})
	if err != nil {
		SetToast(w, ToastError, userMessage(err))
		a.internalError(w, "cannot send the test events", err)
		return
	}

	a.auditSIEM(r, audit.ActionSIEMTest, message)

	data, err := a.siemPageData(r)
	if err != nil {
		a.internalError(w, "cannot read the syslog configuration", err)
		return
	}
	data.Notice = message

	SetToast(w, ToastSuccess, message)
	a.RenderPartial(w, http.StatusOK, "siem-panel", data)
}

// siemProblem sends the form back with the reason it was refused.
func (a *App) siemProblem(w http.ResponseWriter, r *http.Request,
	rules, problem string, status int) {

	data, err := a.siemPageData(r)
	if err != nil {
		a.internalError(w, "cannot read the syslog configuration", err)
		return
	}

	// The submitted rules stay in the form, because the operator has to
	// correct them rather than type them again.
	data.Rules = rules
	data.Problem = problem

	a.RenderPartial(w, status, "siem-panel", data)
}

// auditSIEM records a change to the panel's own forwarding.
func (a *App) auditSIEM(r *http.Request, action, details string) {
	actor := a.actor(r)

	_ = a.Audit.Write(r.Context(), audit.Entry{
		UID:       actor.UID,
		Username:  actor.Username,
		Action:    action,
		Details:   details,
		IPAddress: actor.IPAddress,
	})
}

// siemMessage turns a refusal into a sentence the form can show.
func siemMessage(err error) string {
	switch {
	case errors.Is(err, siem.ErrRule):
		return capitalise(strings.TrimPrefix(err.Error(), siem.ErrRule.Error()+": ")) + "."
	case errors.Is(err, siem.ErrConfig):
		return capitalise(err.Error()) + "."
	default:
		return userMessage(err)
	}
}

func siemStatus(err error) int {
	if errors.Is(err, siem.ErrRule) {
		return http.StatusUnprocessableEntity
	}
	return http.StatusBadRequest
}
