package web

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"unbound-web/internal/audit"
	"unbound-web/internal/i18n"
	appsettings "unbound-web/internal/settings"
	"unbound-web/internal/siem"
)

// defaultLogLines is what the viewer shows without being asked.
const defaultLogLines = 50

// siemPageData feeds the SIEM page and its fragments.
type siemPageData struct {
	Settings siem.Settings

	// Forwarding is the panel's own switch. The rules stay on the host either
	// way, so an operator can silence a noisy receiver without losing them.
	Forwarding bool

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
		a.internalError(w, r, "cannot read the syslog configuration", err)
		return
	}
	a.Render(w, r, http.StatusOK, "siem", PageData{Title: "nav.siem_config", Data: data})
}

// handleSIEMPanel re-renders the configuration card, which is what a save and
// a test both swap back into the page.
func (a *App) handleSIEMPanel(w http.ResponseWriter, r *http.Request) {
	data, err := a.siemPageData(r)
	if err != nil {
		a.internalError(w, r, "cannot read the syslog configuration", err)
		return
	}
	a.RenderPartial(w, r, http.StatusOK, "siem-panel", data)
}

func (a *App) siemPageData(r *http.Request) (siemPageData, error) {
	config, err := a.SIEM.Settings(r.Context())
	if err != nil {
		return siemPageData{}, err
	}

	lines, err := a.SIEM.Recent(defaultLogLines)
	if err != nil {
		// The log file is a view. A panel whose log cannot be read still has to
		// show its configuration, which is what an operator fixes it with.
		lines = nil
	}

	return siemPageData{
		Settings:   config,
		Forwarding: a.Settings.Bool(appsettings.SIEMForwardingEnabled),
		Rules:      config.ForwardingRules,
		Lines:      lines,
	}, nil
}

// handleSIEMForwarding turns the mirror on or off.
//
// It writes the same setting the settings page holds, because a switch next to
// the rules is where an operator looks for it while the receiver is the thing
// going wrong.
func (a *App) handleSIEMForwarding(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.siemProblem(w, r, "", a.catalog(r).T("error.form_unreadable"), http.StatusBadRequest)
		return
	}
	enabled := r.PostForm.Has("forwarding")
	// Save swaps the snapshot before it returns, so the state the entry has to
	// be judged against is the one that is still in place here.
	wasEnabled := a.Settings.Bool(appsettings.SIEMForwardingEnabled)

	err := a.Settings.Save(r.Context(), map[string]string{
		appsettings.SIEMForwardingEnabled: boolValue(enabled),
	})
	if err != nil {
		a.internalError(w, r, "cannot store the forwarding switch", err)
		return
	}

	state := "disabled"
	if enabled {
		state = "enabled"
	}
	a.auditSIEM(r, audit.ActionSIEMConfig, "SIEM forwarding "+state, wasEnabled && !enabled)

	catalog := a.catalog(r)
	SetToast(w, ToastSuccess, catalog.Tf("toast.forwarding_state",
		catalog.T("toast.forwarding_"+state)))

	a.handleSIEMPanel(w, r)
}

// handleSIEMSave writes the forwarding rules and restarts the daemon.
func (a *App) handleSIEMSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.siemProblem(w, r, "", a.catalog(r).T("error.form_unreadable"), http.StatusBadRequest)
		return
	}
	rules := strings.ReplaceAll(strings.TrimSpace(r.PostFormValue("rules")), "\r\n", "\n")

	if err := a.SIEM.Save(r.Context(), rules); err != nil {
		a.siemProblem(w, r, rules, siemMessage(r.Context(), a.catalog(r), err), siemStatus(err))
		return
	}

	a.auditSIEM(r, audit.ActionSIEMConfig, "SIEM forwarding configuration updated", false)
	SetToast(w, ToastSuccess, a.catalog(r).T("toast.rules_saved"))
	a.handleSIEMPanel(w, r)
}

// handleSIEMTest sends the test events.
func (a *App) handleSIEMTest(w http.ResponseWriter, r *http.Request) {
	actor := a.actor(r)
	message, err := siem.SendTestEvents(r.Context(), a.Forwarder, audit.Entry{
		UID: actor.UID, Username: actor.Username, IPAddress: actor.IPAddress})
	if err != nil {
		SetToast(w, ToastError, userMessage(r.Context(), a.catalog(r), err))
		a.internalError(w, r, "cannot send the test events", err)
		return
	}

	a.auditSIEM(r, audit.ActionSIEMTest, message, false)

	data, err := a.siemPageData(r)
	if err != nil {
		a.internalError(w, r, "cannot read the syslog configuration", err)
		return
	}
	data.Notice = message

	SetToast(w, ToastSuccess, message)
	a.RenderPartial(w, r, http.StatusOK, "siem-panel", data)
}

// siemProblem sends the form back with the reason it was refused.
func (a *App) siemProblem(w http.ResponseWriter, r *http.Request,
	rules, problem string, status int) {

	data, err := a.siemPageData(r)
	if err != nil {
		a.internalError(w, r, "cannot read the syslog configuration", err)
		return
	}

	// The submitted rules stay in the form, because the operator has to
	// correct them rather than type them again.
	data.Rules = rules
	data.Problem = problem

	a.RenderPartial(w, r, status, "siem-panel", data)
}

// auditSIEM records a change to the panel's own forwarding.
//
// mirrored asks for the entry to reach the receiver even though the switch it
// just turned off already answers false.
func (a *App) auditSIEM(r *http.Request, action, details string, mirrored bool) {
	actor := a.actor(r)

	entry := audit.Entry{
		UID:       actor.UID,
		Username:  actor.Username,
		Action:    action,
		Details:   details,
		IPAddress: actor.IPAddress,
	}

	if mirrored {
		_ = a.Audit.WriteMirrored(r.Context(), entry)
		return
	}
	_ = a.Audit.Write(r.Context(), entry)
}

// siemMessage turns a refusal into a sentence the form can show.
func siemMessage(ctx context.Context, catalog *i18n.Catalog, err error) string {
	switch {
	case errors.Is(err, siem.ErrRule):
		return capitalise(strings.TrimPrefix(err.Error(), siem.ErrRule.Error()+": ")) + "."
	case errors.Is(err, siem.ErrConfig):
		return capitalise(err.Error()) + "."
	default:
		return userMessage(ctx, catalog, err)
	}
}

func siemStatus(err error) int {
	if errors.Is(err, siem.ErrRule) {
		return http.StatusUnprocessableEntity
	}
	return http.StatusBadRequest
}
