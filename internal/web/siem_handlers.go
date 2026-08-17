package web

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"jbound/internal/audit"
	"jbound/internal/logging"
	appsettings "jbound/internal/settings"
	"jbound/internal/siem"
)

// defaultLogLines is what the viewer shows without being asked.
const defaultLogLines = 50

// siemPageData feeds the SIEM page and its fragments.
type siemPageData struct {
	// Forwarding is the panel's own switch. The receiver stays configured either
	// way, so an operator can silence a noisy collector without losing where it
	// is.
	Forwarding bool

	// Receiver is the collector the panel reaches itself, without a syslog
	// daemon on the host and without a privilege for it.
	Receiver receiverData

	// Facility and Tag are what every line is sent with. The page names them
	// because they are what a receiver filters on.
	Facility string
	Tag      string

	Lines   []string
	Problem string
	Notice  string
}

// receiverData is the receiver card.
//
// What the operator configured comes from the settings, which is where it is
// stored. What the connection is doing comes from the sender. Reading the
// configuration off the sender instead would make the card show a receiver of
// off on a panel that was built without one, whatever the settings hold.
type receiverData struct {
	Protocol string
	Host     string
	Port     int

	// Protocols is the choice list, in the order the page offers it.
	Protocols []string

	// Connected, LastError and LastSent are the connection. They stay empty on
	// a panel with no sender, which reads as a receiver nothing has been sent
	// to yet.
	Connected bool
	LastError string
	LastSent  time.Time

	// Pending is how many audit rows the receiver has not been given. It grows
	// while a collector is down and is what tells an operator that the trail is
	// waiting rather than lost.
	Pending int
}

func (a *App) handleSIEMPage(w http.ResponseWriter, r *http.Request) {
	data, err := a.siemPageData(r)
	if err != nil {
		a.internalError(w, r, "cannot read the SIEM settings", err)
		return
	}
	a.Render(w, r, http.StatusOK, "siem", PageData{Title: "nav.siem_config", Data: data})
}

// handleSIEMPanel re-renders the configuration card, which is what a save and
// a test both swap back into the page.
func (a *App) handleSIEMPanel(w http.ResponseWriter, r *http.Request) {
	data, err := a.siemPageData(r)
	if err != nil {
		a.internalError(w, r, "cannot read the SIEM settings", err)
		return
	}
	a.RenderPartial(w, r, http.StatusOK, "siem-panel", data)
}

func (a *App) siemPageData(r *http.Request) (siemPageData, error) {
	lines, err := a.recentEvents(r.Context())
	if err != nil {
		// The viewer is a view. A panel that could not read it still has to show
		// its configuration, which is what an operator fixes it with.
		logging.From(r.Context()).Warn("cannot read the recent events", "error", err)
		lines = nil
	}

	return siemPageData{
		Forwarding: a.Settings.Bool(appsettings.SIEMForwardingEnabled),
		Receiver:   a.receiverData(r.Context()),
		Facility:   siem.FacilityName,
		Tag:        siem.Tag,
		Lines:      lines,
	}, nil
}

// recentEvents renders the newest audit rows as the CEF lines they are sent as.
//
// It reads the trail rather than a log file on disk. The trail is what the panel
// forwards, so this shows what a receiver was given rather than what a syslog
// daemon happened to write locally, and it needs no file for the panel to read
// back.
func (a *App) recentEvents(ctx context.Context) ([]string, error) {
	page, err := a.Audit.List(ctx, audit.Query{PerPage: defaultLogLines})
	if err != nil {
		return nil, err
	}

	// The listing is newest first, which is the end an operator reads.
	lines := make([]string, 0, len(page.Rows))
	for _, row := range page.Rows {
		lines = append(lines, siem.FormatRow(row, a.Hostname))
	}
	return lines, nil
}

// receiverData reads the receiver card off the settings and the sender.
func (a *App) receiverData(ctx context.Context) receiverData {
	data := receiverData{
		Protocols: []string{
			siem.ProtocolOff, siem.ProtocolUDP, siem.ProtocolTCP, siem.ProtocolTLS,
		},
		Protocol: a.Settings.String(appsettings.SIEMProtocol),
		Host:     a.Settings.String(appsettings.SIEMReceiverHost),
		Port:     a.Settings.Int(appsettings.SIEMReceiverPort),
	}

	if a.Receiver != nil {
		state := a.Receiver.State()
		data.Connected = state.Connected
		data.LastError = state.LastError
		data.LastSent = state.LastSent
	}

	if a.Backlog != nil {
		pending, err := a.Backlog.Pending(ctx)
		if err != nil {
			// The count is a view. A page that could not read it still has to
			// show the receiver, which is what an operator changes.
			logging.From(ctx).Warn("cannot count the pending audit rows", "error", err)
		}
		data.Pending = pending
	}
	return data
}

// handleSIEMReceiver stores where the panel sends its own trail.
//
// The three values live in the settings table, where the settings page also
// offers them. They are here as well because a receiver that is refusing
// connections is read about on this page, and that is where it gets corrected.
func (a *App) handleSIEMReceiver(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.siemProblem(w, r, a.catalog(r).T("error.form_unreadable"), http.StatusBadRequest)
		return
	}

	submitted := map[string]string{
		appsettings.SIEMProtocol:     strings.TrimSpace(r.PostFormValue("protocol")),
		appsettings.SIEMReceiverHost: strings.TrimSpace(r.PostFormValue("receiver_host")),
		appsettings.SIEMReceiverPort: strings.TrimSpace(r.PostFormValue("receiver_port")),
	}

	if err := a.Settings.Save(r.Context(), submitted); err != nil {
		if refusal, ok := errors.AsType[*appsettings.Refusal](err); ok {
			// The operator typed it, so the card comes back with the reason
			// rather than a server error nobody can act on.
			a.siemProblem(w, r,
				capitalise(refusal.Error())+".", http.StatusUnprocessableEntity)
			return
		}
		a.internalError(w, r, "cannot store the receiver", err)
		return
	}

	a.auditSIEM(r, audit.ActionSIEMConfig,
		"SIEM receiver set to "+describeReceiver(submitted))

	// A receiver that has just been named has a backlog of nothing, but one
	// that was down while it was corrected has rows waiting. Waking the queue
	// here is what starts them moving before the next audit entry.
	if a.Backlog != nil {
		a.Backlog.Notify()
	}

	SetToast(w, ToastSuccess, a.catalog(r).T("toast.receiver_saved"))
	a.handleSIEMPanel(w, r)
}

// describeReceiver renders the change for the audit trail. The text stays in
// English, because the same sentence reaches the SIEM.
func describeReceiver(submitted map[string]string) string {
	protocol := submitted[appsettings.SIEMProtocol]
	if protocol == siem.ProtocolOff {
		return "off"
	}
	return protocol + " " + submitted[appsettings.SIEMReceiverHost] +
		":" + submitted[appsettings.SIEMReceiverPort]
}

// handleSIEMForwarding turns the mirror on or off.
//
// It writes the same setting the settings page holds, because a switch next to
// the receiver is where an operator looks for it while the receiver is the thing
// going wrong.
func (a *App) handleSIEMForwarding(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.siemProblem(w, r, a.catalog(r).T("error.form_unreadable"), http.StatusBadRequest)
		return
	}
	enabled := r.PostForm.Has("forwarding")

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
	a.auditSIEM(r, audit.ActionSIEMConfig, "SIEM forwarding "+state)

	catalog := a.catalog(r)
	SetToast(w, ToastSuccess, catalog.Tf("toast.forwarding_state",
		catalog.T("toast.forwarding_"+state)))

	a.handleSIEMPanel(w, r)
}

// handleSIEMTest sends the test events.
func (a *App) handleSIEMTest(w http.ResponseWriter, r *http.Request) {
	if a.Receiver == nil || !a.Receiver.Configured() {
		// Nothing to test. The operator names a receiver first, and saying so
		// is more use than a failure from a socket that was never opened.
		a.siemProblem(w, r, a.catalog(r).T("siem.test_needs_receiver"),
			http.StatusUnprocessableEntity)
		return
	}

	actor := a.actor(r)
	message, err := siem.SendTestEvents(a.Receiver, a.Hostname, audit.Entry{
		UID: actor.UID, Username: actor.Username, IPAddress: actor.IPAddress})
	if err != nil {
		SetToast(w, ToastError, userMessage(r.Context(), a.catalog(r), err))
		a.internalError(w, r, "cannot send the test events", err)
		return
	}

	a.auditSIEM(r, audit.ActionSIEMTest, message)

	data, err := a.siemPageData(r)
	if err != nil {
		a.internalError(w, r, "cannot read the SIEM settings", err)
		return
	}
	data.Notice = message

	SetToast(w, ToastSuccess, message)
	a.RenderPartial(w, r, http.StatusOK, "siem-panel", data)
}

// siemProblem sends the card back with the reason it was refused.
func (a *App) siemProblem(w http.ResponseWriter, r *http.Request,
	problem string, status int) {

	data, err := a.siemPageData(r)
	if err != nil {
		a.internalError(w, r, "cannot read the SIEM settings", err)
		return
	}
	data.Problem = problem

	a.RenderPartial(w, r, status, "siem-panel", data)
}

// auditSIEM records a change to the panel's own forwarding.
//
// The entry that turns the mirror off still reaches the receiver. The queue
// forwards this action whatever the switch says, because everything after that
// entry is silence rather than quiet.
func (a *App) auditSIEM(r *http.Request, action, details string) {
	actor := a.actor(r)

	entry := audit.Entry{
		UID:       actor.UID,
		Username:  actor.Username,
		Action:    action,
		Details:   details,
		IPAddress: actor.IPAddress,
	}

	_ = a.Audit.Write(r.Context(), entry)
}
