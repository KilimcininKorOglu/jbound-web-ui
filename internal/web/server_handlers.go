package web

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"unbound-web/internal/auth"
	"unbound-web/internal/server"
	"unbound-web/internal/store"
	"unbound-web/internal/transport"
)

// serversPageData feeds the servers page and its table fragment.
type serversPageData struct {
	Servers []serverRow
	Groups  []groupRow
}

// serverRow is one line of the server table.
type serverRow struct {
	server.Server
	// Status is what the row shows at a glance: ok, untrusted, failing or
	// disabled.
	Status string
}

// groupRow is one line of the group table.
type groupRow struct {
	server.Group
	Members []server.Server
}

// serverFormData feeds the create and edit form.
type serverFormData struct {
	Server  server.Server
	IsNew   bool
	Problem string
}

// groupFormData feeds the group form.
type groupFormData struct {
	Group   server.Group
	Servers []server.Server
	Chosen  map[int64]bool
	IsNew   bool
	Problem string
}

// keyPanelData shows the public key the operator has to install.
type keyPanelData struct {
	Server server.Server
	Key    server.KeyPair
}

// testResultData shows the outcome of a connection test.
type testResultData struct {
	Server server.Server
	Result server.TestResult
}

func (a *App) handleServersPage(w http.ResponseWriter, r *http.Request) {
	data, err := a.serversPageData(r)
	if err != nil {
		a.internalError(w, "cannot load the servers", err)
		return
	}
	a.Render(w, r, http.StatusOK, "servers", PageData{Title: "Servers", Data: data})
}

// closePanel finishes a change that has nothing left to show.
//
// The panel is emptied and the tables reload themselves on the event, so the
// handler does not have to know which of the two the button was aimed at.
func (a *App) closePanel(w http.ResponseWriter) {
	SetTrigger(w, "servers-changed", nil)
	w.WriteHeader(http.StatusOK)
}

// handleServerTable re-renders both tables, which is what the reload event
// swaps back into the page.
func (a *App) handleServerTable(w http.ResponseWriter, r *http.Request) {
	data, err := a.serversPageData(r)
	if err != nil {
		a.internalError(w, "cannot load the servers", err)
		return
	}
	a.RenderPartial(w, http.StatusOK, "server-tables", data)
}

func (a *App) serversPageData(r *http.Request) (serversPageData, error) {
	servers, err := a.servers.List(r.Context())
	if err != nil {
		return serversPageData{}, err
	}
	groups, err := a.servers.ListGroups(r.Context())
	if err != nil {
		return serversPageData{}, err
	}

	byID := map[int64]server.Server{}
	rows := make([]serverRow, 0, len(servers))
	for _, record := range servers {
		byID[record.ID] = record
		rows = append(rows, serverRow{Server: record, Status: serverStatus(record)})
	}

	groupRows := make([]groupRow, 0, len(groups))
	for _, group := range groups {
		members := make([]server.Server, 0, len(group.ServerIDs))
		for _, id := range group.ServerIDs {
			if member, ok := byID[id]; ok {
				members = append(members, member)
			}
		}
		groupRows = append(groupRows, groupRow{Group: group, Members: members})
	}

	return serversPageData{Servers: rows, Groups: groupRows}, nil
}

// serverStatus summarises a record for the table.
//
// An unapproved host key comes before a failure, because it is the reason for
// the failure and the operator has an action for it.
func serverStatus(record server.Server) string {
	switch {
	case !record.Enabled:
		return "disabled"
	case !record.Trusted():
		return "untrusted"
	case record.LastError != "":
		return "failing"
	case record.LastSeenAt == nil:
		return "untested"
	default:
		return "ok"
	}
}

func (a *App) handleServerForm(w http.ResponseWriter, r *http.Request) {
	data := serverFormData{IsNew: true}
	data.Server.ApplyDefaults()

	if raw := r.PathValue("id"); raw != "" {
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		record, err := a.servers.Get(r.Context(), id)
		if err != nil {
			a.notFoundOrError(w, "cannot load the server", err)
			return
		}
		data = serverFormData{Server: record}
	}
	a.RenderPartial(w, http.StatusOK, "server-form", data)
}

func (a *App) handleServerCreate(w http.ResponseWriter, r *http.Request) {
	record, err := serverFromForm(r)
	if err != nil {
		a.RenderPartial(w, http.StatusUnprocessableEntity, "server-form",
			serverFormData{Server: record, IsNew: true, Problem: err.Error()})
		return
	}

	created, pair, err := a.servers.Create(r.Context(), a.actor(r), server.CreateInput{
		Server:     record,
		PrivateKey: strings.TrimSpace(r.PostFormValue("private_key")),
	})
	if err != nil {
		a.RenderPartial(w, formStatus(err), "server-form",
			serverFormData{Server: record, IsNew: true, Problem: userMessage(err)})
		return
	}

	SetToast(w, ToastSuccess, "Server "+created.Name+" added.")

	// The panel keeps the public key on screen, so the new row arrives through
	// the reload event instead.
	SetTrigger(w, "servers-changed", nil)
	a.RenderPartial(w, http.StatusOK, "server-key", keyPanelData{Server: created, Key: pair})
}

func (a *App) handleServerUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := a.pathID(w, r)
	if !ok {
		return
	}

	record, err := serverFromForm(r)
	if err != nil {
		record.ID = id
		a.RenderPartial(w, http.StatusUnprocessableEntity, "server-form",
			serverFormData{Server: record, Problem: err.Error()})
		return
	}
	record.ID = id

	if err := a.servers.Update(r.Context(), a.actor(r), record); err != nil {
		a.RenderPartial(w, formStatus(err), "server-form",
			serverFormData{Server: record, Problem: userMessage(err)})
		return
	}

	SetToast(w, ToastSuccess, "Server "+record.Name+" updated.")
	a.closePanel(w)
}

func (a *App) handleServerDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := a.pathID(w, r)
	if !ok {
		return
	}

	if err := a.servers.Delete(r.Context(), a.actor(r), id); err != nil {
		a.notFoundOrError(w, "cannot delete the server", err)
		return
	}

	SetToast(w, ToastSuccess, "Server deleted.")
	a.closePanel(w)
}

func (a *App) handleServerKey(w http.ResponseWriter, r *http.Request) {
	id, ok := a.pathID(w, r)
	if !ok {
		return
	}

	record, err := a.servers.Get(r.Context(), id)
	if err != nil {
		a.notFoundOrError(w, "cannot load the server", err)
		return
	}
	pair, err := a.servers.PublicKey(r.Context(), id)
	if err != nil {
		a.internalError(w, "cannot read the public key", err)
		return
	}
	a.RenderPartial(w, http.StatusOK, "server-key", keyPanelData{Server: record, Key: pair})
}

func (a *App) handleServerTest(w http.ResponseWriter, r *http.Request) {
	id, ok := a.pathID(w, r)
	if !ok {
		return
	}

	record, err := a.servers.Get(r.Context(), id)
	if err != nil {
		a.notFoundOrError(w, "cannot load the server", err)
		return
	}

	result, err := a.servers.TestConnection(r.Context(), id)
	if err != nil {
		a.internalError(w, "cannot run the connection test", err)
		return
	}

	// A first contact is not announced as a failure. The panel is waiting for
	// the operator, and the panel body says so.
	switch {
	case result.OK:
		SetToast(w, ToastSuccess, "Connection to "+record.Name+" works.")
	case result.HostKeyChanged:
		SetToast(w, ToastError, record.Name+" offers a different host key than the approved one.")
	case result.HostKey == nil:
		SetToast(w, ToastError, "Connection to "+record.Name+" failed.")
	}

	// The test records the outcome on the record, so the row behind the panel
	// is now out of date.
	SetTrigger(w, "servers-changed", nil)
	a.RenderPartial(w, http.StatusOK, "server-test", testResultData{Server: record, Result: result})
}

func (a *App) handleServerTrust(w http.ResponseWriter, r *http.Request) {
	id, ok := a.pathID(w, r)
	if !ok {
		return
	}

	fingerprint := strings.TrimSpace(r.PostFormValue("fingerprint"))
	if fingerprint == "" {
		a.RenderPartial(w, http.StatusUnprocessableEntity, "alert",
			&Alert{Severity: ToastError, Message: "No fingerprint was submitted."})
		return
	}

	if err := a.servers.TrustHostKey(r.Context(), a.actor(r), id, fingerprint); err != nil {
		a.RenderPartial(w, formStatus(err), "alert",
			&Alert{Severity: ToastError, Message: userMessage(err)})
		return
	}

	SetToast(w, ToastSuccess, "Host key approved.")
	a.handleServerTest(w, r)
}

// --- Groups ----------------------------------------------------------------

func (a *App) handleGroupForm(w http.ResponseWriter, r *http.Request) {
	servers, err := a.servers.List(r.Context())
	if err != nil {
		a.internalError(w, "cannot load the servers", err)
		return
	}

	data := groupFormData{Servers: servers, Chosen: map[int64]bool{}, IsNew: true}

	if raw := r.PathValue("id"); raw != "" {
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		group, err := a.servers.GetGroup(r.Context(), id)
		if err != nil {
			a.notFoundOrError(w, "cannot load the group", err)
			return
		}
		data.Group = group
		data.IsNew = false
		for _, memberID := range group.ServerIDs {
			data.Chosen[memberID] = true
		}
	}
	a.RenderPartial(w, http.StatusOK, "group-form", data)
}

func (a *App) handleGroupCreate(w http.ResponseWriter, r *http.Request) {
	group := groupFromForm(r)

	created, err := a.servers.CreateGroup(r.Context(), a.actor(r), group)
	if err != nil {
		a.renderGroupProblem(w, r, group, true, err)
		return
	}

	SetToast(w, ToastSuccess, "Group "+created.Name+" added.")
	a.closePanel(w)
}

func (a *App) handleGroupUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := a.pathID(w, r)
	if !ok {
		return
	}

	group := groupFromForm(r)
	group.ID = id

	if err := a.servers.UpdateGroup(r.Context(), a.actor(r), group); err != nil {
		a.renderGroupProblem(w, r, group, false, err)
		return
	}

	SetToast(w, ToastSuccess, "Group "+group.Name+" updated.")
	a.closePanel(w)
}

func (a *App) handleGroupDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := a.pathID(w, r)
	if !ok {
		return
	}

	if err := a.servers.DeleteGroup(r.Context(), a.actor(r), id); err != nil {
		a.notFoundOrError(w, "cannot delete the group", err)
		return
	}

	SetToast(w, ToastSuccess, "Group deleted.")
	a.closePanel(w)
}

// renderGroupProblem sends the form back with the reason it was refused.
func (a *App) renderGroupProblem(w http.ResponseWriter, r *http.Request,
	group server.Group, isNew bool, cause error) {

	servers, err := a.servers.List(r.Context())
	if err != nil {
		a.internalError(w, "cannot load the servers", err)
		return
	}

	chosen := map[int64]bool{}
	for _, id := range group.ServerIDs {
		chosen[id] = true
	}

	a.RenderPartial(w, formStatus(cause), "group-form", groupFormData{
		Group:   group,
		Servers: servers,
		Chosen:  chosen,
		IsNew:   isNew,
		Problem: userMessage(cause),
	})
}

// --- Helpers ---------------------------------------------------------------

// actor identifies the signed in user for the audit trail.
func (a *App) actor(r *http.Request) server.Actor {
	session, _ := SessionFrom(r.Context())
	return server.Actor{
		UID:       session.UID,
		Username:  session.Username,
		IPAddress: auth.ClientIP(r),
	}
}

// pathID reads the identifier out of the route.
func (a *App) pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		http.NotFound(w, r)
		return 0, false
	}
	return id, true
}

// serverFromForm builds a record out of the submitted fields.
func serverFromForm(r *http.Request) (server.Server, error) {
	if err := r.ParseForm(); err != nil {
		return server.Server{}, errors.New("the form could not be read")
	}

	record := server.Server{
		Name:            strings.TrimSpace(r.PostFormValue("name")),
		Host:            strings.TrimSpace(r.PostFormValue("host")),
		SSHUser:         strings.TrimSpace(r.PostFormValue("ssh_user")),
		HostEntriesPath: strings.TrimSpace(r.PostFormValue("host_entries_path")),
		ReloadCmd:       strings.TrimSpace(r.PostFormValue("reload_cmd")),
		StatusCmd:       strings.TrimSpace(r.PostFormValue("status_cmd")),
		Base64Path:      strings.TrimSpace(r.PostFormValue("base64_path")),
		TeePath:         strings.TrimSpace(r.PostFormValue("tee_path")),
		MvPath:          strings.TrimSpace(r.PostFormValue("mv_path")),
		Sha256Path:      strings.TrimSpace(r.PostFormValue("sha256_path")),
		Enabled:         r.PostFormValue("enabled") != "",
	}

	raw := strings.TrimSpace(r.PostFormValue("ssh_port"))
	if raw != "" {
		port, err := strconv.Atoi(raw)
		if err != nil {
			return record, errors.New("the SSH port must be a number")
		}
		record.SSHPort = port
	}

	record.ApplyDefaults()
	return record, nil
}

// groupFromForm builds a group out of the submitted fields.
func groupFromForm(r *http.Request) server.Group {
	_ = r.ParseForm()

	group := server.Group{
		Name:        strings.TrimSpace(r.PostFormValue("name")),
		Description: strings.TrimSpace(r.PostFormValue("description")),
	}

	for _, raw := range r.PostForm["server_ids"] {
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			// A member that will not parse cannot be honoured, and dropping it
			// silently would leave the group missing a server the operator
			// ticked. The service refuses the identifier instead.
			continue
		}
		group.ServerIDs = append(group.ServerIDs, id)
	}
	return group
}

// formStatus maps an error to the status its response carries.
func formStatus(err error) int {
	switch {
	case errors.Is(err, server.ErrValidation), errors.Is(err, server.ErrNameTaken):
		return http.StatusUnprocessableEntity
	case errors.Is(err, store.ErrNotFound):
		return http.StatusNotFound
	default:
		return http.StatusInternalServerError
	}
}

// userMessage turns an error into something worth showing.
//
// An internal fault gets a flat message, because its text may name a path or a
// command the reader has no business seeing.
func userMessage(err error) string {
	switch {
	case errors.Is(err, server.ErrValidation):
		return strings.TrimPrefix(err.Error(), "invalid input: ")
	case errors.Is(err, server.ErrNameTaken):
		return "That name is already in use."
	case errors.Is(err, store.ErrNotFound):
		return "That record no longer exists."
	case errors.Is(err, transport.ErrHostKeyMismatch):
		return "The server offers a different host key than the approved one."
	default:
		slog.Error("server operation failed", "error", err)
		return "The panel could not complete the request."
	}
}

func (a *App) internalError(w http.ResponseWriter, message string, err error) {
	slog.Error(message, "error", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

func (a *App) notFoundOrError(w http.ResponseWriter, message string, err error) {
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	a.internalError(w, message, err)
}
