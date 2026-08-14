package web

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"unbound-web/internal/auth"
	"unbound-web/internal/fleet"
	"unbound-web/internal/i18n"
	"unbound-web/internal/logging"
	"unbound-web/internal/server"
	"unbound-web/internal/settings"
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

	// Pending marks a server whose file carries changes its resolver has not
	// loaded. The indicator is per server rather than one for the whole panel,
	// because each server holds its own file.
	Pending bool

	// Records is how many entries the panel last read from that server.
	Records int

	// Failure is the last contact failure as a sentence. The stored value is a
	// class rather than the text of the error, because that text names the
	// remote command and its stderr.
	Failure string

	// HasBackup marks a server the panel holds a previous file for. Without it
	// the restore button would be offered on every row and answer most of them
	// with nothing to restore.
	HasBackup bool
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

	// Rotated marks a key that was just replaced. The panel then says that the
	// server is out of reach until the new line is installed on it, which is
	// not something to leave the operator to work out.
	Rotated bool
}

// testResultData shows the outcome of a connection test.
type testResultData struct {
	Server server.Server
	Result server.TestResult
}

func (a *App) handleServersPage(w http.ResponseWriter, r *http.Request) {
	data, err := a.serversPageData(r)
	if err != nil {
		a.internalError(w, r, "cannot load the servers", err)
		return
	}
	a.Render(w, r, http.StatusOK, "servers", PageData{Title: "nav.servers", Data: data})
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
		a.internalError(w, r, "cannot load the servers", err)
		return
	}
	a.RenderPartial(w, r, http.StatusOK, "server-tables", data)
}

func (a *App) serversPageData(r *http.Request) (serversPageData, error) {
	servers, err := a.Servers.List(r.Context())
	if err != nil {
		return serversPageData{}, err
	}
	groups, err := a.Servers.ListGroups(r.Context())
	if err != nil {
		return serversPageData{}, err
	}

	states, err := a.Records.States(r.Context())
	if err != nil {
		return serversPageData{}, err
	}

	restorable, err := a.Records.Backups(r.Context())
	if err != nil {
		return serversPageData{}, err
	}

	catalog := a.catalog(r)
	byID := map[int64]server.Server{}
	rows := make([]serverRow, 0, len(servers))
	for _, record := range servers {
		byID[record.ID] = record

		state := states[record.ID]
		rows = append(rows, serverRow{
			Server:    record,
			Status:    serverStatus(record),
			Pending:   record.Enabled && state.Pending(),
			Records:   state.RecordCount,
			Failure:   cacheErrorText(catalog, record.LastError),
			HasBackup: restorable[record.ID],
		})
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
		record, err := a.Servers.Get(r.Context(), id)
		if err != nil {
			a.notFoundOrError(w, r, "cannot load the server", err)
			return
		}
		data = serverFormData{Server: record}
	}
	a.RenderPartial(w, r, http.StatusOK, "server-form", data)
}

func (a *App) handleServerCreate(w http.ResponseWriter, r *http.Request) {
	record, err := serverFromForm(r)
	if err != nil {
		a.RenderPartial(w, r, http.StatusUnprocessableEntity, "server-form",
			serverFormData{Server: record, IsNew: true, Problem: err.Error()})
		return
	}

	created, pair, err := a.Servers.Create(r.Context(), a.actor(r), server.CreateInput{
		Server:     record,
		PrivateKey: strings.TrimSpace(r.PostFormValue("private_key")),
	})
	if err != nil {
		a.RenderPartial(w, r, formStatus(err), "server-form",
			serverFormData{Server: record, IsNew: true, Problem: userMessage(r.Context(), a.catalog(r), err)})
		return
	}

	SetToast(w, ToastSuccess, a.catalog(r).Tf("toast.server_added", created.Name))

	// The panel keeps the public key on screen, so the new row arrives through
	// the reload event instead.
	SetTrigger(w, "servers-changed", nil)
	a.RenderPartial(w, r, http.StatusOK, "server-key", keyPanelData{Server: created, Key: pair})
}

func (a *App) handleServerUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := a.pathID(w, r)
	if !ok {
		return
	}

	record, err := serverFromForm(r)
	if err != nil {
		record.ID = id
		a.RenderPartial(w, r, http.StatusUnprocessableEntity, "server-form",
			serverFormData{Server: record, Problem: err.Error()})
		return
	}
	record.ID = id

	if err := a.Servers.Update(r.Context(), a.actor(r), record); err != nil {
		a.RenderPartial(w, r, formStatus(err), "server-form",
			serverFormData{Server: record, Problem: userMessage(r.Context(), a.catalog(r), err)})
		return
	}
	if !record.Enabled {
		a.releaseSourceServer(r.Context(), id)
	}

	SetToast(w, ToastSuccess, a.catalog(r).Tf("toast.server_updated", record.Name))
	a.closePanel(w)
}

func (a *App) handleServerDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := a.pathID(w, r)
	if !ok {
		return
	}

	if err := a.Servers.Delete(r.Context(), a.actor(r), id); err != nil {
		a.notFoundOrError(w, r, "cannot delete the server", err)
		return
	}
	a.releaseSourceServer(r.Context(), id)

	SetToast(w, ToastSuccess, a.catalog(r).T("toast.server_deleted"))
	a.closePanel(w)
}

// releaseSourceServer clears the source setting when it names this server.
//
// A server that is gone or disabled cannot be the reference of a comparison,
// and a dangling identifier would leave the drift page pointing at nothing.
func (a *App) releaseSourceServer(ctx context.Context, id int64) {
	if a.Settings.Values().Int64(settings.SourceServerID) != id {
		return
	}

	if err := a.Settings.Save(ctx, map[string]string{settings.SourceServerID: ""}); err != nil {
		// The server change already happened. The stale identifier is worth
		// reporting but not worth failing the request over, and the drift page
		// treats a source it cannot resolve as no source at all.
		logging.From(ctx).Error("cannot clear the source server setting",
			"server", id, "error", err)
	}
}

func (a *App) handleServerKey(w http.ResponseWriter, r *http.Request) {
	id, ok := a.pathID(w, r)
	if !ok {
		return
	}

	record, err := a.Servers.Get(r.Context(), id)
	if err != nil {
		a.notFoundOrError(w, r, "cannot load the server", err)
		return
	}
	pair, err := a.Servers.PublicKey(r.Context(), id)
	if err != nil {
		a.internalError(w, r, "cannot read the public key", err)
		return
	}
	a.RenderPartial(w, r, http.StatusOK, "server-key", keyPanelData{Server: record, Key: pair})
}

// handleServerRotateKey replaces the key of one server.
//
// The server keeps its record, its group membership and its history. Deleting
// and re-creating it was the only way to re-key it before, and that takes the
// cached records, the state row and the group layout with it.
func (a *App) handleServerRotateKey(w http.ResponseWriter, r *http.Request) {
	id, ok := a.pathID(w, r)
	if !ok {
		return
	}

	record, pair, err := a.Servers.RotateKey(r.Context(), a.actor(r), id)
	if err != nil {
		a.notFoundOrError(w, r, "cannot rotate the key of a server", err)
		return
	}

	SetTrigger(w, "servers-changed", nil)
	SetToast(w, ToastSuccess, a.catalog(r).T("toast.key_rotated"))
	a.RenderPartial(w, r, http.StatusOK, "server-key",
		keyPanelData{Server: record, Key: pair, Rotated: true})
}

// handleServerRestoreFile puts back the file one server carried before the
// last change the panel made to it.
//
// One server at a time, by hand. A change that reached a group is undone by
// pressing this on each member, which is deliberate: the operator sees what
// each one answers rather than firing a second fleet wide write to repair the
// first.
func (a *App) handleServerRestoreFile(w http.ResponseWriter, r *http.Request) {
	id, ok := a.pathID(w, r)
	if !ok {
		return
	}

	result, err := a.Records.RestoreFile(r.Context(), a.actor(r), id)
	if err != nil {
		if errors.Is(err, fleet.ErrNoBackup) {
			SetToast(w, ToastWarning, a.catalog(r).T("toast.no_stored_file"))
			a.closePanel(w)
			return
		}
		a.notFoundOrError(w, r, "cannot restore the file of a server", err)
		return
	}

	catalog := a.catalog(r)
	switch result.Status {
	case fleet.StatusSuccess:
		SetToast(w, ToastSuccess, catalog.Tf("toast.file_restored", result.ServerName))
	case fleet.StatusSkipped:
		SetToast(w, ToastInfo, catalog.Tf("toast.file_not_restored", result.ServerName))
	default:
		// The message names the transport failure, which is the same text the
		// record report shows for a write that could not land.
		SetToast(w, ToastError, catalog.Tf("toast.file_restore_failed", result.ServerName))
	}
	a.closePanel(w)
}

func (a *App) handleServerTest(w http.ResponseWriter, r *http.Request) {
	id, ok := a.pathID(w, r)
	if !ok {
		return
	}

	record, err := a.Servers.Get(r.Context(), id)
	if err != nil {
		a.notFoundOrError(w, r, "cannot load the server", err)
		return
	}

	result, err := a.Servers.TestConnection(r.Context(), a.actor(r), id)
	if err != nil {
		a.internalError(w, r, "cannot run the connection test", err)
		return
	}

	// A first contact is not announced as a failure. The panel is waiting for
	// the operator, and the panel body says so.
	switch {
	case result.OK:
		SetToast(w, ToastSuccess, a.catalog(r).Tf("toast.connection_ok", record.Name))
	case result.HostKeyChanged:
		SetToast(w, ToastError, a.catalog(r).Tf("toast.host_key_changed", record.Name))
	case result.HostKey == nil:
		SetToast(w, ToastError, a.catalog(r).Tf("toast.connection_failed", record.Name))
	}

	// The test records the outcome on the record, so the row behind the panel
	// is now out of date.
	SetTrigger(w, "servers-changed", nil)
	a.RenderPartial(w, r, http.StatusOK, "server-test", testResultData{Server: record, Result: result})
}

func (a *App) handleServerTrust(w http.ResponseWriter, r *http.Request) {
	id, ok := a.pathID(w, r)
	if !ok {
		return
	}

	fingerprint := strings.TrimSpace(r.PostFormValue("fingerprint"))
	if fingerprint == "" {
		a.RenderPartial(w, r, http.StatusUnprocessableEntity, "alert",
			&Alert{Severity: ToastError, Message: "No fingerprint was submitted."})
		return
	}

	if err := a.Servers.TrustHostKey(r.Context(), a.actor(r), id, fingerprint); err != nil {
		a.RenderPartial(w, r, formStatus(err), "alert",
			&Alert{Severity: ToastError, Message: userMessage(r.Context(), a.catalog(r), err)})
		return
	}

	SetToast(w, ToastSuccess, a.catalog(r).T("toast.host_key_approved"))
	a.handleServerTest(w, r)
}

// --- Groups ----------------------------------------------------------------

func (a *App) handleGroupForm(w http.ResponseWriter, r *http.Request) {
	servers, err := a.Servers.List(r.Context())
	if err != nil {
		a.internalError(w, r, "cannot load the servers", err)
		return
	}

	data := groupFormData{Servers: servers, Chosen: map[int64]bool{}, IsNew: true}

	if raw := r.PathValue("id"); raw != "" {
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		group, err := a.Servers.GetGroup(r.Context(), id)
		if err != nil {
			a.notFoundOrError(w, r, "cannot load the group", err)
			return
		}
		data.Group = group
		data.IsNew = false
		for _, memberID := range group.ServerIDs {
			data.Chosen[memberID] = true
		}
	}
	a.RenderPartial(w, r, http.StatusOK, "group-form", data)
}

func (a *App) handleGroupCreate(w http.ResponseWriter, r *http.Request) {
	group := groupFromForm(r)

	created, err := a.Servers.CreateGroup(r.Context(), a.actor(r), group)
	if err != nil {
		a.renderGroupProblem(w, r, group, true, err)
		return
	}

	SetToast(w, ToastSuccess, a.catalog(r).Tf("toast.group_added", created.Name))
	a.closePanel(w)
}

func (a *App) handleGroupUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := a.pathID(w, r)
	if !ok {
		return
	}

	group := groupFromForm(r)
	group.ID = id

	if err := a.Servers.UpdateGroup(r.Context(), a.actor(r), group); err != nil {
		a.renderGroupProblem(w, r, group, false, err)
		return
	}

	SetToast(w, ToastSuccess, a.catalog(r).Tf("toast.group_updated", group.Name))
	a.closePanel(w)
}

func (a *App) handleGroupDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := a.pathID(w, r)
	if !ok {
		return
	}

	if err := a.Servers.DeleteGroup(r.Context(), a.actor(r), id); err != nil {
		a.notFoundOrError(w, r, "cannot delete the group", err)
		return
	}

	SetToast(w, ToastSuccess, a.catalog(r).T("toast.group_deleted"))
	a.closePanel(w)
}

// renderGroupProblem sends the form back with the reason it was refused.
func (a *App) renderGroupProblem(w http.ResponseWriter, r *http.Request,
	group server.Group, isNew bool, cause error) {

	servers, err := a.Servers.List(r.Context())
	if err != nil {
		a.internalError(w, r, "cannot load the servers", err)
		return
	}

	chosen := map[int64]bool{}
	for _, id := range group.ServerIDs {
		chosen[id] = true
	}

	a.RenderPartial(w, r, formStatus(cause), "group-form", groupFormData{
		Group:   group,
		Servers: servers,
		Chosen:  chosen,
		IsNew:   isNew,
		Problem: userMessage(r.Context(), a.catalog(r), cause),
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
// The validation text itself stays in the language of the package that raised
// it. It names a field of a record and travels to the audit trail as well,
// where a machine reads it.
func userMessage(ctx context.Context, catalog *i18n.Catalog, err error) string {
	switch {
	case errors.Is(err, server.ErrValidation):
		return strings.TrimPrefix(err.Error(), "invalid input: ")
	case errors.Is(err, server.ErrNameTaken):
		return catalog.T("error.name_taken")
	case errors.Is(err, store.ErrNotFound):
		return catalog.T("error.not_found")
	case errors.Is(err, transport.ErrHostKeyMismatch):
		return catalog.T("error.host_key_mismatch")
	default:
		logging.From(ctx).Error("server operation failed", "error", err)
		return catalog.T("error.generic")
	}
}

// internalError logs a failure and answers with the reference to its line.
//
// The request travels with it, so the line the operator finds names the same
// request the reader was looking at.
func (a *App) internalError(w http.ResponseWriter, r *http.Request,
	message string, err error) {

	logging.From(r.Context()).Error(message, "error", err)
	serverError(w, r)
}

func (a *App) notFoundOrError(w http.ResponseWriter, r *http.Request,
	message string, err error) {

	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	a.internalError(w, r, message, err)
}
