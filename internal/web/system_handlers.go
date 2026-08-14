package web

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"jbound/internal/build"
	"jbound/internal/fleet"
	"jbound/internal/i18n"
	"jbound/internal/server"
	"jbound/internal/transport"
)

// The states a server can be in on the system page.
//
// They are ordered by what an operator acts on first. A host key nobody has
// approved comes before the failure it causes, and a resolver that is down
// comes before anything the cache says about its file.
const (
	systemDisabled    = "disabled"
	systemUntrusted   = "untrusted"
	systemUnknown     = "unknown"
	systemUnreachable = "unreachable"
	systemUnboundDown = "unbound-down"
	systemOK          = "ok"
)

// systemPageData feeds the system page and its status fragment.
type systemPageData struct {
	Session sessionCard
	Panel   panelCard
	Syslog  syslogCard
	Status  systemStatus
}

// sessionCard is who is signed in and since when.
type sessionCard struct {
	Username   string
	UID        int
	Role       string
	StartedAt  time.Time
	LastActive time.Time
}

// panelCard is what the panel runs as.
type panelCard struct {
	Hostname     string
	Version      string
	Uptime       string
	DatabaseSize string
}

// syslogCard is where the panel's own trail goes.
type syslogCard struct {
	Status     string
	Facility   string
	LogFile    string
	Forwarding bool

	// Problem carries the reason the configuration could not be read. The card
	// is still shown, because a panel whose syslog cannot be inspected is
	// exactly when an operator needs to know.
	Problem string
}

// systemStatus is the part of the page that refreshes on its own.
type systemStatus struct {
	Servers []systemRow
	Summary string

	// ShowEndpoints says whether the reader may see where the panel connects.
	// Columns is the width of the table, which follows from it.
	ShowEndpoints bool
	Columns       int
}

// systemRow is one server as the panel last saw it.
//
// The fields are named one by one rather than embedding the server record.
// This page is open to every signed in account, and embedding put every column
// of the record within reach of a template that is not.
//
// CacheError is the last read of the file rather than the last SSH operation,
// and it carries a classified sentence rather than what the remote command
// said, so it names no path and no command.
type systemRow struct {
	Name    string
	Enabled bool

	// Endpoint is where the panel connects, and it is filled for an
	// administrator only. The login name, the host and the port are the non
	// secret half of the panel's credential pair and a ready made target list
	// for the fleet, which is why every other view of them is behind
	// requireAdmin.
	Endpoint string

	State         string
	Records       int
	Pending       bool
	UnboundActive bool
	FetchedAt     *time.Time
	CacheError    string
}

// handleSystemPage renders the read only host information.
//
// Every signed in user reaches it. It changes nothing and names no credential,
// and an operator who cannot see the state of the fleet cannot report it.
func (a *App) handleSystemPage(w http.ResponseWriter, r *http.Request) {
	data, err := a.systemPageData(r)
	if err != nil {
		a.internalError(w, r, "cannot read the system information", err)
		return
	}
	a.Render(w, r, http.StatusOK, "system", PageData{Title: "nav.system_info", Data: data})
}

// handleSystemStatus re-renders the server card, which the page polls.
func (a *App) handleSystemStatus(w http.ResponseWriter, r *http.Request) {
	status, err := a.systemStatus(r)
	if err != nil {
		a.internalError(w, r, "cannot read the fleet status", err)
		return
	}
	a.RenderPartial(w, r, http.StatusOK, "system-status", status)
}

func (a *App) systemPageData(r *http.Request) (systemPageData, error) {
	status, err := a.systemStatus(r)
	if err != nil {
		return systemPageData{}, err
	}

	session, _ := SessionFrom(r.Context())

	return systemPageData{
		Session: sessionCard{
			Username:   session.Username,
			UID:        session.UID,
			Role:       session.Role,
			StartedAt:  session.CreatedAt,
			LastActive: session.LastActive,
		},
		Panel:  a.panelCard(),
		Syslog: a.syslogCard(r),
		Status: status,
	}, nil
}

// systemStatus reads the fleet from the cache.
//
// The page opens no connection. What it shows is what the refresher last saw,
// which is why every row carries the moment it was read.
func (a *App) systemStatus(r *http.Request) (systemStatus, error) {
	catalog := a.catalog(r)

	servers, err := a.Servers.List(r.Context())
	if err != nil {
		return systemStatus{}, err
	}
	states, err := a.Records.States(r.Context())
	if err != nil {
		return systemStatus{}, err
	}

	session, _ := SessionFrom(r.Context())
	admin := session.IsAdmin()

	rows := make([]systemRow, 0, len(servers))
	for _, record := range servers {
		state := states[record.ID]
		row := systemRow{
			Name:          record.Name,
			Enabled:       record.Enabled,
			State:         systemState(record, state),
			Records:       state.RecordCount,
			Pending:       record.Enabled && state.Pending(),
			UnboundActive: state.UnboundActive,
			FetchedAt:     state.FetchedAt,
			CacheError:    cacheErrorText(catalog, state.LastError),
		}
		if admin {
			row.Endpoint = fmt.Sprintf("%s@%s:%d",
				record.SSHUser, record.Host, record.SSHPort)
		}
		rows = append(rows, row)
	}

	// The address column disappears for a reader who may not see it, rather
	// than standing there empty.
	columns := 6
	if admin {
		columns++
	}

	return systemStatus{
		Servers:       rows,
		Summary:       systemSummary(catalog, rows),
		ShowEndpoints: admin,
		Columns:       columns,
	}, nil
}

// cacheErrorText turns a stored failure class into a sentence.
//
// A row written before the panel started storing a class holds the old text.
// It falls back to the unknown sentence, so no remote command line reaches the
// page from an old row either.
func cacheErrorText(catalog *i18n.Catalog, code string) string {
	if code == "" {
		return ""
	}

	switch code {
	case transport.CodeUnreachable, transport.CodeHostKeyUnknown,
		transport.CodeHostKeyMismatch, transport.CodeAuth,
		transport.CodeConflict, transport.CodeCommandFailed,
		transport.CodeRemoteOutput, transport.CodeTimeout,
		transport.CodeCancelled:
		return catalog.T("system.error." + code)
	default:
		return catalog.T("system.error." + transport.CodeUnknown)
	}
}

// systemState classifies one server for the status card.
func systemState(record server.Server, state fleet.State) string {
	switch {
	case !record.Enabled:
		return systemDisabled
	case !record.Trusted():
		return systemUntrusted
	case state.FetchedAt == nil:
		return systemUnknown
	case !state.Reachable:
		return systemUnreachable
	case !state.UnboundActive:
		return systemUnboundDown
	default:
		return systemOK
	}
}

// systemSummary is the sentence above the server table.
func systemSummary(catalog *i18n.Catalog, rows []systemRow) string {
	var enabled, healthy int
	for _, row := range rows {
		if !row.Enabled {
			continue
		}
		enabled++
		if row.State == systemOK {
			healthy++
		}
	}

	switch {
	case enabled == 0:
		return catalog.T("system.summary.none")
	case healthy == enabled:
		return catalog.Tf("system.summary.all", enabled)
	default:
		return catalog.Tf("system.summary.some", healthy, enabled)
	}
}

func (a *App) panelCard() panelCard {
	return panelCard{
		Hostname:     a.Hostname,
		Version:      build.Version,
		Uptime:       uptime(time.Since(a.Started)),
		DatabaseSize: humanBytes(databaseSize(a.Config.DBPath)),
	}
}

func (a *App) syslogCard(r *http.Request) syslogCard {
	settings, err := a.SIEM.Settings(r.Context())
	if err != nil {
		return syslogCard{Status: "unknown", Problem: userMessage(r.Context(), a.catalog(r), err)}
	}

	return syslogCard{
		Status:     settings.Status,
		Facility:   settings.Facility,
		LogFile:    settings.LogFile,
		Forwarding: settings.HasActiveRules,
	}
}

// databaseSize adds up the files SQLite keeps the database in.
//
// The write ahead log holds committed data until the next checkpoint, so a
// size that leaves it out reads smaller than what the disk carries.
func databaseSize(path string) int64 {
	var total int64
	for _, suffix := range []string{"", "-wal", "-shm"} {
		info, err := os.Stat(path + suffix)
		if err != nil {
			// A missing companion file is the normal case rather than a
			// failure, since SQLite creates them on demand.
			if !errors.Is(err, os.ErrNotExist) {
				return 0
			}
			continue
		}
		total += info.Size()
	}
	return total
}

// humanBytes renders a size the way an operator reads one.
func humanBytes(size int64) string {
	const unit = 1024

	if size < unit {
		return fmt.Sprintf("%d B", size)
	}

	value := float64(size)
	for _, name := range []string{"KB", "MB", "GB", "TB"} {
		value /= unit
		if value < unit {
			return fmt.Sprintf("%.1f %s", value, name)
		}
	}
	return fmt.Sprintf("%.1f PB", value/unit)
}

// uptime renders how long the process has been running.
//
// Two units are enough. Seconds next to days say nothing an operator acts on.
func uptime(since time.Duration) string {
	if since < time.Second {
		return "just started"
	}

	days := int(since.Hours()) / 24
	hours := int(since.Hours()) % 24
	minutes := int(since.Minutes()) % 60
	seconds := int(since.Seconds()) % 60

	switch {
	case days > 0:
		return fmt.Sprintf("%dd %dh", days, hours)
	case hours > 0:
		return fmt.Sprintf("%dh %dm", hours, minutes)
	case minutes > 0:
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	default:
		return fmt.Sprintf("%ds", seconds)
	}
}
