package web

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"unbound-web/internal/build"
	"unbound-web/internal/fleet"
	"unbound-web/internal/i18n"
	"unbound-web/internal/server"
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
}

// systemRow is one server as the panel last saw it.
//
// The cache fields are named apart from the ones the server record carries.
// LastError on the record is the last SSH operation, and CacheError is the
// last read of the file, which are two different failures.
type systemRow struct {
	server.Server

	State         string
	Records       int
	Pending       bool
	Reachable     bool
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
		a.internalError(w, "cannot read the system information", err)
		return
	}
	a.Render(w, r, http.StatusOK, "system", PageData{Title: "nav.system_info", Data: data})
}

// handleSystemStatus re-renders the server card, which the page polls.
func (a *App) handleSystemStatus(w http.ResponseWriter, r *http.Request) {
	status, err := a.systemStatus(r)
	if err != nil {
		a.internalError(w, "cannot read the fleet status", err)
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

	rows := make([]systemRow, 0, len(servers))
	for _, record := range servers {
		state := states[record.ID]
		rows = append(rows, systemRow{
			Server:        record,
			State:         systemState(record, state),
			Records:       state.RecordCount,
			Pending:       record.Enabled && state.Pending(),
			Reachable:     state.Reachable,
			UnboundActive: state.UnboundActive,
			FetchedAt:     state.FetchedAt,
			CacheError:    state.LastError,
		})
	}

	return systemStatus{Servers: rows, Summary: systemSummary(catalog, rows)}, nil
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
		return syslogCard{Status: "unknown", Problem: userMessage(a.catalog(r), err)}
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
