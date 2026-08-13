package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"unbound-web/internal/fleet"
	"unbound-web/internal/server"
)

// systemPage returns the rendered system page.
func (e *fleetEnv) systemPage(t *testing.T) string {
	t.Helper()

	recorder := e.do(t, httptest.NewRequest(http.MethodGet, "/system", nil), e.cookie)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /system = %d", recorder.Code)
	}
	return recorder.Body.String()
}

func TestTheSystemPageNeedsASession(t *testing.T) {
	env := newTestEnv(t)

	for _, path := range []string{"/system", "/system/status"} {
		recorder := env.do(t, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusSeeOther {
			t.Errorf("GET %s = %d, want a redirect to the login page", path, recorder.Code)
		}
	}
}

func TestAPlainUserMayReadTheSystemPage(t *testing.T) {
	// The page changes nothing and names no credential. An operator who cannot
	// see the state of the fleet cannot report it either.
	env := newTestEnv(t)
	cookie := env.login(t, "dnsuser")

	for _, path := range []string{"/system", "/system/status"} {
		recorder := env.do(t, httptest.NewRequest(http.MethodGet, path, nil), cookie)
		if recorder.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", path, recorder.Code)
		}
	}
}

func TestTheSystemPageOpensNoConnection(t *testing.T) {
	// The whole point of the cache. A fleet of fifty servers would otherwise
	// open fifty sessions every time somebody looks at this page.
	env := newFleetEnv(t)

	before := env.connector.connections()
	env.systemPage(t)
	env.do(t, httptest.NewRequest(http.MethodGet, "/system/status", nil), env.cookie)

	if after := env.connector.connections(); after != before {
		t.Errorf("the page opened %d connections, want 0", after-before)
	}
}

func TestTheSystemPageShowsWhoIsSignedIn(t *testing.T) {
	env := newFleetEnv(t)

	body := env.systemPage(t)
	for _, want := range []string{
		`data-field="username">dnsadmin<`,
		`data-field="uid">1001<`,
		`class="badge bg-label-primary" data-field="role">admin<`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the session card does not carry %s:\n%s", want, body)
		}
	}
}

func TestTheRoleBadgeOfAPlainUserIsNotTheAdminOne(t *testing.T) {
	// The reference interface marks an admin as primary and a plain user as
	// info, and the difference is what a screenshot of a session is read for.
	env := newTestEnv(t)
	cookie := env.login(t, "dnsuser")

	recorder := env.do(t, httptest.NewRequest(http.MethodGet, "/system", nil), cookie)
	body := recorder.Body.String()

	if !strings.Contains(body, `class="badge bg-label-info" data-field="role">user<`) {
		t.Errorf("the plain user is not marked as a user:\n%s", body)
	}
}

func TestThePanelCardNamesTheHostAndTheDatabase(t *testing.T) {
	env := newFleetEnv(t)

	body := env.systemPage(t)
	for _, want := range []string{
		`data-field="hostname">`, `data-field="version">`,
		`data-field="uptime">`, `data-field="db-size">`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the panel card does not carry %s:\n%s", want, body)
		}
	}
	// The database exists, so a size of zero would mean the panel is measuring
	// the wrong path rather than an empty file.
	if strings.Contains(body, `data-field="db-size">0 B<`) {
		t.Error("the panel reports an empty database")
	}
}

func TestTheSyslogCardNamesTheFacilityAndTheFile(t *testing.T) {
	env := newFleetEnv(t)

	body := env.systemPage(t)
	for _, want := range []string{
		`data-field="facility">local6<`,
		`data-field="log-file">`,
		`data-field="rsyslog">`,
		`data-field="forwarding">`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the syslog card does not carry %s:\n%s", want, body)
		}
	}
}

func TestAnUnreachableServerIsShownWithItsError(t *testing.T) {
	env := newFleetEnv(t)

	// dns2 goes quiet, and the refresher records why.
	env.target(2).failReads(errors.New("dial tcp 192.0.2.1:22: connect: no route to host"))
	if _, err := env.records.Refresh(context.Background()); err != nil {
		t.Fatalf("cannot refresh the cache: %v", err)
	}

	body := env.systemPage(t)
	if !strings.Contains(body, `data-field="state">unreachable<`) {
		t.Errorf("the server is not marked as unreachable:\n%s", body)
	}
	if !strings.Contains(body, "no route to host") {
		t.Errorf("the reason is missing:\n%s", body)
	}
	if !strings.Contains(body, "2 of 3 enabled servers answered the last read.") {
		t.Errorf("the summary does not count the failure:\n%s", body)
	}
}

func TestTheStatusFragmentCarriesNoLayout(t *testing.T) {
	// It replaces one card every half minute. Sending the navigation with it
	// would multiply the page by the number of refreshes.
	env := newFleetEnv(t)

	recorder := env.do(t,
		httptest.NewRequest(http.MethodGet, "/system/status", nil), env.cookie)
	body := recorder.Body.String()

	if strings.Contains(body, "<html") || strings.Contains(body, "menu-inner") {
		t.Errorf("the fragment carries the layout:\n%s", body)
	}
	if !strings.Contains(body, `data-field="fleet-summary"`) {
		t.Errorf("the fragment is not the status card:\n%s", body)
	}
}

func TestTheStatusCardCountsRecordsAndChanges(t *testing.T) {
	env := newFleetEnv(t)

	// A change lands on the file and nothing reloads it yet, which is the
	// state the card exists to report.
	env.adminForm(t, http.MethodPost, "/dns/records", env.cookie, groupForm(url.Values{
		"fqdn": {"pending.example.local"}, "type": {"A"}, "value": {"10.0.0.90"},
	}))

	body := env.systemPage(t)
	if count := strings.Count(body, `data-field="pending">unapplied<`); count != 3 {
		t.Errorf("%d servers report an unapplied change, want 3:\n%s", count, body)
	}
	if !strings.Contains(body, `data-field="records">`) {
		t.Errorf("the card does not count the records:\n%s", body)
	}
}

func TestSystemStateReadsTheServerBeforeTheCache(t *testing.T) {
	moment := time.Now()

	cases := []struct {
		name   string
		record server.Server
		state  fleet.State
		want   string
	}{
		{
			name:   "a disabled server is not a failure",
			record: server.Server{Enabled: false, HostKey: "ssh-ed25519 AAAA"},
			want:   systemDisabled,
		},
		{
			name:   "an unapproved host key comes before the failure it causes",
			record: server.Server{Enabled: true},
			want:   systemUntrusted,
		},
		{
			name:   "a server nobody has read yet is unknown rather than down",
			record: server.Server{Enabled: true, HostKey: "ssh-ed25519 AAAA"},
			want:   systemUnknown,
		},
		{
			name:   "a read that failed is unreachable",
			record: server.Server{Enabled: true, HostKey: "ssh-ed25519 AAAA"},
			state:  fleet.State{FetchedAt: &moment},
			want:   systemUnreachable,
		},
		{
			name:   "a machine that answers with a stopped resolver",
			record: server.Server{Enabled: true, HostKey: "ssh-ed25519 AAAA"},
			state:  fleet.State{FetchedAt: &moment, Reachable: true},
			want:   systemUnboundDown,
		},
		{
			name:   "everything answered",
			record: server.Server{Enabled: true, HostKey: "ssh-ed25519 AAAA"},
			state: fleet.State{
				FetchedAt: &moment, Reachable: true, UnboundActive: true},
			want: systemOK,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := systemState(testCase.record, testCase.state); got != testCase.want {
				t.Errorf("state = %q, want %q", got, testCase.want)
			}
		})
	}
}

func TestTheSummaryCountsOnlyTheEnabledServers(t *testing.T) {
	cases := []struct {
		name string
		rows []systemRow
		want string
	}{
		{
			name: "nothing to report",
			want: "No server is enabled.",
		},
		{
			name: "a disabled server is left out of both counts",
			rows: []systemRow{
				{Server: server.Server{Enabled: true}, State: systemOK},
				{Server: server.Server{Enabled: false}, State: systemDisabled},
			},
			want: "All 1 enabled servers answered the last read.",
		},
		{
			name: "one is down",
			rows: []systemRow{
				{Server: server.Server{Enabled: true}, State: systemOK},
				{Server: server.Server{Enabled: true}, State: systemUnreachable},
			},
			want: "1 of 2 enabled servers answered the last read.",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := systemSummary(testCase.rows); got != testCase.want {
				t.Errorf("summary = %q, want %q", got, testCase.want)
			}
		})
	}
}

func TestUptimeKeepsTwoUnits(t *testing.T) {
	cases := []struct {
		since time.Duration
		want  string
	}{
		{since: 200 * time.Millisecond, want: "just started"},
		{since: 42 * time.Second, want: "42s"},
		{since: 3*time.Minute + 7*time.Second, want: "3m 7s"},
		{since: 5*time.Hour + 9*time.Minute, want: "5h 9m"},
		{since: 50*time.Hour + 30*time.Minute, want: "2d 2h"},
	}

	for _, testCase := range cases {
		if got := uptime(testCase.since); got != testCase.want {
			t.Errorf("uptime(%s) = %q, want %q", testCase.since, got, testCase.want)
		}
	}
}

func TestHumanBytesStaysReadable(t *testing.T) {
	cases := []struct {
		size int64
		want string
	}{
		{size: 0, want: "0 B"},
		{size: 512, want: "512 B"},
		{size: 2048, want: "2.0 KB"},
		{size: 5 * 1024 * 1024, want: "5.0 MB"},
		{size: 3 * 1024 * 1024 * 1024, want: "3.0 GB"},
	}

	for _, testCase := range cases {
		if got := humanBytes(testCase.size); got != testCase.want {
			t.Errorf("humanBytes(%d) = %q, want %q", testCase.size, got, testCase.want)
		}
	}
}

func TestTheDatabaseSizeAddsUpTheCompanionFiles(t *testing.T) {
	// SQLite keeps committed data in the write ahead log until the next
	// checkpoint, so a size that leaves it out reads smaller than the disk.
	env := newTestEnv(t)

	size := databaseSize(env.app.Config.DBPath)
	if size <= 0 {
		t.Fatalf("size = %d, want the database on disk", size)
	}
	if databaseSize(env.app.Config.DBPath+".missing") != 0 {
		t.Error("a path that does not exist reports a size")
	}
}
