package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// logTable returns the rendered audit table for one query string.
func (e *fleetEnv) logTable(t *testing.T, query string) string {
	t.Helper()

	recorder := e.do(t, httptest.NewRequest(http.MethodGet, "/logs/table?"+query, nil), e.cookie)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /logs/table?%s = %d", query, recorder.Code)
	}
	return recorder.Body.String()
}

// seedLog produces one record change and one reload, so the log holds rows of
// more than one action and more than one server.
func (e *fleetEnv) seedLog(t *testing.T) {
	t.Helper()

	e.adminForm(t, http.MethodPost, "/dns/records", e.cookie, groupForm(url.Values{
		"fqdn": {"logged.example.local"}, "type": {"A"}, "value": {"10.0.0.60"},
	}))
	e.applyRules(t, groupForm(url.Values{}))
}

func TestTheLogPageNeedsASession(t *testing.T) {
	env := newTestEnv(t)

	recorder := env.do(t, httptest.NewRequest(http.MethodGet, "/logs", nil))
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want a redirect to the login page", recorder.Code)
	}
}

func TestAPlainUserMayNotReadTheLog(t *testing.T) {
	// The trail carries every account's sign ins with their source addresses,
	// and the details of a failed login hold the exact string that was typed
	// into the user name box, which is regularly a password.
	env := newTestEnv(t)
	cookie := env.login(t, "dnsuser")

	for _, path := range []string{"/logs", "/logs/table"} {
		recorder := env.do(t, httptest.NewRequest(http.MethodGet, path, nil), cookie)
		if recorder.Code != http.StatusForbidden {
			t.Errorf("GET %s = %d, want 403", path, recorder.Code)
		}
	}
}

func TestTheLogShowsWhoChangedWhatWhere(t *testing.T) {
	env := newFleetEnv(t)
	env.seedLog(t)

	body := env.logTable(t, "")
	for _, want := range []string{
		"dnsadmin", "dns_add", "dns1", "logged.example.local", "192.0.2.1",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the log does not show %q", want)
		}
	}
}

func TestTheNewestEntryComesFirst(t *testing.T) {
	env := newFleetEnv(t)
	env.seedLog(t)

	body := env.logTable(t, "")
	reload := strings.Index(body, "dns_restart")
	added := strings.Index(body, "dns_add")

	if reload < 0 || added < 0 {
		t.Fatalf("the log is missing one of the two actions:\n%s", body)
	}
	if reload > added {
		t.Error("the older entry is listed above the newer one")
	}
}

func TestTheActionFilterMatchesExactly(t *testing.T) {
	env := newFleetEnv(t)
	env.seedLog(t)

	body := env.logTable(t, "action=dns_restart")
	if strings.Contains(body, "dns_add") {
		t.Errorf("the filter let another action through:\n%s", body)
	}
	if !strings.Contains(body, "dns_restart") {
		t.Error("the filter dropped the matching action")
	}
}

func TestTheServerFilterNarrowsToOneMachine(t *testing.T) {
	env := newFleetEnv(t)
	env.seedLog(t)

	body := env.logTable(t, "server_id=1")
	if strings.Contains(body, "dns2") || strings.Contains(body, "dns3") {
		t.Errorf("the filter let another server through:\n%s", body)
	}
	if !strings.Contains(body, "dns1") {
		t.Error("the filter dropped the matching server")
	}
}

func TestTheSearchCoversUserDetailAndAddress(t *testing.T) {
	env := newFleetEnv(t)
	env.seedLog(t)

	for _, search := range []string{"dnsadmin", "logged.example.local", "192.0.2.1"} {
		if body := env.logTable(t, "search="+url.QueryEscape(search)); strings.Contains(
			body, "No entries found.") {
			t.Errorf("the search for %q found nothing", search)
		}
	}

	if body := env.logTable(t, "search=nothing-matches-this"); !strings.Contains(
		body, "No entries found.") {
		t.Errorf("the search matched something it should not:\n%s", body)
	}
}

func TestALikeWildcardIsSearchedLiterally(t *testing.T) {
	// An unescaped wildcard reads as a broken filter rather than as a search.
	env := newFleetEnv(t)
	env.seedLog(t)

	body := env.logTable(t, "search=%25")
	if !strings.Contains(body, "No entries found.") {
		t.Errorf("a percent sign matched every row:\n%s", body)
	}
}

func TestAnActionNobodyWritesFallsBackToEveryRow(t *testing.T) {
	// These are view controls. A stale link is not worth an empty page that
	// reads as an empty log.
	env := newFleetEnv(t)
	env.seedLog(t)

	body := env.logTable(t, "action=not_an_action")
	if strings.Contains(body, "No entries found.") {
		t.Errorf("an unknown action filtered every row away:\n%s", body)
	}
}

func TestTheLogPagesAndSummarises(t *testing.T) {
	env := newFleetEnv(t)
	env.seedLog(t)

	// Eleven entries: three servers added, one group created, three record
	// changes, three reloads and the login itself.
	body := env.logTable(t, "per_page=10&page=1")
	if !strings.Contains(body, "Showing 10 of 11 entries (Page 1/2)") {
		t.Errorf("the summary is wrong:\n%s", body)
	}
	if !strings.Contains(body, "page-link") {
		t.Error("a second page is not offered")
	}

	body = env.logTable(t, "per_page=10&page=2")
	if !strings.Contains(body, "Showing 1 of 11 entries (Page 2/2)") {
		t.Errorf("the second page is wrong:\n%s", body)
	}
}

func TestAPanelActionShowsNoServer(t *testing.T) {
	// A login targets no managed server, and an empty cell would read as a
	// missing value rather than as the panel itself.
	env := newFleetEnv(t)

	body := env.logTable(t, "action=login")
	if !strings.Contains(body, ">panel<") {
		t.Errorf("the row does not say the action was the panel's:\n%s", body)
	}
}
