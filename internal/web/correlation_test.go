package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"jbound/internal/logging"
)

// idPattern reads the identifier out of one structured line.
var idPattern = regexp.MustCompile(logging.Field + `=([0-9a-f]+)`)

// idsIn returns every request identifier the captured log carries.
func idsIn(logged string) []string {
	var ids []string
	for _, match := range idPattern.FindAllStringSubmatch(logged, -1) {
		ids = append(ids, match[1])
	}
	return ids
}

func TestEveryLineOfOneRequestCarriesTheSameIdentifier(t *testing.T) {
	// An error line used to stand on its own: no request, no user, no path.
	// With two operators on one panel there was nothing to attribute it to.
	env := newTestEnv(t)
	cookie := env.adminCookie(t)
	logged := captureLog(t)

	// The table is gone, so the handler logs its failure and the request line
	// follows it. Both belong to the same request.
	if _, err := env.db.Exec("ALTER TABLE servers RENAME TO servers_moved"); err != nil {
		t.Fatalf("cannot take the table away: %v", err)
	}
	recorder := env.do(t, httptest.NewRequest(http.MethodGet, "/servers/table", nil), cookie)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", recorder.Code)
	}

	ids := idsIn(logged.String())
	if len(ids) < 2 {
		t.Fatalf("got %d identified lines, want the failure and the request:\n%s",
			len(ids), logged.String())
	}
	for _, id := range ids {
		if id != ids[0] {
			t.Errorf("the lines of one request carry %q and %q:\n%s",
				ids[0], id, logged.String())
		}
	}

	// The reader gets the same value, which is what turns "it failed" into a
	// line somebody can find.
	if !strings.Contains(recorder.Body.String(), ids[0]) {
		t.Errorf("the answer does not carry the reference:\n%s", recorder.Body.String())
	}
	if got := recorder.Header().Get("X-Request-Id"); got != ids[0] {
		t.Errorf("the header reads %q, want %q", got, ids[0])
	}
}

func TestTwoRequestsAreToldApart(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.adminCookie(t)
	logged := captureLog(t)

	env.do(t, httptest.NewRequest(http.MethodGet, "/system", nil), cookie)
	env.do(t, httptest.NewRequest(http.MethodGet, "/system", nil), cookie)

	ids := idsIn(logged.String())
	if len(ids) != 2 {
		t.Fatalf("got %d identified lines, want one per request:\n%s",
			len(ids), logged.String())
	}
	if ids[0] == ids[1] {
		t.Errorf("both requests were named %q", ids[0])
	}
}

func TestTheRequestLineNamesWhoMadeIt(t *testing.T) {
	// The session is attached further in than the line is written, so this is
	// the part that used to be missing even though the panel knew it.
	env := newTestEnv(t)
	cookie := env.adminCookie(t)

	anonymous := captureLog(t)
	env.do(t, httptest.NewRequest(http.MethodGet, "/", nil))
	if strings.Contains(anonymous.String(), "username=") {
		t.Errorf("the login page named a user:\n%s", anonymous.String())
	}

	signedIn := captureLog(t)
	env.do(t, httptest.NewRequest(http.MethodGet, "/system", nil), cookie)
	if !strings.Contains(signedIn.String(), "username=dnsadmin") {
		t.Errorf("the request line does not name the user:\n%s", signedIn.String())
	}
}

func TestAFailureInsideTheFleetCarriesTheRequestIdentifier(t *testing.T) {
	// The lines worth correlating are written by the package that talks to the
	// servers, not by the one that answers the browser.
	env := newFleetEnv(t)
	env.target(2).setFile("# nothing here\n")
	logged := captureLog(t)

	env.deleteRecord(t, groupForm(url.Values{
		"fqdn": {"www.example.local"}, "type": {"A"}, "value": {"10.0.0.20"},
	}))

	if !strings.Contains(logged.String(), "cannot write a record to a server") {
		t.Fatalf("the fleet logged no failure:\n%s", logged.String())
	}
	for line := range strings.SplitSeq(strings.TrimSpace(logged.String()), "\n") {
		if strings.Contains(line, "cannot write a record to a server") &&
			!strings.Contains(line, logging.Field+"=") {
			t.Errorf("the fleet failure names no request:\n%s", line)
		}
	}
}
