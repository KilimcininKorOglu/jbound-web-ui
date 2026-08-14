package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// addAgentServer adds a server the panel will reach through an agent.
func (e *testEnv) addAgentServer(t *testing.T, cookie *http.Cookie, name string) *httptest.ResponseRecorder {
	t.Helper()

	return e.adminForm(t, http.MethodPost, "/servers", cookie, url.Values{
		"name":      {name},
		"host":      {name + ".example"},
		"transport": {"agent"},
		"enabled":   {"1"},
	})
}

func TestAnAgentServerIsAddedWithoutAnAccount(t *testing.T) {
	// Nothing logs in, so the form does not ask for one and the panel must not
	// refuse the record for the field it did not show.
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")

	recorder := env.addAgentServer(t, cookie, "dns4")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200:\n%s", recorder.Code, recorder.Body.String())
	}
}

func TestTheTokenIsShownOnceAndNeverAgain(t *testing.T) {
	// The whole of the panel's authority over that resolver is in this string.
	// A page that could re-display it would be a way to collect the
	// credentials of the fleet from a browser.
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")

	recorder := env.addAgentServer(t, cookie, "dns4")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200:\n%s", recorder.Code, recorder.Body.String())
	}

	body := recorder.Body.String()
	if !strings.Contains(body, `data-field="agent-token"`) {
		t.Fatalf("the token panel was not rendered:\n%s", body)
	}

	token := between(t, body, `data-field="agent-token">`, "</pre>")
	if len(token) < 32 {
		t.Fatalf("the token is %d characters: %q", len(token), token)
	}

	// The key page is the one that would hand it out a second time. It refuses
	// rather than failing, because a server with nothing to show is a decision
	// rather than a fault, and a token that happened to parse as a key would
	// otherwise slip through the failure.
	again := env.do(t, httptest.NewRequest(http.MethodGet, "/servers/1/key", nil), cookie)
	if again.Code != http.StatusNotFound {
		t.Errorf("the key page answered %d, want a refusal", again.Code)
	}
	if strings.Contains(again.Body.String(), token) {
		t.Errorf("the key page handed out the token again:\n%s", again.Body.String())
	}
}

func TestNoListingCarriesAnAgentToken(t *testing.T) {
	// The servers page renders every record. A token that reached it would be
	// on the screen of everyone who opens the page and in every proxy log
	// between them and the panel.
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")

	created := env.addAgentServer(t, cookie, "dns4")
	token := between(t, created.Body.String(), `data-field="agent-token">`, "</pre>")

	for _, path := range []string{"/servers", "/dns", "/servers/1/edit"} {
		t.Run(path, func(t *testing.T) {
			recorder := env.do(t, httptest.NewRequest(http.MethodGet, path, nil), cookie)
			if strings.Contains(recorder.Body.String(), token) {
				t.Errorf("%s carries the agent token", path)
			}
		})
	}
}

func TestAnAgentRowSaysHowItIsReached(t *testing.T) {
	// A reader should not have to open the form to find out whether a server
	// is managed over ssh or through an agent. The two behave differently
	// enough that it is the most basic fact about the row.
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")
	env.addServer(t, cookie, "dns1")
	env.addAgentServer(t, cookie, "dns4")

	recorder := env.do(t, httptest.NewRequest(http.MethodGet, "/servers", nil), cookie)
	body := recorder.Body.String()

	if !strings.Contains(body, `data-field="transport"`) {
		t.Errorf("no row says which transport it uses:\n%s", body)
	}
	if !strings.Contains(body, "dns4.example:8443") {
		t.Errorf("the agent row does not show its endpoint:\n%s", body)
	}
	if !strings.Contains(body, "dnsops@dns1.example:22") {
		t.Errorf("the ssh row lost its endpoint:\n%s", body)
	}
	// An agent endpoint with an account in it would name a login nobody makes.
	if strings.Contains(body, "@dns4.example") {
		t.Errorf("the agent row names an account nobody logs in as:\n%s", body)
	}
}

func TestTheTransportCannotBeChangedAfterTheFact(t *testing.T) {
	// The secret that reaches the server is a private key on one path and a
	// bearer token on the other. A record that switched would point at a file
	// of the wrong kind, and the panel would fail on the next connection with
	// something about a key that will not parse.
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")
	env.addServer(t, cookie, "dns1")

	recorder := env.adminForm(t, http.MethodPost, "/servers/1", cookie, url.Values{
		"name":      {"dns1"},
		"host":      {"dns1.example"},
		"transport": {"agent"},
		"ssh_user":  {"dnsops"},
		"enabled":   {"1"},
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d:\n%s", recorder.Code, recorder.Body.String())
	}

	record, err := env.servers.Get(t.Context(), 1)
	if err != nil {
		t.Fatalf("cannot read the server back: %v", err)
	}
	if record.Transport != "ssh" {
		t.Errorf("transport = %q, want the submitted value to have been ignored",
			record.Transport)
	}
}

func TestTheFormOffersOneSetOfFieldsPerTransport(t *testing.T) {
	// The fields an agent server has no use for are marked rather than absent,
	// because the selector switches between the two without a round trip and
	// the content security policy allows no inline script to do it.
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")

	recorder := env.do(t, httptest.NewRequest(http.MethodGet, "/servers/new", nil), cookie)
	body := recorder.Body.String()

	for _, marker := range []string{
		`data-action="transport"`,
		`data-transport="ssh"`,
		`data-transport="agent"`,
		`name="agent_port"`,
	} {
		if !strings.Contains(body, marker) {
			t.Errorf("the form is missing %s:\n%s", marker, body)
		}
	}
}

func TestAnAgentFormHidesTheFieldsTheAgentOwns(t *testing.T) {
	// The records file and every command live on the target. Showing them here
	// would be asking the operator to fill in decisions somebody else already
	// made, and the values would reach nothing.
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")
	env.addAgentServer(t, cookie, "dns4")

	recorder := env.do(t, httptest.NewRequest(http.MethodGet, "/servers/1/edit", nil), cookie)
	body := recorder.Body.String()

	// The block holding the records path is rendered but hidden, so the marker
	// and the hidden attribute have to be on the same element.
	block := between(t, body, `<div class="col-md-8" data-transport="ssh"`, "</div>")
	if !strings.Contains(block, "hidden") {
		t.Errorf("the records path is shown on an agent server:\n%s", block)
	}
}

// between returns what sits between two markers, failing when either is absent.
func between(t *testing.T, body, open, close string) string {
	t.Helper()

	start := strings.Index(body, open)
	if start < 0 {
		t.Fatalf("the response does not contain %q", open)
	}
	rest := body[start+len(open):]

	end := strings.Index(rest, close)
	if end < 0 {
		t.Fatalf("the response does not close %q", open)
	}
	return strings.TrimSpace(rest[:end])
}
