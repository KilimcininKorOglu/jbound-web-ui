package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"unbound-web/internal/dnsfile"
	"unbound-web/internal/fleet"
	"unbound-web/internal/i18n"
	"unbound-web/internal/server"
	"unbound-web/internal/siem"
	"unbound-web/internal/store"
	"unbound-web/internal/transport"
)

func TestTheHealthEndpointNeedsNoSession(t *testing.T) {
	// A load balancer has no cookie. A health check behind the login would
	// report the panel as down for as long as it is up.
	env := newTestEnv(t)

	recorder := env.do(t, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if strings.TrimSpace(recorder.Body.String()) != "ok" {
		t.Errorf("body = %q, want ok", recorder.Body.String())
	}
}

func TestTheHealthEndpointReadsTheDatabase(t *testing.T) {
	// A process that is up and a panel that works are two different things. An
	// unreadable database leaves every page failing while the process itself
	// answers perfectly well.
	env := newTestEnv(t)

	var asked bool
	env.health.check = func(ctx context.Context) error {
		asked = true
		if _, ok := ctx.Deadline(); !ok {
			t.Error("the probe runs with no deadline")
		}
		return nil
	}

	if recorder := env.do(t, httptest.NewRequest(http.MethodGet, "/healthz", nil)); recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if !asked {
		t.Error("the health route answered without asking the database")
	}
}

func TestTheHealthEndpointReportsADatabaseThatStoppedAnswering(t *testing.T) {
	env := newTestEnv(t)
	env.health.check = func(context.Context) error {
		return errors.New("attempt to write a readonly database")
	}

	recorder := env.do(t, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", recorder.Code)
	}

	body := recorder.Body.String()
	if strings.TrimSpace(body) != "unavailable" {
		t.Errorf("body = %q, want unavailable", body)
	}
	// The route is the one status surface open without a session, so it says
	// whether the panel serves and nothing about why it does not.
	if strings.Contains(body, "readonly") {
		t.Errorf("the body carries the reason: %q", body)
	}
}

func TestThePanelRefusesToStartWithNoHealthProbe(t *testing.T) {
	// Without a probe the route can only report that a process answered, which
	// is what a monitor reads as a working panel.
	if _, err := NewApp(Deps{}); err == nil {
		t.Fatal("an application with no health probe was built")
	}
}

func TestTheDiffPageCarriesItsControls(t *testing.T) {
	env := newFleetEnv(t)

	recorder := env.do(t, httptest.NewRequest(http.MethodGet, "/diff", nil), env.cookie)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}

	body := recorder.Body.String()
	for _, want := range []string{"diff-controls", "only_mismatches", "resolvers"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page does not carry %s:\n%s", want, body)
		}
	}
}

func TestTheQueryFormOffersTheTarget(t *testing.T) {
	env := newFleetEnv(t)

	recorder := env.do(t,
		httptest.NewRequest(http.MethodGet, "/dns/query", nil), env.cookie)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}

	body := recorder.Body.String()
	for _, want := range []string{`name="domain"`, `name="query_type"`, "resolvers"} {
		if !strings.Contains(body, want) {
			t.Errorf("the form does not carry %s:\n%s", want, body)
		}
	}
}

func TestAKeyIsApprovedOnlyAgainstWhatTheServerOffersNow(t *testing.T) {
	// The fingerprint the operator saw is passed back in, and the key is only
	// stored when the server still offers that same key. Here the server
	// cannot be reached at all, so nothing may be trusted.
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")

	if recorder := env.addServer(t, cookie, "dns1"); recorder.Code != http.StatusOK {
		t.Fatalf("cannot add the server: %d", recorder.Code)
	}

	recorder := env.adminForm(t, http.MethodPost, "/servers/1/trust", cookie,
		url.Values{"fingerprint": {"SHA256:whatever-the-operator-saw"}})
	if recorder.Code == http.StatusOK {
		t.Fatalf("the approval was accepted:\n%s", recorder.Body.String())
	}

	stored, err := env.servers.Get(t.Context(), 1)
	if err != nil {
		t.Fatalf("cannot read the server: %v", err)
	}
	if stored.Trusted() {
		t.Error("the server was trusted without offering a key")
	}
}

func TestAnApprovalWithoutAFingerprintIsRefused(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")

	if recorder := env.addServer(t, cookie, "dns1"); recorder.Code != http.StatusOK {
		t.Fatalf("cannot add the server: %d", recorder.Code)
	}

	recorder := env.adminForm(t, http.MethodPost, "/servers/1/trust", cookie, url.Values{})
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "No fingerprint was submitted.") {
		t.Errorf("the reason is missing:\n%s", recorder.Body.String())
	}
}

func TestTheGroupFormListsTheServersAndTheMembers(t *testing.T) {
	env := newFleetEnv(t)

	recorder := env.do(t,
		httptest.NewRequest(http.MethodGet, "/groups/new", nil), env.cookie)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	for _, want := range []string{"dns1", "dns2", "dns3"} {
		if !strings.Contains(recorder.Body.String(), want) {
			t.Errorf("the form does not offer %s", want)
		}
	}

	// The edit form of the seeded group carries its membership, which is what
	// the operator changes rather than retypes.
	recorder = env.do(t,
		httptest.NewRequest(http.MethodGet, "/groups/1/edit", nil), env.cookie)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if count := strings.Count(recorder.Body.String(), "checked"); count != 3 {
		t.Errorf("%d members are marked, want 3:\n%s", count, recorder.Body.String())
	}
}

func TestAGroupFormWithAnIdentifierThatIsNotOneIsNotFound(t *testing.T) {
	env := newFleetEnv(t)

	recorder := env.do(t,
		httptest.NewRequest(http.MethodGet, "/groups/abc/edit", nil), env.cookie)
	if recorder.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", recorder.Code)
	}
}

func TestDeletingAGroupLeavesTheServersBehind(t *testing.T) {
	// The group is a target the operator built. Removing it may not remove the
	// machines it pointed at.
	env := newFleetEnv(t)

	request := httptest.NewRequest(http.MethodDelete, "/groups/1", nil)
	request.Header.Set("X-CSRF-Token", env.csrfTokenOf(t, env.cookie))
	recorder := env.do(t, request, env.cookie)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200:\n%s", recorder.Code, recorder.Body.String())
	}

	groups, err := env.servers.ListGroups(t.Context())
	if err != nil {
		t.Fatalf("cannot list the groups: %v", err)
	}
	if len(groups) != 0 {
		t.Errorf("%d groups remain, want none", len(groups))
	}

	servers, err := env.servers.List(t.Context())
	if err != nil {
		t.Fatalf("cannot list the servers: %v", err)
	}
	if len(servers) != 3 {
		t.Errorf("%d servers remain, want 3", len(servers))
	}
}

func TestDeletingAGroupThatIsGoneIsNotFound(t *testing.T) {
	env := newFleetEnv(t)

	request := httptest.NewRequest(http.MethodDelete, "/groups/404", nil)
	request.Header.Set("X-CSRF-Token", env.csrfTokenOf(t, env.cookie))
	recorder := env.do(t, request, env.cookie)

	if recorder.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", recorder.Code)
	}
}

func TestAFailureIsReportedWithoutNamingTheInternals(t *testing.T) {
	// The text of an internal fault may name a path or a command the reader
	// has no business seeing.
	cases := []struct {
		name    string
		err     error
		message string
		status  int
	}{
		{
			name:    "a rule the operator broke",
			err:     server.ErrValidation,
			message: "invalid input",
			status:  http.StatusUnprocessableEntity,
		},
		{
			name:    "a name somebody else took",
			err:     server.ErrNameTaken,
			message: "That name is already in use.",
			status:  http.StatusUnprocessableEntity,
		},
		{
			name:    "a row that is gone",
			err:     store.ErrNotFound,
			message: "That record no longer exists.",
			status:  http.StatusNotFound,
		},
		{
			name:    "a server that changed its key",
			err:     transport.ErrHostKeyMismatch,
			message: "The server offers a different host key than the approved one.",
			status:  http.StatusInternalServerError,
		},
		{
			name:    "anything else",
			err:     errors.New("open /data/keys/server-1.key: permission denied"),
			message: "The panel could not complete the request.",
			status:  http.StatusInternalServerError,
		},
	}

	catalogs, err := i18n.Load()
	if err != nil {
		t.Fatalf("cannot load the catalogues: %v", err)
	}
	catalog := catalogs.Catalog(i18n.Default)

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := userMessage(context.Background(), catalog, testCase.err); got != testCase.message {
				t.Errorf("message = %q, want %q", got, testCase.message)
			}
			if got := formStatus(testCase.err); got != testCase.status {
				t.Errorf("status = %d, want %d", got, testCase.status)
			}
		})
	}
}

func TestAServerRowNamesTheReasonItCannotBeUsed(t *testing.T) {
	// An unapproved host key comes before the failure it causes, because it is
	// the reason for the failure and the operator has an action for it.
	moment := time.Now()

	cases := []struct {
		name   string
		record server.Server
		want   string
	}{
		{
			name:   "disabled",
			record: server.Server{HostKey: "ssh-ed25519 AAAA"},
			want:   "disabled",
		},
		{
			name:   "untrusted",
			record: server.Server{Enabled: true, LastError: "connection refused"},
			want:   "untrusted",
		},
		{
			name: "failing",
			record: server.Server{Enabled: true, HostKey: "ssh-ed25519 AAAA",
				LastError: "connection refused", LastSeenAt: &moment},
			want: "failing",
		},
		{
			name:   "untested",
			record: server.Server{Enabled: true, HostKey: "ssh-ed25519 AAAA"},
			want:   "untested",
		},
		{
			name: "ok",
			record: server.Server{Enabled: true, HostKey: "ssh-ed25519 AAAA",
				LastSeenAt: &moment},
			want: "ok",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := serverStatus(testCase.record); got != testCase.want {
				t.Errorf("status = %q, want %q", got, testCase.want)
			}
		})
	}
}

func TestARefusedRecordCarriesItsOwnReason(t *testing.T) {
	// A rejected record and a missing target are the operator's to fix, so the
	// reason travels as it is rather than as a generic failure.
	cases := []struct {
		name    string
		err     error
		message string
		status  int
	}{
		{
			name:    "a record the parser refused",
			err:     fmt.Errorf("%w: the value is not an address", dnsfile.ErrInvalid),
			message: "The value is not an address.",
			status:  http.StatusBadRequest,
		},
		{
			name:    "a target that is not one",
			err:     fmt.Errorf("%w: a change needs a single server or a group", fleet.ErrScope),
			message: "A change needs a single server or a group.",
			status:  http.StatusBadRequest,
		},
		{
			name:    "a server the operator broke",
			err:     server.ErrValidation,
			message: "invalid input",
			status:  http.StatusUnprocessableEntity,
		},
		{
			name:    "a row that is gone",
			err:     store.ErrNotFound,
			message: "That record no longer exists.",
			status:  http.StatusNotFound,
		},
		{
			name:    "anything else",
			err:     errors.New("dial tcp: no route to host"),
			message: "The panel could not complete the request.",
			status:  http.StatusInternalServerError,
		},
	}

	catalogs, err := i18n.Load()
	if err != nil {
		t.Fatalf("cannot load the catalogues: %v", err)
	}
	catalog := catalogs.Catalog(i18n.Default)

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := recordMessage(context.Background(), catalog, testCase.err); got != testCase.message {
				t.Errorf("message = %q, want %q", got, testCase.message)
			}
			if got := dnsStatus(testCase.err); got != testCase.status {
				t.Errorf("status = %d, want %d", got, testCase.status)
			}
		})
	}
}

func TestARefusedRuleIsReportedByItsKind(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		message string
	}{
		{
			name:    "a rule the panel will not write",
			err:     fmt.Errorf("%w: line 1: *.* @@host", siem.ErrRule),
			message: "Line 1: *.* @@host.",
		},
		{
			name:    "a configuration the daemon refused",
			err:     fmt.Errorf("%w: unknown parameter", siem.ErrConfig),
			message: "Rsyslog rejected the configuration: unknown parameter.",
		},
		{
			// A write that failed names the path and the reason, which the
			// reader has no business seeing and cannot act on.
			name:    "anything else",
			err:     errors.New("permission denied"),
			message: "The panel could not complete the request.",
		},
	}

	catalogs, err := i18n.Load()
	if err != nil {
		t.Fatalf("cannot load the catalogues: %v", err)
	}
	catalog := catalogs.Catalog(i18n.Default)

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := siemMessage(context.Background(), catalog, testCase.err); got != testCase.message {
				t.Errorf("message = %q, want %q", got, testCase.message)
			}
		})
	}
}

func TestAPortThatIsNotANumberIsRefusedBeforeTheServiceSeesIt(t *testing.T) {
	form := url.Values{
		"name": {"dns1"}, "host": {"dns1.example"},
		"ssh_user": {"dnsops"}, "ssh_port": {"twenty-two"},
	}
	request := httptest.NewRequest(http.MethodPost, "/servers",
		strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if _, err := serverFromForm(request); err == nil {
		t.Fatal("the form was accepted")
	}
}

func TestTheDefaultsFillTheFieldsTheFormLeftEmpty(t *testing.T) {
	// The form offers the paths of a Debian host as placeholders. A submission
	// that leaves them empty means the operator agreed with them.
	form := url.Values{
		"name": {"dns1"}, "host": {"dns1.example"},
		"ssh_user": {"dnsops"}, "enabled": {"1"},
	}
	request := httptest.NewRequest(http.MethodPost, "/servers",
		strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	record, err := serverFromForm(request)
	if err != nil {
		t.Fatalf("the form was refused: %v", err)
	}
	if record.SSHPort == 0 || record.HostEntriesPath == "" || record.ReloadCmd == "" {
		t.Errorf("the defaults did not fill the record: %+v", record)
	}
	if !record.Enabled {
		t.Error("the server came back disabled")
	}
}

func TestAMemberThatWillNotParseIsNotCounted(t *testing.T) {
	form := url.Values{
		"name":       {"resolvers"},
		"server_ids": {"1", "two", "3"},
	}
	request := httptest.NewRequest(http.MethodPost, "/groups",
		strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	group := groupFromForm(request)
	if len(group.ServerIDs) != 2 {
		t.Errorf("membership = %v, want the two identifiers that are ones", group.ServerIDs)
	}
}

func TestAnIdentifierInThePathIsRefusedBeforeTheStore(t *testing.T) {
	env := newFleetEnv(t)

	for _, path := range []string{"/servers/0/edit", "/servers/-1/edit", "/servers/x/edit"} {
		recorder := env.do(t, httptest.NewRequest(http.MethodGet, path, nil), env.cookie)
		if recorder.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, recorder.Code)
		}
	}
}
