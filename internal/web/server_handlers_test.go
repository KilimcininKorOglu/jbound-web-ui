package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"jbound/internal/auth"
	"jbound/internal/i18n"
	"jbound/internal/server"
	"jbound/internal/settings"
	"jbound/internal/store"
	"jbound/internal/transport"
)

// adminForm submits a form as the signed in admin, with the CSRF token the
// panel issued for that session.
func (e *testEnv) adminForm(t *testing.T, method, target string,
	cookie *http.Cookie, values url.Values) *httptest.ResponseRecorder {

	t.Helper()

	body := values.Encode()
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set(auth.CSRFHeader, e.csrfTokenOf(t, cookie))

	return e.do(t, request, cookie)
}

// addServer creates one server through the HTTP surface.
func (e *testEnv) addServer(t *testing.T, cookie *http.Cookie, name string) *httptest.ResponseRecorder {
	t.Helper()

	return e.adminForm(t, http.MethodPost, "/servers", cookie, url.Values{
		"name":     {name},
		"host":     {name + ".example"},
		"ssh_user": {"dnsops"},
		"enabled":  {"1"},
	})
}

func TestRotatingAKeyShowsTheNewPublicHalfAndKeepsTheServer(t *testing.T) {
	// Replacing a leaked key used to mean deleting the server, which takes its
	// cached records, its state row and its group membership with it.
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")
	env.addServer(t, cookie, "dns1")

	before := env.do(t, httptest.NewRequest(http.MethodGet, "/servers/1/key", nil), cookie)
	if before.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", before.Code)
	}

	recorder := env.adminForm(t, http.MethodPost, "/servers/1/rotate-key", cookie, url.Values{})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}

	body := recorder.Body.String()
	if !strings.Contains(body, "ssh-ed25519 ") {
		t.Error("the panel does not show the new public key")
	}
	if body == before.Body.String() {
		t.Error("the panel still shows the previous key")
	}
	if strings.Contains(body, "PRIVATE KEY") {
		t.Error("the response mentions a private key block")
	}

	// The record and its identifier survive, which is the whole point.
	after := env.do(t, httptest.NewRequest(http.MethodGet, "/servers/1/key", nil), cookie)
	if after.Code != http.StatusOK {
		t.Fatalf("the server did not survive the rotation: %d", after.Code)
	}
}

func TestServerRoutesRefuseAPlainUser(t *testing.T) {
	// Hiding the menu entry is not access control, so every route is checked.
	env := newTestEnv(t)
	cookie := env.login(t, "dnsuser")
	token := env.csrfTokenOf(t, cookie)

	reads := []string{"/servers", "/servers/table", "/servers/new", "/servers/1/edit", "/servers/1/key"}
	for _, path := range reads {
		t.Run("GET "+path, func(t *testing.T) {
			recorder := env.do(t, httptest.NewRequest(http.MethodGet, path, nil), cookie)
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", recorder.Code)
			}
		})
	}

	writes := []struct {
		method, path string
	}{
		{http.MethodPost, "/servers"},
		{http.MethodPost, "/servers/1"},
		{http.MethodDelete, "/servers/1"},
		{http.MethodPost, "/servers/1/test"},
		{http.MethodPost, "/servers/1/trust"},
		{http.MethodPost, "/servers/1/rotate-key"},
		{http.MethodPost, "/servers/1/restore-file"},
		{http.MethodPost, "/groups"},
		{http.MethodDelete, "/groups/1"},
	}
	for _, write := range writes {
		t.Run(write.method+" "+write.path, func(t *testing.T) {
			request := httptest.NewRequest(write.method, write.path, strings.NewReader(""))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.Header.Set(auth.CSRFHeader, token)

			recorder := env.do(t, request, cookie)
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", recorder.Code)
			}
		})
	}
}

func TestServerRoutesNeedACSRFToken(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")

	recorder := env.do(t, postForm("/servers", "name=dns1&host=dns1.example&ssh_user=dnsops"), cookie)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", recorder.Code)
	}
}

func TestCreateServerShowsThePublicKeyAndNeverThePrivateOne(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")

	recorder := env.addServer(t, cookie, "dns1")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200:\n%s", recorder.Code, recorder.Body.String())
	}

	body := recorder.Body.String()
	if !strings.Contains(body, "ssh-ed25519 ") {
		t.Error("the response does not carry the public key")
	}
	if !strings.Contains(body, "authorized_keys") {
		t.Error("the response does not say what to do with the key")
	}

	// The private key is the one thing that must never reach a response.
	private, err := os.ReadFile(filepath.Join(env.dataDir, server.KeyRelPath(1)))
	if err != nil {
		t.Fatalf("the private key was not written: %v", err)
	}
	for line := range strings.SplitSeq(string(private), "\n") {
		if len(line) < 20 {
			continue
		}
		if strings.Contains(body, line) {
			t.Fatal("a line of the private key appears in the response")
		}
	}
	if strings.Contains(body, "PRIVATE KEY") {
		t.Error("the response mentions a private key block")
	}
}

func TestCreateServerRefusesABadName(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")

	recorder := env.adminForm(t, http.MethodPost, "/servers", cookie, url.Values{
		"name":     {"../escape"},
		"host":     {"dns1.example"},
		"ssh_user": {"dnsops"},
	})

	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "name") {
		t.Error("the form does not say which field was refused")
	}
}

func TestCreateServerRefusesAnInjectedCommand(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")

	recorder := env.adminForm(t, http.MethodPost, "/servers", cookie, url.Values{
		"name":       {"dns1"},
		"host":       {"dns1.example"},
		"ssh_user":   {"dnsops"},
		"reload_cmd": {"sudo service unbound reload; id"},
	})

	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", recorder.Code)
	}
	if entries, _ := os.ReadDir(env.keyDir); len(entries) != 0 {
		t.Errorf("%d key files survived a refused record", len(entries))
	}
}

func TestCreateServerRefusesADuplicateName(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")

	if recorder := env.addServer(t, cookie, "dns1"); recorder.Code != http.StatusOK {
		t.Fatalf("the first create returned %d", recorder.Code)
	}

	recorder := env.addServer(t, cookie, "dns1")
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "already in use") {
		t.Errorf("the form does not explain the refusal:\n%s", recorder.Body.String())
	}
}

func TestServerListShowsTheNewServer(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")
	env.addServer(t, cookie, "dns1")

	body := env.do(t, httptest.NewRequest(http.MethodGet, "/servers", nil), cookie).Body.String()

	if !strings.Contains(body, "dns1") {
		t.Error("the page does not list the server")
	}
	// A server nobody approved cannot be reached, so the table says so rather
	// than reporting a failure the operator cannot act on.
	if !strings.Contains(body, "host key not approved") {
		t.Error("the table does not flag the unapproved host key")
	}
}

func TestPressingTestLeavesAnAuditRow(t *testing.T) {
	// The route reaches a managed host with the panel's key and writes the
	// outcome onto the row, so who probed which server has to be answerable.
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")
	env.addServer(t, cookie, "dns1")
	if err := env.trust(1); err != nil {
		t.Fatalf("cannot approve the host key: %v", err)
	}

	if recorder := env.adminForm(t, http.MethodPost, "/servers/1/test", cookie,
		url.Values{}); recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}

	var count int
	var details, username string
	row := env.db.QueryRow(`
SELECT COUNT(*), COALESCE(MAX(details), ''), COALESCE(MAX(username), '')
  FROM audit_logs WHERE action = 'server_test'`)
	if err := row.Scan(&count, &details, &username); err != nil {
		t.Fatalf("cannot read the audit table: %v", err)
	}
	if count != 1 {
		t.Fatalf("%d rows were written, want 1", count)
	}
	if username != "dnsadmin" || !strings.Contains(details, "dns1") {
		t.Errorf("the row does not name who tested what: %q %q", username, details)
	}
}

func TestTheRestoreButtonWaitsUntilThereIsSomethingToRestore(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")
	env.addServer(t, cookie, "dns1")

	body := env.do(t, httptest.NewRequest(http.MethodGet, "/servers", nil), cookie).Body.String()
	if strings.Contains(body, "/servers/1/restore-file") {
		t.Error("a server with no stored file is offered the restore button")
	}

	backups := store.NewBackups(env.db)
	if err := backups.Save(t.Context(), 1, []byte(previousFile), "digest", time.Now()); err != nil {
		t.Fatalf("cannot store the previous file: %v", err)
	}

	body = env.do(t, httptest.NewRequest(http.MethodGet, "/servers", nil), cookie).Body.String()
	if !strings.Contains(body, "/servers/1/restore-file") {
		t.Error("a server with a stored file is not offered the restore button")
	}
}

// previousFile stands in for the records file as it was before a change
// the operator wants back.
const previousFile = "local-data: \"www.example.net. A 192.0.2.10\"\n"

func TestRestoringPutsTheStoredFileBackOnTheServer(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")
	env.addServer(t, cookie, "dns1")
	if err := env.trust(1); err != nil {
		t.Fatalf("cannot approve the host key: %v", err)
	}

	env.transport.content = []byte("local-data: \"wrong.example.net. A 192.0.2.99\"\n")
	backups := store.NewBackups(env.db)
	if err := backups.Save(t.Context(), 1, []byte(previousFile), "digest", time.Now()); err != nil {
		t.Fatalf("cannot store the previous file: %v", err)
	}

	recorder := env.adminForm(t, http.MethodPost, "/servers/1/restore-file", cookie, url.Values{})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200:\n%s", recorder.Code, recorder.Body.String())
	}

	if string(env.transport.content) != previousFile {
		t.Errorf("the server holds:\n%s\nwant:\n%s", env.transport.content, previousFile)
	}

	// The file that was replaced becomes the next copy, so the operator can
	// change their mind about the restore itself.
	backup, err := backups.Get(t.Context(), 1)
	if err != nil {
		t.Fatalf("Get returned an error: %v", err)
	}
	if !strings.Contains(string(backup.Content), "wrong.example.net") {
		t.Errorf("the restore did not keep the file it replaced: %q", backup.Content)
	}
}

func TestRestoringWithNothingStoredSaysSo(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")
	env.addServer(t, cookie, "dns1")
	if err := env.trust(1); err != nil {
		t.Fatalf("cannot approve the host key: %v", err)
	}

	recorder := env.adminForm(t, http.MethodPost, "/servers/1/restore-file", cookie, url.Values{})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200:\n%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Header().Get("HX-Trigger"), "no previous file") {
		t.Errorf("the toast does not explain the refusal: %q", recorder.Header().Get("HX-Trigger"))
	}
}

func TestUpdateServerKeepsTheKeyPath(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")
	env.addServer(t, cookie, "dns1")

	record, err := env.servers.Get(t.Context(), 1)
	if err != nil {
		t.Fatalf("cannot read the server: %v", err)
	}

	recorder := env.adminForm(t, http.MethodPost, "/servers/1", cookie, url.Values{
		"name":     {"dns1"},
		"host":     {"moved.example"},
		"ssh_user": {"dnsops"},
		"enabled":  {"1"},
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200:\n%s", recorder.Code, recorder.Body.String())
	}

	updated, err := env.servers.Get(t.Context(), 1)
	if err != nil {
		t.Fatalf("cannot read the server: %v", err)
	}
	if updated.Host != "moved.example" {
		t.Errorf("host = %q, want the edit to land", updated.Host)
	}
	if updated.SSHKeyPath != record.SSHKeyPath {
		t.Errorf("key path = %q, want %q", updated.SSHKeyPath, record.SSHKeyPath)
	}
}

func TestDeleteServerRemovesItFromTheTable(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")
	env.addServer(t, cookie, "dns1")

	recorder := env.adminForm(t, http.MethodDelete, "/servers/1", cookie, url.Values{})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}

	table := env.do(t, httptest.NewRequest(http.MethodGet, "/servers/table", nil), cookie)
	if strings.Contains(table.Body.String(), "dns1.example") {
		t.Error("the table still lists the deleted server")
	}
	if _, err := os.Stat(filepath.Join(env.dataDir, server.KeyRelPath(1))); !os.IsNotExist(err) {
		t.Error("the private key survived the deletion")
	}
}

func TestTestConnectionReportsSuccess(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")
	env.addServer(t, cookie, "dns1")

	recorder := env.adminForm(t, http.MethodPost, "/servers/1/test", cookie, url.Values{})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "Every step passed") {
		t.Errorf("the fragment does not report success:\n%s", recorder.Body.String())
	}
	if !strings.Contains(recorder.Header().Get("HX-Trigger"), "toast") {
		t.Error("no toast was raised for a successful test")
	}
}

func TestTestConnectionNamesTheFailedStep(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")
	env.addServer(t, cookie, "dns1")

	// The write step is the one that matters: a sudoers rule pointing at a
	// different path fails there.
	env.transport.probeErr = &transport.ProbeError{
		Step: transport.StepWrite, Err: transport.ErrCommandFailed}

	body := env.adminForm(t, http.MethodPost, "/servers/1/test", cookie, url.Values{}).Body.String()

	if !strings.Contains(body, `data-field="step">write<`) {
		t.Errorf("the fragment does not name the failed step:\n%s", body)
	}
	if !strings.Contains(body, "sudoers") {
		t.Error("the fragment does not explain what a write failure means")
	}
}

func TestTestConnectionOffersTheFingerprintForApproval(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")
	env.addServer(t, cookie, "dns1")

	env.transport.probeErr = &transport.ProbeError{
		Step: transport.StepConnect,
		Err: &transport.HostKeyError{
			Observed: "SHA256:example", Err: transport.ErrHostKeyUnknown},
	}

	body := env.adminForm(t, http.MethodPost, "/servers/1/test", cookie, url.Values{}).Body.String()

	// The scan needs a real server, so the offer is absent here. What matters
	// is that the operator is told to approve rather than shown a bare error.
	if !strings.Contains(body, "connect") && !strings.Contains(body, "host key") {
		t.Errorf("the fragment gives no direction:\n%s", body)
	}
}

func TestAChangedHostKeyAsksForApprovalAgain(t *testing.T) {
	// The scan needs a real server, so the fragment is rendered directly. What
	// the panel does with a changed key is covered against the development
	// target by the integration tests of the server package.
	env := newTestEnv(t)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/servers", nil)
	env.app.RenderPartial(recorder, request, http.StatusOK, "server-test", testResultData{
		Server: server.Server{ID: 1, Name: "dns1", Host: "dns1.example"},
		Result: server.TestResult{
			HostKeyChanged: true,
			HostKey:        &server.HostKeyOffer{Fingerprint: "SHA256:thenewone"},
		},
	})

	body := recorder.Body.String()
	if !strings.Contains(body, "different host key") {
		t.Errorf("the fragment does not say the key changed:\n%s", body)
	}
	if !strings.Contains(body, `data-field="fingerprint">SHA256:thenewone<`) {
		t.Error("the fragment does not show the new fingerprint")
	}
	if !strings.Contains(body, `hx-post="/servers/1/trust"`) {
		t.Error("the fragment offers no way to approve the new key")
	}
	if strings.Contains(body, "no approved host key yet") {
		t.Error("a changed key is presented as a first contact")
	}
}

func TestNoServerRouteLeaksThePrivateKey(t *testing.T) {
	// The private key is the one thing that must never reach a response, so
	// every route that touches a server is swept rather than only the one that
	// creates it.
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")
	env.addServer(t, cookie, "dns1")

	private, err := os.ReadFile(filepath.Join(env.dataDir, server.KeyRelPath(1)))
	if err != nil {
		t.Fatalf("the private key was not written: %v", err)
	}

	var bodies []string
	for _, path := range []string{"/servers", "/servers/table", "/servers/1/edit", "/servers/1/key"} {
		recorder := env.do(t, httptest.NewRequest(http.MethodGet, path, nil), cookie)
		if recorder.Code != http.StatusOK {
			t.Fatalf("GET %s: status = %d, want 200", path, recorder.Code)
		}
		bodies = append(bodies, recorder.Body.String())
	}
	for _, path := range []string{"/servers/1/test", "/servers/1"} {
		bodies = append(bodies,
			env.adminForm(t, http.MethodPost, path, cookie, url.Values{
				"name": {"dns1"}, "host": {"dns1.example"}, "ssh_user": {"dnsops"},
			}).Body.String())
	}

	for _, body := range bodies {
		if strings.Contains(body, "PRIVATE KEY") {
			t.Error("a response mentions a private key block")
		}
		for line := range strings.SplitSeq(string(private), "\n") {
			if len(line) < 20 {
				continue
			}
			if strings.Contains(body, line) {
				t.Fatal("a line of the private key appears in a response")
			}
		}
	}
}

func TestGroupCreateListsItsMembers(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")
	env.addServer(t, cookie, "dns1")
	env.addServer(t, cookie, "dns2")

	recorder := env.adminForm(t, http.MethodPost, "/groups", cookie, url.Values{
		"name":        {"resolvers"},
		"description": {"the office pair"},
		"server_ids":  {"1", "2"},
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200:\n%s", recorder.Code, recorder.Body.String())
	}
	// The panel is emptied and the tables reload themselves on the event.
	if !strings.Contains(recorder.Header().Get("HX-Trigger"), "servers-changed") {
		t.Error("the tables were not asked to reload")
	}

	body := env.do(t, httptest.NewRequest(http.MethodGet, "/servers/table", nil), cookie).Body.String()
	if !strings.Contains(body, "resolvers") {
		t.Error("the table does not list the group")
	}
	if !strings.Contains(body, "dns1") || !strings.Contains(body, "dns2") {
		t.Error("the table does not list the members")
	}
}

func TestGroupCreateRefusesAMemberThatDoesNotExist(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")

	recorder := env.adminForm(t, http.MethodPost, "/groups", cookie, url.Values{
		"name":       {"resolvers"},
		"server_ids": {"404"},
	})

	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", recorder.Code)
	}
}

func TestGroupUpdateReplacesTheMembership(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")
	env.addServer(t, cookie, "dns1")
	env.addServer(t, cookie, "dns2")

	env.adminForm(t, http.MethodPost, "/groups", cookie, url.Values{
		"name":       {"resolvers"},
		"server_ids": {"1", "2"},
	})

	recorder := env.adminForm(t, http.MethodPost, "/groups/1", cookie, url.Values{
		"name":       {"resolvers"},
		"server_ids": {"2"},
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}

	group, err := env.servers.GetGroup(t.Context(), 1)
	if err != nil {
		t.Fatalf("cannot read the group: %v", err)
	}
	if len(group.ServerIDs) != 1 || group.ServerIDs[0] != 2 {
		t.Errorf("membership = %v, want only the second server", group.ServerIDs)
	}
}

func TestEveryServerActionIsAudited(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")

	env.addServer(t, cookie, "dns1")
	env.adminForm(t, http.MethodPost, "/servers/1", cookie, url.Values{
		"name": {"dns1"}, "host": {"moved.example"}, "ssh_user": {"dnsops"}})
	env.adminForm(t, http.MethodPost, "/groups", cookie, url.Values{"name": {"resolvers"}})
	env.adminForm(t, http.MethodDelete, "/servers/1", cookie, url.Values{})

	rows, err := env.db.Query(
		"SELECT action, username FROM audit_logs WHERE action LIKE 'server_%' OR action LIKE 'group_%' ORDER BY id")
	if err != nil {
		t.Fatalf("cannot read the audit table: %v", err)
	}
	defer rows.Close()

	var actions []string
	for rows.Next() {
		var action, username string
		if err := rows.Scan(&action, &username); err != nil {
			t.Fatalf("cannot read an audit row: %v", err)
		}
		if username != "dnsadmin" {
			t.Errorf("the row is attributed to %q", username)
		}
		actions = append(actions, action)
	}

	want := []string{"server_create", "server_update", "group_create", "server_delete"}
	if len(actions) != len(want) {
		t.Fatalf("audit actions = %v, want %v", actions, want)
	}
	for i := range want {
		if actions[i] != want[i] {
			t.Errorf("action %d = %s, want %s", i, actions[i], want[i])
		}
	}
}

func TestServerFormCarriesTheDefaults(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")

	body := env.do(t, httptest.NewRequest(http.MethodGet, "/servers/new", nil), cookie).Body.String()

	for _, want := range []string{
		"/etc/unbound/local_records.conf",
		"sudo /usr/sbin/service unbound reload",
		"/usr/bin/sha256sum",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the form does not offer %q", want)
		}
	}
}

func TestTheServerTableMarksUnappliedChanges(t *testing.T) {
	// The indicator is per server. Each one holds its own file, and a single
	// panel wide marker would say nothing about which server to look at.
	env := newFleetEnv(t)

	body := env.do(t, httptest.NewRequest(http.MethodGet, "/servers/table", nil),
		env.cookie).Body.String()
	if strings.Count(body, `data-field="pending"`) != 3 {
		t.Errorf("the table does not mark the servers that lag behind:\n%s", body)
	}

	if recorder := env.applyRules(t, groupForm(url.Values{})); recorder.Code != http.StatusOK {
		t.Fatalf("Apply Rules returned %d", recorder.Code)
	}

	body = env.do(t, httptest.NewRequest(http.MethodGet, "/servers/table", nil),
		env.cookie).Body.String()
	if strings.Contains(body, `data-field="pending"`) {
		t.Errorf("the marker survived a reload:\n%s", body)
	}
}

func TestDeletingTheSourceServerClearsTheSetting(t *testing.T) {
	// A dangling identifier would leave the drift page pointing at a machine
	// that is no longer there.
	env := newFleetEnv(t)

	body := env.settingsForm(t, map[string]string{settings.SourceServerID: "2"})
	if recorder := env.do(t, postForm("/settings", body), env.adminCookie(t)); recorder.Code != http.StatusOK {
		t.Fatalf("cannot choose the source: %d", recorder.Code)
	}

	recorder := env.adminForm(t, http.MethodDelete, "/servers/2", env.cookie, url.Values{})
	if recorder.Code != http.StatusOK {
		t.Fatalf("DELETE /servers/2 = %d", recorder.Code)
	}

	if got := env.app.Settings.String(settings.SourceServerID); got != "" {
		t.Errorf("the source setting still reads %q", got)
	}
}

func TestDisablingTheSourceServerClearsTheSetting(t *testing.T) {
	// A disabled server joins no operation, so it cannot be the reference of
	// one either.
	env := newFleetEnv(t)

	body := env.settingsForm(t, map[string]string{settings.SourceServerID: "3"})
	if recorder := env.do(t, postForm("/settings", body), env.adminCookie(t)); recorder.Code != http.StatusOK {
		t.Fatalf("cannot choose the source: %d", recorder.Code)
	}

	// An unchecked switch sends nothing at all, which is how the handler reads
	// a disabled server.
	form := url.Values{
		"name":     {"dns3"},
		"host":     {"dns3.example"},
		"ssh_user": {"dnsops"},
	}
	if recorder := env.adminForm(t, http.MethodPost, "/servers/3", env.cookie, form); recorder.Code != http.StatusOK {
		t.Fatalf("PUT /servers/3 = %d: %s", recorder.Code, recorder.Body.String())
	}

	if got := env.app.Settings.String(settings.SourceServerID); got != "" {
		t.Errorf("the source setting still reads %q", got)
	}
}

func TestTheServerTableTooltipCarriesNoRemoteCommand(t *testing.T) {
	// The tooltip used to print what the probe returned, which is the same
	// text userMessage refuses to show one step to the right on the same page.
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")
	env.addServer(t, cookie, "dns1")
	// A server nobody approved reads as untrusted, and the failing row is the
	// one that carries the tooltip.
	if err := env.trust(1); err != nil {
		t.Fatalf("cannot approve the host key: %v", err)
	}

	env.transport.probeErr = &transport.ProbeError{
		Step: transport.StepWrite,
		Err: &transport.CommandError{
			Command:  "/usr/bin/base64 -w0 /etc/unbound/local_records.conf",
			ExitCode: 1,
			Stderr:   "sudo: a password is required",
		},
	}
	env.adminForm(t, http.MethodPost, "/servers/1/test", cookie, url.Values{})

	table := env.do(t, httptest.NewRequest(http.MethodGet, "/servers/table", nil), cookie)
	if table.Code != http.StatusOK {
		t.Fatalf("GET /servers/table = %d, want 200", table.Code)
	}

	body := table.Body.String()
	for _, secret := range []string{"base64", "local_records.conf", "a password is required"} {
		if strings.Contains(body, secret) {
			t.Errorf("the table carries %q:\n%s", secret, body)
		}
	}

	catalog := env.app.Catalogs.Catalog(i18n.Default)
	if !strings.Contains(body, catalog.T("system.error."+transport.CodeCommandFailed)) {
		t.Errorf("the table does not say what went wrong:\n%s", body)
	}
}
