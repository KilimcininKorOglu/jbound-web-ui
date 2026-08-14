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

	"unbound-web/internal/auth"
	"unbound-web/internal/dnsfile"
	"unbound-web/internal/fleet"
	"unbound-web/internal/server"
	"unbound-web/internal/transport"
)

// seedFile is what a managed server holds before the panel touches it.
const seedFile = `# managed by the panel
local-data: "www.example.local. A 10.0.0.20"
local-data: "mail.example.local. MX 10 mx1.example.local"
`

// fleetEnv is a panel with three approved servers in one group, each holding
// the same file.
type fleetEnv struct {
	*testEnv
	cookie *http.Cookie
}

func newFleetEnv(t *testing.T) *fleetEnv {
	t.Helper()
	ctx := context.Background()

	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")

	for i := 1; i <= 3; i++ {
		name := fmt.Sprintf("dns%d", i)
		if recorder := env.addServer(t, cookie, name); recorder.Code != http.StatusOK {
			t.Fatalf("cannot add %s: %d", name, recorder.Code)
		}
		// A refresh reaches out, and an unapproved server is refused before it
		// is reached, so the key is approved the way the operator would.
		if err := env.trust(int64(i)); err != nil {
			t.Fatalf("cannot approve %s: %v", name, err)
		}
		env.target(int64(i)).setFile(seedFile)
	}

	group, err := env.servers.CreateGroup(ctx, server.Actor{UID: 1001, Username: "dnsadmin"},
		server.Group{Name: "resolvers", ServerIDs: []int64{1, 2, 3}})
	if err != nil {
		t.Fatalf("cannot create the group: %v", err)
	}
	if group.ID != 1 {
		t.Fatalf("group id = %d, want 1", group.ID)
	}

	if _, err := env.records.Refresh(ctx); err != nil {
		t.Fatalf("cannot fill the cache: %v", err)
	}
	return &fleetEnv{testEnv: env, cookie: cookie}
}

// trust approves a host key without going through the scan, which needs a real
// server to offer one.
func (e *testEnv) trust(id int64) error {
	return e.serverDB.SetHostKey(context.Background(), id, "ssh-ed25519 AAAAapproved")
}

// groupForm is the target every record change in these tests uses.
func groupForm(values url.Values) url.Values {
	values.Set("scope", "group")
	values.Set("group_id", "1")
	return values
}

// deleteRecord submits a delete the way htmx does, with the fields in the
// query string rather than in the body.
func (e *fleetEnv) deleteRecord(t *testing.T, values url.Values) *httptest.ResponseRecorder {
	t.Helper()

	request := httptest.NewRequest(http.MethodDelete, "/dns/records?"+values.Encode(), nil)
	request.Header.Set(auth.CSRFHeader, e.csrfTokenOf(t, e.cookie))
	return e.do(t, request, e.cookie)
}

// table returns the rendered record table for one query string.
func (e *fleetEnv) table(t *testing.T, query string) string {
	t.Helper()

	recorder := e.do(t, httptest.NewRequest(http.MethodGet, "/dns/records?"+query, nil), e.cookie)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /dns/records?%s = %d", query, recorder.Code)
	}
	return recorder.Body.String()
}

func TestRecordRoutesNeedASession(t *testing.T) {
	env := newTestEnv(t)

	for _, path := range []string{"/dns", "/dns/records", "/dns/records/new"} {
		recorder := env.do(t, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusSeeOther {
			t.Errorf("GET %s = %d, want a redirect to the login page", path, recorder.Code)
		}
	}
}

func TestRecordChangesNeedACSRFToken(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")

	recorder := env.do(t, postForm("/dns/records", "fqdn=a.example.net&type=A&value=192.0.2.1"), cookie)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", recorder.Code)
	}
}

func TestAPlainUserMayManageRecords(t *testing.T) {
	// Records are the everyday work. Which machines they land on is admin
	// territory, and that is guarded separately.
	env := newTestEnv(t)
	cookie := env.login(t, "dnsuser")

	recorder := env.do(t, httptest.NewRequest(http.MethodGet, "/dns", nil), cookie)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
}

func TestTheTableListsWhatTheServersHold(t *testing.T) {
	env := newFleetEnv(t)

	body := env.table(t, "")
	for _, want := range []string{"www.example.local", "mail.example.local", "dns1", "dns3"} {
		if !strings.Contains(body, want) {
			t.Errorf("the table does not show %q", want)
		}
	}
	// Three servers holding the same two records. One row each, because a
	// change through the panel reaches all three at once.
	if !strings.Contains(body, "Showing 2 of 2 records (Page 1/1)") {
		t.Errorf("the summary is wrong:\n%s", body)
	}
	if count := strings.Count(body, `data-field="holders">3/3<`); count != 2 {
		t.Errorf("%d rows report every server, want 2:\n%s", count, body)
	}
}

func TestARecordOneServerMissesIsMarked(t *testing.T) {
	// The count is the whole point of folding the rows: anything below the
	// size of the target is drift.
	env := newFleetEnv(t)

	env.target(3).setFile("# managed by the panel\n")
	if _, err := env.records.RefreshOne(context.Background(), 3); err != nil {
		t.Fatalf("cannot refresh: %v", err)
	}

	body := env.table(t, "")
	if count := strings.Count(body, `data-field="holders"`); count != 2 {
		t.Fatalf("%d rows came back, want 2:\n%s", count, body)
	}
	if !strings.Contains(body, `data-field="holders">2/3<`) {
		t.Errorf("the table does not report the server that misses the record:\n%s", body)
	}
	if strings.Contains(body, `data-field="holders">3/3<`) {
		t.Errorf("a record only two servers hold reads as complete:\n%s", body)
	}
}

func TestTheTableScopesToOneServer(t *testing.T) {
	env := newFleetEnv(t)
	env.target(2).setFile("local-data: \"only-on-two.example.local. A 10.0.0.99\"\n")
	if _, err := env.records.RefreshOne(context.Background(), 2); err != nil {
		t.Fatalf("cannot refresh: %v", err)
	}

	body := env.table(t, "scope=server&server_id=2")
	if !strings.Contains(body, "only-on-two.example.local") {
		t.Error("the table does not show the record of that server")
	}
	if strings.Contains(body, "www.example.local") {
		t.Error("the table shows records from another server")
	}
	// Every row would repeat the same name, so the column is dropped.
	if strings.Contains(body, "<th>Server</th>") {
		t.Error("the server column is shown for a single server view")
	}
}

func TestTheTableSearchesAndFilters(t *testing.T) {
	env := newFleetEnv(t)

	body := env.table(t, "search=mail")
	if strings.Contains(body, "www.example.local") {
		t.Error("the search returned a record it should have filtered out")
	}
	if !strings.Contains(body, "mail.example.local") {
		t.Error("the search dropped the matching record")
	}

	body = env.table(t, "type=MX")
	if strings.Contains(body, ">A<") && !strings.Contains(body, "MX") {
		t.Error("the type filter did not hold")
	}
}

func TestTheTablePagesAndSummarises(t *testing.T) {
	env := newFleetEnv(t)

	body := env.table(t, "per_page=10&page=1")
	if !strings.Contains(body, "Showing 2 of 2 records (Page 1/1)") {
		t.Errorf("summary = %s", body)
	}

	// Ten per page over two records leaves one page, so no links are drawn.
	if strings.Contains(body, "page-link") {
		t.Error("pagination is drawn for a single page")
	}
}

func TestAnEmptyResultSaysSo(t *testing.T) {
	env := newFleetEnv(t)

	body := env.table(t, "search=nothing-matches-this")
	if !strings.Contains(body, "No records found.") {
		t.Errorf("the table does not say the result is empty:\n%s", body)
	}
}

func TestAddingARecordReachesEveryMemberOfTheGroup(t *testing.T) {
	env := newFleetEnv(t)

	recorder := env.adminForm(t, http.MethodPost, "/dns/records", env.cookie, groupForm(url.Values{
		"fqdn": {"new.example.local"}, "type": {"A"}, "value": {"10.0.0.50"},
	}))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200:\n%s", recorder.Code, recorder.Body.String())
	}

	body := recorder.Body.String()
	for _, want := range []string{"dns1", "dns2", "dns3", "Record added"} {
		if !strings.Contains(body, want) {
			t.Errorf("the result table does not mention %q", want)
		}
	}
	if strings.Count(body, `data-field="status">success<`) != 3 {
		t.Errorf("the result table does not report three successes:\n%s", body)
	}

	for id := int64(1); id <= 3; id++ {
		if !strings.Contains(env.target(id).file(), "new.example.local") {
			t.Errorf("server %d did not receive the record", id)
		}
	}
}

func TestAPartialFailureAnswersWith207(t *testing.T) {
	env := newFleetEnv(t)
	env.target(3).writeErr = transport.ErrCommandFailed

	recorder := env.adminForm(t, http.MethodPost, "/dns/records", env.cookie, groupForm(url.Values{
		"fqdn": {"new.example.local"}, "type": {"A"}, "value": {"10.0.0.50"},
	}))
	if recorder.Code != http.StatusMultiStatus {
		t.Fatalf("status = %d, want 207", recorder.Code)
	}

	body := recorder.Body.String()
	if strings.Count(body, `data-field="status">success<`) != 2 {
		t.Errorf("the result table does not report two successes:\n%s", body)
	}
	if !strings.Contains(body, `data-field="status">failed<`) {
		t.Error("the failing server is not reported")
	}
	if !strings.Contains(body, "Some servers took the change") {
		t.Error("the panel does not explain what a partial result means")
	}
	if !strings.Contains(recorder.Header().Get("HX-Trigger"), "toast") {
		t.Error("no toast was raised")
	}
}

func TestAFailureOnEveryServerAnswersWith500(t *testing.T) {
	env := newFleetEnv(t)
	for id := int64(1); id <= 3; id++ {
		env.target(id).writeErr = transport.ErrCommandFailed
	}

	recorder := env.adminForm(t, http.MethodPost, "/dns/records", env.cookie, groupForm(url.Values{
		"fqdn": {"new.example.local"}, "type": {"A"}, "value": {"10.0.0.50"},
	}))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "No server took the change") {
		t.Error("the panel does not say the change landed nowhere")
	}
}

func TestADisabledServerIsReportedAsSkipped(t *testing.T) {
	env := newFleetEnv(t)

	record, err := env.servers.Get(context.Background(), 3)
	if err != nil {
		t.Fatalf("cannot read the server: %v", err)
	}
	record.Enabled = false
	if err := env.servers.Update(context.Background(),
		server.Actor{UID: 1001, Username: "dnsadmin"}, record); err != nil {
		t.Fatalf("cannot disable the server: %v", err)
	}

	recorder := env.adminForm(t, http.MethodPost, "/dns/records", env.cookie, groupForm(url.Values{
		"fqdn": {"new.example.local"}, "type": {"A"}, "value": {"10.0.0.50"},
	}))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, because a skip is not a failure", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), `data-field="status">skipped<`) {
		t.Errorf("the disabled server is not reported as skipped:\n%s", recorder.Body.String())
	}
}

func TestAnInvalidRecordIsRefusedBeforeAnyServerIsTouched(t *testing.T) {
	env := newFleetEnv(t)

	recorder := env.adminForm(t, http.MethodPost, "/dns/records", env.cookie, groupForm(url.Values{
		"fqdn": {"not a name"}, "type": {"A"}, "value": {"10.0.0.50"},
	}))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "name may hold") {
		t.Errorf("the form does not explain the refusal:\n%s", recorder.Body.String())
	}

	for id := int64(1); id <= 3; id++ {
		if strings.Contains(env.target(id).file(), "not a name") {
			t.Errorf("server %d was written to", id)
		}
	}
}

func TestAChangeWithoutATargetIsRefused(t *testing.T) {
	env := newFleetEnv(t)

	recorder := env.adminForm(t, http.MethodPost, "/dns/records", env.cookie, url.Values{
		"fqdn": {"new.example.local"}, "type": {"A"}, "value": {"10.0.0.50"},
		"scope": {"all"},
	})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "single server or a group") {
		t.Errorf("the form does not explain the refusal:\n%s", recorder.Body.String())
	}
}

func TestEditingARecordReplacesItEverywhere(t *testing.T) {
	env := newFleetEnv(t)

	recorder := env.adminForm(t, http.MethodPut, "/dns/records", env.cookie, groupForm(url.Values{
		"old_fqdn": {"www.example.local"}, "old_type": {"A"}, "old_value": {"10.0.0.20"},
		"fqdn": {"www.example.local"}, "type": {"A"}, "value": {"10.0.0.99"},
	}))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200:\n%s", recorder.Code, recorder.Body.String())
	}

	for id := int64(1); id <= 3; id++ {
		file := env.target(id).file()
		if !strings.Contains(file, "10.0.0.99") || strings.Contains(file, "10.0.0.20") {
			t.Errorf("server %d still holds the old value:\n%s", id, file)
		}
	}
}

func TestDeletingARecordRemovesItEverywhere(t *testing.T) {
	env := newFleetEnv(t)

	recorder := env.deleteRecord(t, groupForm(url.Values{
		"fqdn": {"www.example.local"}, "type": {"A"}, "value": {"10.0.0.20"},
	}))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200:\n%s", recorder.Code, recorder.Body.String())
	}

	for id := int64(1); id <= 3; id++ {
		if strings.Contains(env.target(id).file(), "www.example.local") {
			t.Errorf("server %d still holds the record", id)
		}
	}
}

func TestARecordMissingOnOneServerFailsOnlyThere(t *testing.T) {
	// The servers drifted apart before the panel arrived, which is the case
	// the fleet view exists for.
	env := newFleetEnv(t)
	env.target(3).setFile("# nothing here\n")

	recorder := env.deleteRecord(t, groupForm(url.Values{
		"fqdn": {"www.example.local"}, "type": {"A"}, "value": {"10.0.0.20"},
	}))
	if recorder.Code != http.StatusMultiStatus {
		t.Fatalf("status = %d, want 207", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "not in the file") {
		t.Errorf("the result does not explain the failure:\n%s", recorder.Body.String())
	}
}

func TestASuccessfulChangeIsCachedRightAway(t *testing.T) {
	// The operator submits and expects to see the record, not to wait for the
	// next refresh interval.
	env := newFleetEnv(t)

	env.adminForm(t, http.MethodPost, "/dns/records", env.cookie, groupForm(url.Values{
		"fqdn": {"fresh.example.local"}, "type": {"A"}, "value": {"10.0.0.60"},
	}))

	body := env.table(t, "search=fresh")
	if !strings.Contains(body, "fresh.example.local") {
		t.Errorf("the table does not show the new record:\n%s", body)
	}
}

func TestEveryRecordChangeIsAuditedPerServer(t *testing.T) {
	env := newFleetEnv(t)

	env.adminForm(t, http.MethodPost, "/dns/records", env.cookie, groupForm(url.Values{
		"fqdn": {"new.example.local"}, "type": {"A"}, "value": {"10.0.0.50"},
	}))

	rows, err := env.db.Query(
		"SELECT action, username, server_id, details FROM audit_logs WHERE action LIKE 'dns_%' ORDER BY id")
	if err != nil {
		t.Fatalf("cannot read the audit table: %v", err)
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var action, username, details string
		var serverID *int64
		if err := rows.Scan(&action, &username, &serverID, &details); err != nil {
			t.Fatalf("cannot read an audit row: %v", err)
		}
		count++

		if action != "dns_add" || username != "dnsadmin" || serverID == nil {
			t.Errorf("got %s by %s on %v", action, username, serverID)
		}
		if !strings.Contains(details, "Added A record: new.example.local -> 10.0.0.50") {
			t.Errorf("details = %q", details)
		}
		if !strings.Contains(details, "group resolvers") {
			t.Errorf("the details do not name the group: %q", details)
		}
	}
	if count != 3 {
		t.Errorf("got %d audit rows, want one per server", count)
	}
}

func TestRefreshReadsEveryServerAgain(t *testing.T) {
	env := newFleetEnv(t)

	// Somebody edited the file on the target by hand, which is what the
	// refresh exists to notice.
	env.target(2).setFile("local-data: \"byhand.example.local. A 10.0.0.77\"\n")

	recorder := env.adminForm(t, http.MethodPost, "/dns/refresh", env.cookie, url.Values{})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "byhand.example.local") {
		t.Errorf("the table does not show the record found on the target:\n%s", recorder.Body.String())
	}
}

func TestTheFormOffersEveryManagedType(t *testing.T) {
	env := newFleetEnv(t)

	recorder := env.do(t, httptest.NewRequest(http.MethodGet, "/dns/records/new", nil), env.cookie)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}

	body := recorder.Body.String()
	for _, recordType := range dnsfile.Types {
		if !strings.Contains(body, `value="`+recordType+`"`) {
			t.Errorf("the form does not offer %s", recordType)
		}
	}
}

func TestTheEditFormCarriesTheRecordItReplaces(t *testing.T) {
	env := newFleetEnv(t)

	recorder := env.do(t, httptest.NewRequest(http.MethodGet,
		"/dns/records/edit?fqdn=www.example.local&type=A&value=10.0.0.20&priority=0", nil), env.cookie)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}

	body := recorder.Body.String()
	for _, want := range []string{
		`name="old_fqdn" value="www.example.local"`,
		`name="old_type" value="A"`,
		`name="old_value" value="10.0.0.20"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the form does not carry %s:\n%s", want, body)
		}
	}
}

func TestAStaleServerIsMarkedInTheTable(t *testing.T) {
	// Old records with a warning next to them say more than an empty page.
	env := newFleetEnv(t)

	// Nobody has read that server for an hour, which is longer than the window
	// the panel trusts.
	old := time.Now().UTC().Add(-time.Hour)
	err := env.stateDB.SetFetched(context.Background(), fleet.State{
		ServerID: 2, FileSHA256: "abc", FetchedAt: &old, RecordCount: 2})
	if err != nil {
		t.Fatalf("cannot age the server state: %v", err)
	}

	body := env.table(t, "")
	if !strings.Contains(body, `data-field="stale"`) {
		t.Errorf("the table does not mark the stale server:\n%s", body)
	}
}

func TestTheQueryFallsBackRatherThanFailing(t *testing.T) {
	// These are view controls. A stale link is not worth an error page.
	env := newFleetEnv(t)

	body := env.table(t, "scope=server&server_id=&type=SRV&page=notanumber&per_page=9999")
	if !strings.Contains(body, "Showing 2 of 2 records") {
		t.Errorf("an unreadable query did not fall back to the default view:\n%s", body)
	}
}

// applyRules presses the Apply Rules button for one target.
func (e *fleetEnv) applyRules(t *testing.T, values url.Values) *httptest.ResponseRecorder {
	t.Helper()
	return e.adminForm(t, http.MethodPost, "/dns/apply", e.cookie, values)
}

func TestApplyRulesReloadsEveryMemberOfTheGroup(t *testing.T) {
	env := newFleetEnv(t)

	recorder := env.applyRules(t, groupForm(url.Values{}))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200:\n%s", recorder.Code, recorder.Body.String())
	}

	body := recorder.Body.String()
	if strings.Count(body, `data-field="status">success<`) != 3 {
		t.Errorf("the result table does not report three reloads:\n%s", body)
	}
	for id := int64(1); id <= 3; id++ {
		if count := env.target(id).reloadCount(); count != 1 {
			t.Errorf("server %d was reloaded %d times", id, count)
		}
	}
}

func TestAPartialReloadAnswersWith207(t *testing.T) {
	env := newFleetEnv(t)
	env.target(3).failReload(transport.ErrCommandFailed)

	recorder := env.applyRules(t, groupForm(url.Values{}))
	if recorder.Code != http.StatusMultiStatus {
		t.Fatalf("status = %d, want 207", recorder.Code)
	}

	body := recorder.Body.String()
	if strings.Count(body, `data-field="status">success<`) != 2 {
		t.Errorf("the result table does not report two reloads:\n%s", body)
	}
	if !strings.Contains(body, "Some servers reloaded") {
		t.Errorf("the panel does not explain what a partial reload means:\n%s", body)
	}
}

func TestApplyRulesRefusesTheWholeFleet(t *testing.T) {
	// A reload of every server at once has to be a group somebody built on
	// purpose, the same way a write does.
	env := newFleetEnv(t)

	recorder := env.applyRules(t, url.Values{"scope": {"all"}})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "A change needs a single server or a group.") {
		t.Errorf("the refusal does not explain itself:\n%s", recorder.Body.String())
	}
	if env.target(1).reloadCount() != 0 {
		t.Error("a refused target still reached a server")
	}
}

func TestApplyRulesIsAuditedPerServer(t *testing.T) {
	env := newFleetEnv(t)
	env.applyRules(t, groupForm(url.Values{}))

	rows, err := env.db.Query(
		"SELECT server_id, details FROM audit_logs WHERE action = 'dns_restart' ORDER BY id")
	if err != nil {
		t.Fatalf("cannot read the audit table: %v", err)
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var serverID *int64
		var details string
		if err := rows.Scan(&serverID, &details); err != nil {
			t.Fatalf("cannot read an audit row: %v", err)
		}
		count++

		if serverID == nil {
			t.Error("the row names no server")
		}
		if !strings.HasPrefix(details, "Unbound service reloaded. Output: ") {
			t.Errorf("details = %q", details)
		}
	}
	if count != 3 {
		t.Errorf("got %d audit rows, want one per server", count)
	}
}

func TestTheStatusBarCountsTheServersThatLagBehind(t *testing.T) {
	env := newFleetEnv(t)

	// Nobody has applied anything yet, so every server carries a file the
	// resolver has not been told about.
	body := env.table(t, "scope=group&group_id=1")
	if !strings.Contains(body, "3 of 3 servers have unapplied changes.") {
		t.Errorf("the status bar does not count the servers:\n%s", body)
	}

	if recorder := env.applyRules(t, groupForm(url.Values{})); recorder.Code != http.StatusOK {
		t.Fatalf("Apply Rules returned %d", recorder.Code)
	}

	body = env.table(t, "scope=group&group_id=1")
	if !strings.Contains(body, "Every server has loaded its current file.") {
		t.Errorf("the status bar still reports unapplied changes:\n%s", body)
	}
	if !strings.Contains(body, `data-field="apply-rules"`) || !strings.Contains(body, "disabled") {
		t.Errorf("the button is not disabled with nothing to apply:\n%s", body)
	}
}

func TestAWriteReopensTheUnappliedMarker(t *testing.T) {
	env := newFleetEnv(t)
	env.applyRules(t, groupForm(url.Values{}))

	env.adminForm(t, http.MethodPost, "/dns/records", env.cookie, groupForm(url.Values{
		"fqdn": {"new.example.local"}, "type": {"A"}, "value": {"10.0.0.50"},
	}))

	body := env.table(t, "scope=group&group_id=1")
	if !strings.Contains(body, "3 of 3 servers have unapplied changes.") {
		t.Errorf("a written file does not read as unapplied:\n%s", body)
	}
}

func TestTheStatusBarCannotApplyToTheWholeFleet(t *testing.T) {
	env := newFleetEnv(t)

	body := env.table(t, "")
	if !strings.Contains(body, "Choose a single server or a group to apply the rules.") {
		t.Errorf("the status bar does not say why the button is unavailable:\n%s", body)
	}
}

func TestTheStatusBarRidesWithTheTable(t *testing.T) {
	// One request answers about one target. A second request for the status
	// could arrive with a different one and disagree with the table above it.
	env := newFleetEnv(t)

	body := env.table(t, "scope=group&group_id=1")
	if !strings.Contains(body, `id="record-status"`) || !strings.Contains(body, `hx-swap-oob="true"`) {
		t.Errorf("the table response carries no status bar:\n%s", body)
	}
}

// query submits the query form for one target.
func (e *fleetEnv) query(t *testing.T, values url.Values) *httptest.ResponseRecorder {
	t.Helper()
	return e.adminForm(t, http.MethodPost, "/dns/query", e.cookie, values)
}

func TestAQueryAsksEveryServerOfTheGroup(t *testing.T) {
	env := newFleetEnv(t)
	for _, host := range []string{"dns1.example", "dns2.example", "dns3.example"} {
		env.queries.answer(host, "10.0.0.20")
	}

	recorder := env.query(t, groupForm(url.Values{
		"domain": {"www.example.local"}, "query_type": {"A"},
	}))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200:\n%s", recorder.Code, recorder.Body.String())
	}

	body := recorder.Body.String()
	if strings.Count(body, `data-field="query-answer"`) != 3 {
		t.Errorf("the panel does not show one answer per server:\n%s", body)
	}
	if !strings.Contains(body, "Every server that answered gave the same answer.") {
		t.Error("the panel does not say that the servers agree")
	}

	asked := env.queries.questions()
	if len(asked) != 3 {
		t.Fatalf("asked = %v, want one question per server", asked)
	}
	for _, question := range asked {
		if !strings.HasSuffix(question, "www.example.local A") {
			t.Errorf("question = %q", question)
		}
	}
}

func TestAQueryShowsThatTheServersDisagree(t *testing.T) {
	// A record that resolves on two servers and not on the third is drift the
	// record table cannot show, because the files may well be identical and
	// one resolver simply behind.
	env := newFleetEnv(t)
	env.queries.answer("dns1.example", "10.0.0.20")
	env.queries.answer("dns2.example", "10.0.0.20")

	recorder := env.query(t, groupForm(url.Values{"domain": {"www.example.local"}}))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}

	body := recorder.Body.String()
	if !strings.Contains(body, "The servers do not agree.") {
		t.Errorf("the panel does not report the disagreement:\n%s", body)
	}
	if !strings.Contains(body, `data-field="query-empty"`) {
		t.Error("the server that answered nothing is not shown as such")
	}
}

func TestAQueryRefusesAnInvalidName(t *testing.T) {
	env := newFleetEnv(t)

	recorder := env.query(t, groupForm(url.Values{"domain": {"www example.local"}}))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}
	if len(env.queries.questions()) != 0 {
		t.Error("a refused name still reached a server")
	}
}

func TestAQueryMayCoverTheWholeFleet(t *testing.T) {
	// A query reads. Unlike a write, it does not need a target somebody built
	// on purpose.
	env := newFleetEnv(t)

	recorder := env.query(t, url.Values{"scope": {"all"}, "domain": {"www.example.local"}})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200:\n%s", recorder.Code, recorder.Body.String())
	}
	if len(env.queries.questions()) != 3 {
		t.Errorf("asked = %v, want every server", env.queries.questions())
	}
}

func TestAQueryIsAuditedOnce(t *testing.T) {
	// A row per member of a large group would bury the changes the log exists
	// for, and a query changes nothing.
	env := newFleetEnv(t)
	env.query(t, groupForm(url.Values{"domain": {"www.example.local"}}))

	var count int
	var details string
	row := env.db.QueryRow(
		"SELECT COUNT(*), COALESCE(MAX(details), '') FROM audit_logs WHERE action = 'dns_query'")
	if err := row.Scan(&count, &details); err != nil {
		t.Fatalf("cannot read the audit table: %v", err)
	}

	if count != 1 {
		t.Fatalf("got %d audit rows, want 1", count)
	}
	if !strings.HasPrefix(details, "Queried: www.example.local") {
		t.Errorf("details = %q", details)
	}
	if !strings.Contains(details, "group resolvers") {
		t.Errorf("the row does not name the target: %q", details)
	}
}

func TestAQueryNamesTheServerItCouldNotAsk(t *testing.T) {
	env := newFleetEnv(t)
	env.queries.err = errors.New("dial udp 10.0.0.3:53: connection refused")

	recorder := env.query(t, groupForm(url.Values{"domain": {"www.example.local"}}))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "connection refused") {
		t.Errorf("the reason is not shown:\n%s", recorder.Body.String())
	}
}

func TestTheQueryFormNeedsASession(t *testing.T) {
	env := newTestEnv(t)

	recorder := env.do(t, httptest.NewRequest(http.MethodGet, "/dns/query", nil))
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want a redirect to the login page", recorder.Code)
	}
}

func TestTheTargetSelectorDecidesTheScope(t *testing.T) {
	// The selector offers servers and groups in one list. Splitting it in the
	// browser would race with the request that reads the split fields, and the
	// loser of that race is a change aimed at the wrong servers.
	env := newFleetEnv(t)

	// The controls still carry the target the page was drawn with.
	body := env.table(t, "target=group%3A1&scope=all&server_id=0&group_id=0")
	if !strings.Contains(body, "3 of 3 servers have unapplied changes.") {
		t.Errorf("the status bar did not follow the selector:\n%s", body)
	}
	if strings.Contains(body, "Choose a single server or a group") {
		t.Errorf("the chosen group was read as the whole fleet:\n%s", body)
	}
}

func TestChangingTheTargetGoesBackToTheFirstPage(t *testing.T) {
	env := newFleetEnv(t)

	body := env.table(t, "target=server%3A1&scope=group&group_id=1&page=3&per_page=10")
	if !strings.Contains(body, "(Page 1/1)") {
		t.Errorf("the page number survived a change of target:\n%s", body)
	}
}

func TestAChangeFollowsTheSelectorRatherThanTheHiddenFields(t *testing.T) {
	env := newFleetEnv(t)

	recorder := env.adminForm(t, http.MethodPost, "/dns/records", env.cookie, url.Values{
		"target": {"server:1"},
		"scope":  {"group"}, "group_id": {"1"},
		"fqdn": {"new.example.local"}, "type": {"A"}, "value": {"10.0.0.50"},
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200:\n%s", recorder.Code, recorder.Body.String())
	}
	if strings.Count(recorder.Body.String(), `data-field="status">success<`) != 1 {
		t.Errorf("the change did not go to the one chosen server:\n%s", recorder.Body.String())
	}
	if strings.Contains(env.target(2).file(), "new.example.local") {
		t.Error("the change reached a server the selector did not name")
	}
}

func TestARefreshTheOperatorAskedForIsAudited(t *testing.T) {
	// The timer runs every few minutes, and a row for each pass would bury the
	// changes the log exists for, so only this one is recorded.
	env := newFleetEnv(t)

	env.adminForm(t, http.MethodPost, "/dns/refresh", env.cookie, url.Values{})

	var count int
	var details string
	row := env.db.QueryRow(
		"SELECT COUNT(*), COALESCE(MAX(details), '') FROM audit_logs WHERE action = 'cache_refresh'")
	if err := row.Scan(&count, &details); err != nil {
		t.Fatalf("cannot read the audit table: %v", err)
	}

	if count != 1 {
		t.Fatalf("got %d audit rows, want 1", count)
	}
	if !strings.Contains(details, "3 of 3 servers read") {
		t.Errorf("details = %q", details)
	}
}

func TestAFleetOperationThatRunsOutOfTimeStillReportsPerServer(t *testing.T) {
	// One slow machine used to take the whole answer with it: the write timeout
	// of the server dropped the connection, and the operator never learned that
	// two of the three servers already carry the record.
	env := newFleetEnv(t)
	env.target(2).slowDown(time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	body := groupForm(url.Values{
		"fqdn": {"slow.example.local"}, "type": {"A"}, "value": {"10.0.0.90"},
	}).Encode()

	request := httptest.NewRequest(http.MethodPost, "/dns/records",
		strings.NewReader(body)).WithContext(ctx)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set(auth.CSRFHeader, env.csrfTokenOf(t, env.cookie))

	recorder := env.do(t, request, env.cookie)
	if recorder.Code != http.StatusMultiStatus {
		t.Fatalf("status = %d, want 207:\n%s", recorder.Code, recorder.Body.String())
	}

	page := recorder.Body.String()
	if !strings.Contains(page, "ran out of time") {
		t.Errorf("the report does not say the server ran out of time:\n%s", page)
	}
	// The two that answered carry the record, which is exactly what the
	// operator has to know before deciding what to do about the third.
	for _, id := range []int64{1, 3} {
		if !strings.Contains(env.target(id).file(), "10.0.0.90") {
			t.Errorf("server %d did not get the record", id)
		}
	}
}

func TestAChangeThatLandedIsAuditedEvenIfTheRequestIsCancelled(t *testing.T) {
	// htmx cancels a request whenever the same element fires a second one, and
	// a resolver the panel has already changed still has to appear in the log
	// the operator reads.
	env := newFleetEnv(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env.target(1).onWrite(cancel)

	body := groupForm(url.Values{
		"fqdn": {"cancelled.example.local"}, "type": {"A"}, "value": {"10.0.0.91"},
	}).Encode()

	request := httptest.NewRequest(http.MethodPost, "/dns/records",
		strings.NewReader(body)).WithContext(ctx)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set(auth.CSRFHeader, env.csrfTokenOf(t, env.cookie))

	env.do(t, request, env.cookie)

	if !strings.Contains(env.target(1).file(), "10.0.0.91") {
		t.Fatal("the record never reached the server, the test proves nothing")
	}

	var rows int
	if err := env.db.QueryRow(
		"SELECT COUNT(*) FROM audit_logs WHERE action = 'dns_add' AND details LIKE '%cancelled.example.local%'",
	).Scan(&rows); err != nil {
		t.Fatalf("cannot read the audit table: %v", err)
	}
	if rows == 0 {
		t.Error("the change landed on a server with no audit row behind it")
	}
}

func TestARefusedRecordDoesNotComeBackWithEmptyTargetLists(t *testing.T) {
	// The form used to render with empty server and group selectors when the
	// store failed. The next submission is then refused with "no server was
	// chosen", which blames the operator for a database fault.
	env := newFleetEnv(t)
	logged := captureLog(t)

	if _, err := env.db.Exec("ALTER TABLE servers RENAME TO servers_moved"); err != nil {
		t.Fatalf("cannot take the table away: %v", err)
	}

	recorder := env.adminForm(t, http.MethodPost, "/dns/records", env.cookie,
		groupForm(url.Values{"fqdn": {"not a name"}, "type": {"A"}, "value": {"10.0.0.92"}}))

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500:\n%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(logged.String(), "cannot load the servers for the record form") {
		t.Errorf("the failure never reached the log:\n%s", logged.String())
	}
}

func TestAnMXRecordKeepsThePreferenceTheOperatorTyped(t *testing.T) {
	// Zero is the preference the most preferred exchanger of a zone carries.
	// It used to be written as ten, so the confirmation showed one record and
	// the servers held another, and the record could then never be removed.
	env := newFleetEnv(t)

	env.adminForm(t, http.MethodPost, "/dns/records", env.cookie, groupForm(url.Values{
		"fqdn": {"example.local"}, "type": {"MX"},
		"value": {"mx1.example.local"}, "priority": {"0"},
	}))

	for id := int64(1); id <= 3; id++ {
		if !strings.Contains(env.target(id).file(), "MX 0 mx1.example.local") {
			t.Errorf("server %d holds:\n%s", id, env.target(id).file())
		}
	}

	// And what was written can be taken away again, which is the half the
	// operator only discovers later.
	recorder := env.deleteRecord(t, groupForm(url.Values{
		"fqdn": {"example.local"}, "type": {"MX"},
		"value": {"mx1.example.local"}, "priority": {"0"},
	}))
	if recorder.Code != http.StatusOK {
		t.Fatalf("delete = %d, want 200:\n%s", recorder.Code, recorder.Body.String())
	}
	for id := int64(1); id <= 3; id++ {
		// The seed file holds another exchanger with the same target, so the
		// whole line decides rather than the value alone.
		if strings.Contains(env.target(id).file(), `"example.local. MX 0`) {
			t.Errorf("server %d still holds the record:\n%s", id, env.target(id).file())
		}
	}
}

func TestACancelledRequestStillLeavesTheCacheCurrent(t *testing.T) {
	// The remote file is written before the cache is refilled, so a client
	// that goes away mid request used to leave the panel describing a file it
	// had just changed, until the next timer pass up to cache_refresh_interval
	// later. htmx aborts an in flight request whenever the same element fires
	// another, so this is ordinary use.
	env := newFleetEnv(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env.target(1).onWrite(cancel)

	body := groupForm(url.Values{
		"fqdn": {"cached.example.local"}, "type": {"A"}, "value": {"10.0.0.93"},
	}).Encode()

	request := httptest.NewRequest(http.MethodPost, "/dns/records",
		strings.NewReader(body)).WithContext(ctx)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set(auth.CSRFHeader, env.csrfTokenOf(t, env.cookie))

	env.do(t, request, env.cookie)

	if !strings.Contains(env.target(1).file(), "10.0.0.93") {
		t.Fatal("the record never reached the server, the test proves nothing")
	}

	// The table is read on a request of its own, the way the browser reads it
	// after the change.
	if table := env.table(t, "search=cached"); !strings.Contains(table, "cached.example.local") {
		t.Errorf("the table does not show the record that was written:\n%s", table)
	}
}
