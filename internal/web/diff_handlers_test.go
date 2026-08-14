package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"unbound-web/internal/settings"
)

// drift makes one server hold something the others do not, which is what the
// page exists to show.
func (e *fleetEnv) drift(t *testing.T, id int64, file string) {
	t.Helper()

	e.target(id).setFile(file)
	if _, err := e.records.RefreshOne(context.Background(), id); err != nil {
		t.Fatalf("cannot refresh server %d: %v", id, err)
	}
}

// diffTable returns the rendered drift table for one query string.
func (e *fleetEnv) diffTable(t *testing.T, query string) string {
	t.Helper()

	recorder := e.do(t, httptest.NewRequest(http.MethodGet, "/diff/table?"+query, nil), e.cookie)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /diff/table?%s = %d", query, recorder.Code)
	}
	return recorder.Body.String()
}

func TestTheDiffPageNeedsASession(t *testing.T) {
	env := newTestEnv(t)

	recorder := env.do(t, httptest.NewRequest(http.MethodGet, "/diff", nil))
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want a redirect to the login page", recorder.Code)
	}
}

func TestAFleetThatAgreesShowsNoDifference(t *testing.T) {
	env := newFleetEnv(t)

	body := env.diffTable(t, "scope=group&group_id=1")
	if !strings.Contains(body, "The servers hold the same records.") {
		t.Errorf("the page does not report an agreeing fleet:\n%s", body)
	}
	if strings.Contains(body, `data-field="repair"`) {
		t.Error("a repair is offered for a fleet that agrees")
	}
}

func TestAMissingRecordShowsAsMissing(t *testing.T) {
	env := newFleetEnv(t)
	env.drift(t, 3, "local-data: \"mail.example.local. MX 10 mx1.example.local\"\n")

	body := env.diffTable(t, "scope=group&group_id=1")
	if !strings.Contains(body, "www.example.local") {
		t.Fatalf("the differing record is not listed:\n%s", body)
	}
	if strings.Count(body, `data-field="cell">missing<`) != 1 {
		t.Errorf("the missing record is not marked once:\n%s", body)
	}
	if strings.Count(body, `data-field="cell">present<`) != 2 {
		t.Errorf("the two servers that hold it are not marked:\n%s", body)
	}
	if !strings.Contains(body, "1 record differ") {
		t.Errorf("the summary does not count the difference:\n%s", body)
	}
}

func TestTheSameNameWithAnotherValueShowsAsDifferent(t *testing.T) {
	env := newFleetEnv(t)
	env.drift(t, 3, "local-data: \"www.example.local. A 10.0.0.99\"\n"+
		"local-data: \"mail.example.local. MX 10 mx1.example.local\"\n")

	body := env.diffTable(t, "scope=group&group_id=1")
	if !strings.Contains(body, `data-field="cell">different<`) {
		t.Errorf("the drifted value is not marked as a difference:\n%s", body)
	}
	if !strings.Contains(body, "This server holds 10.0.0.99") {
		t.Error("the cell does not say what that server holds instead")
	}
}

func TestTheFilterStartsOnAndCanBeTurnedOff(t *testing.T) {
	env := newFleetEnv(t)
	env.drift(t, 3, "local-data: \"mail.example.local. MX 10 mx1.example.local\"\n")

	// The filter is the default view, so the record every server agrees about
	// is left out.
	body := env.diffTable(t, "scope=group&group_id=1")
	if strings.Contains(body, "mail.example.local") {
		t.Errorf("the default view shows a record everybody agrees about:\n%s", body)
	}

	body = env.diffTable(t, "scope=group&group_id=1&view=1")
	if !strings.Contains(body, "mail.example.local") {
		t.Errorf("turning the filter off did not show the matching record:\n%s", body)
	}
	if !strings.Contains(body, "1 record of 2 records differ") {
		t.Errorf("the full view does not summarise both counts:\n%s", body)
	}
}

func TestARepairWritesTheRecordWhereItIsMissing(t *testing.T) {
	env := newFleetEnv(t)
	env.drift(t, 3, "local-data: \"mail.example.local. MX 10 mx1.example.local\"\n")

	recorder := env.adminForm(t, http.MethodPost, "/diff/repair", env.cookie, groupForm(url.Values{
		"fqdn": {"www.example.local"}, "type": {"A"}, "value": {"10.0.0.20"},
	}))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200:\n%s", recorder.Code, recorder.Body.String())
	}

	body := recorder.Body.String()
	if !strings.Contains(body, "Every server now holds the record.") {
		t.Errorf("the report does not say the repair worked:\n%s", body)
	}
	if strings.Count(body, `data-field="status">skipped<`) != 2 {
		t.Errorf("the servers that already agreed were not left alone:\n%s", body)
	}
	if !strings.Contains(env.target(3).file(), "www.example.local") {
		t.Errorf("the record was not written:\n%s", env.target(3).file())
	}

	// The repair refreshed that server, so the difference is gone.
	if table := env.diffTable(t, "scope=group&group_id=1"); !strings.Contains(
		table, "The servers hold the same records.") {
		t.Errorf("the difference survived the repair:\n%s", table)
	}
}

func TestARepairIsAudited(t *testing.T) {
	env := newFleetEnv(t)
	env.drift(t, 3, "local-data: \"mail.example.local. MX 10 mx1.example.local\"\n")

	env.adminForm(t, http.MethodPost, "/diff/repair", env.cookie, groupForm(url.Values{
		"fqdn": {"www.example.local"}, "type": {"A"}, "value": {"10.0.0.20"},
	}))

	var count int
	var details string
	row := env.db.QueryRow(
		"SELECT COUNT(*), COALESCE(MAX(details), '') FROM audit_logs WHERE action = 'diff_repair'")
	if err := row.Scan(&count, &details); err != nil {
		t.Fatalf("cannot read the audit table: %v", err)
	}

	if count != 1 {
		t.Fatalf("got %d audit rows, want one per server that changed", count)
	}
	if !strings.HasPrefix(details, "Repaired A www.example.local -> 10.0.0.20 on dns3") {
		t.Errorf("details = %q", details)
	}
}

func TestARepairNeedsATarget(t *testing.T) {
	env := newFleetEnv(t)

	recorder := env.adminForm(t, http.MethodPost, "/diff/repair", env.cookie, url.Values{
		"scope": {"all"},
		"fqdn":  {"www.example.local"}, "type": {"A"}, "value": {"10.0.0.20"},
	})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}
}

func TestARepairNeedsACSRFToken(t *testing.T) {
	env := newFleetEnv(t)

	recorder := env.do(t, postForm("/diff/repair",
		"scope=group&group_id=1&fqdn=www.example.local&type=A&value=10.0.0.20"), env.cookie)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", recorder.Code)
	}
}

func TestTheSyncRouteIsAdminTerritory(t *testing.T) {
	// The synchronisation removes records the operator did not name one by
	// one, so it sits with the other fleet configuration routes.
	env := newTestEnv(t)
	cookie := env.login(t, "dnsuser")

	recorder := env.do(t, postForm("/diff/sync", "scope=all&group_id=0&server_id=0"), cookie)
	if recorder.Code != http.StatusForbidden {
		t.Errorf("POST /diff/sync as a plain user = %d, want 403", recorder.Code)
	}
}

func TestTheDiffTableSaysWhenNoSourceIsChosen(t *testing.T) {
	env := newFleetEnv(t)

	body := env.diffTable(t, "")
	if !strings.Contains(body, `data-field="no-source"`) {
		t.Errorf("the table does not say that no source is chosen:\n%s", body)
	}
	if strings.Contains(body, `data-field="sync-from-source"`) {
		t.Errorf("the table offers a synchronisation with no source:\n%s", body)
	}
}

func TestTheDiffTableMarksTheSourceColumn(t *testing.T) {
	env := newFleetEnv(t)

	form := env.settingsForm(t, map[string]string{settings.SourceServerID: "1"})
	if recorder := env.do(t, postForm("/settings", form), env.adminCookie(t)); recorder.Code != http.StatusOK {
		t.Fatalf("cannot choose the source: %d", recorder.Code)
	}

	body := env.diffTable(t, "")
	if !strings.Contains(body, `data-field="source"`) {
		t.Errorf("the source column carries no badge:\n%s", body)
	}
	if !strings.Contains(body, `data-field="sync-from-source"`) {
		t.Errorf("the table offers no synchronisation:\n%s", body)
	}
}
