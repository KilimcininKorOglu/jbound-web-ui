package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// siemPanel returns the rendered SIEM card.
func (e *fleetEnv) siemPanel(t *testing.T) string {
	t.Helper()

	recorder := e.do(t, httptest.NewRequest(http.MethodGet, "/siem/panel", nil), e.cookie)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /siem/panel = %d", recorder.Code)
	}
	return recorder.Body.String()
}

// saveRules submits the forwarding rules.
func (e *fleetEnv) saveRules(t *testing.T, rules string) *httptest.ResponseRecorder {
	t.Helper()

	return e.adminForm(t, http.MethodPost, "/siem", e.cookie, url.Values{"rules": {rules}})
}

func TestTheSIEMPageRefusesAPlainUser(t *testing.T) {
	// The forwarding configuration decides where the panel's own trail goes,
	// which is admin territory.
	env := newTestEnv(t)
	cookie := env.login(t, "dnsuser")

	for _, path := range []string{"/siem", "/siem/panel"} {
		recorder := env.do(t, httptest.NewRequest(http.MethodGet, path, nil), cookie)
		if recorder.Code != http.StatusForbidden {
			t.Errorf("GET %s = %d, want 403", path, recorder.Code)
		}
	}
}

func TestSavingTheRulesNeedsACSRFToken(t *testing.T) {
	env := newFleetEnv(t)

	recorder := env.do(t, postForm("/siem", "rules="), env.cookie)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", recorder.Code)
	}
}

func TestTheRulesAreWrittenAndComeBack(t *testing.T) {
	env := newFleetEnv(t)
	const rule = "local6.*    @@siem-sink:514"

	recorder := env.saveRules(t, rule)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200:\n%s", recorder.Code, recorder.Body.String())
	}

	body := recorder.Body.String()
	if !strings.Contains(body, rule) {
		t.Errorf("the form does not show the saved rule:\n%s", body)
	}
	if !strings.Contains(body, `data-field="forwarding">forwarding<`) {
		t.Errorf("the panel does not report that it forwards:\n%s", body)
	}

	content, err := os.ReadFile(filepath.Join(env.siemDir, "60-panel.conf"))
	if err != nil {
		t.Fatalf("cannot read the configuration: %v", err)
	}
	if !strings.Contains(string(content), rule) {
		t.Errorf("the file does not carry the rule:\n%s", content)
	}
}

func TestARefusedRuleComesBackWithTheReason(t *testing.T) {
	env := newFleetEnv(t)

	recorder := env.saveRules(t, "*.* @@everything.example.net:514")
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", recorder.Code)
	}

	body := recorder.Body.String()
	if !strings.Contains(body, "line 1") {
		t.Errorf("the reason does not name the line:\n%s", body)
	}
	// The operator corrects the text rather than typing it again.
	if !strings.Contains(body, "*.* @@everything.example.net:514") {
		t.Errorf("the refused rule was dropped from the form:\n%s", body)
	}
}

func TestSavingTheRulesIsAudited(t *testing.T) {
	env := newFleetEnv(t)
	env.saveRules(t, "local6.*    @@siem-sink:514")

	var count int
	var details string
	row := env.db.QueryRow(
		"SELECT COUNT(*), COALESCE(MAX(details), '') FROM audit_logs WHERE action = 'siem_config'")
	if err := row.Scan(&count, &details); err != nil {
		t.Fatalf("cannot read the audit table: %v", err)
	}
	if count != 1 || !strings.Contains(details, "SIEM forwarding configuration updated") {
		t.Errorf("got %d rows: %q", count, details)
	}
}

func TestTheTestEventsGoOutAndAreAudited(t *testing.T) {
	env := newFleetEnv(t)
	before := len(env.forwarder.sent())

	recorder := env.adminForm(t, http.MethodPost, "/siem/test", env.cookie, url.Values{})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200:\n%s", recorder.Code, recorder.Body.String())
	}

	// Four events plus the audit row the run itself produces.
	sent := env.forwarder.sent()
	if len(sent)-before != 5 {
		t.Fatalf("the panel sent %d entries, want 5", len(sent)-before)
	}

	actions := map[string]bool{}
	for _, entry := range sent[before:] {
		actions[entry.Action] = true
	}
	for _, want := range []string{"login", "dns_add", "dns_delete", "login_failed", "siem_test"} {
		if !actions[want] {
			t.Errorf("the run sent no %s event", want)
		}
	}

	if !strings.Contains(recorder.Body.String(), "4 test events sent to syslog (facility local6).") {
		t.Errorf("the panel does not report what it sent:\n%s", recorder.Body.String())
	}
}

func TestTheViewerShowsTheNewestLineFirst(t *testing.T) {
	env := newFleetEnv(t)

	logFile := filepath.Join(env.siemDir, "panel.log")
	if err := os.WriteFile(logFile, []byte("older line\nnewer line\n"), 0o644); err != nil {
		t.Fatalf("cannot write the log file: %v", err)
	}

	body := env.siemPanel(t)
	older := strings.Index(body, "older line")
	newer := strings.Index(body, "newer line")

	if older < 0 || newer < 0 {
		t.Fatalf("the viewer does not show the log:\n%s", body)
	}
	if newer > older {
		t.Error("the older line is shown above the newer one")
	}
}

func TestAPanelWithNoLogYetSaysSo(t *testing.T) {
	env := newFleetEnv(t)

	body := env.siemPanel(t)
	if !strings.Contains(body, "No events yet.") {
		t.Errorf("the viewer does not explain the empty state:\n%s", body)
	}
}
