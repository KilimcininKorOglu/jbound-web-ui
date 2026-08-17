package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"jbound/internal/audit"
	"jbound/internal/i18n"
	appsettings "jbound/internal/settings"
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

// setForwarding flips the switch the way the card does.
func (e *fleetEnv) setForwarding(t *testing.T, on bool) *httptest.ResponseRecorder {
	t.Helper()

	values := url.Values{}
	if on {
		// An unchecked switch sends nothing at all, which is how the handler
		// reads a false.
		values.Set("forwarding", "on")
	}
	return e.adminForm(t, http.MethodPost, "/siem/forwarding", e.cookie, values)
}

// The rules stay on the host when the mirror is switched off, so a receiver
// under repair costs nothing to restore.
func TestTheForwardingSwitchKeepsTheRules(t *testing.T) {
	const rule = "local6.*    @@siem-sink:514"

	env := newFleetEnv(t)
	env.saveRules(t, rule)

	if recorder := env.setForwarding(t, false); recorder.Code != http.StatusOK {
		t.Fatalf("POST /siem/forwarding = %d, want 200", recorder.Code)
	}

	if env.app.Settings.Bool(appsettings.SIEMForwardingEnabled) {
		t.Error("the setting is still on after the switch was cleared")
	}

	body := env.siemPanel(t)
	if !strings.Contains(body, "forwarding disabled") {
		t.Error("the card does not say that forwarding is off")
	}
	if !strings.Contains(body, rule) {
		t.Error("the rule was lost when the mirror was switched off")
	}
}

func TestTheForwardingSwitchStopsTheMirror(t *testing.T) {
	env := newFleetEnv(t)

	if recorder := env.setForwarding(t, false); recorder.Code != http.StatusOK {
		t.Fatalf("POST /siem/forwarding = %d, want 200", recorder.Code)
	}

	before := len(env.forwarder.sent())
	env.saveRules(t, "local6.*    @@siem-sink:514")

	if after := len(env.forwarder.sent()); after != before {
		t.Errorf("%d entry(s) were forwarded with the switch off, want none",
			after-before)
	}
}

func TestTheForwardingSwitchIsAudited(t *testing.T) {
	env := newFleetEnv(t)
	env.setForwarding(t, false)

	var details string
	err := env.db.QueryRow(
		`SELECT details FROM audit_logs
		  WHERE action = 'siem_config' ORDER BY id DESC LIMIT 1`).Scan(&details)
	if err != nil {
		t.Fatalf("cannot read the audit table: %v", err)
	}
	if !strings.Contains(details, "disabled") {
		t.Errorf("the entry reads %q, want it to say the mirror was disabled", details)
	}
}

func TestTheForwardingSwitchIsAdminTerritory(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.login(t, "dnsuser")

	recorder := env.do(t, postForm("/siem/forwarding", "forwarding=on"), cookie)
	if recorder.Code != http.StatusForbidden {
		t.Errorf("POST /siem/forwarding as a plain user = %d, want 403", recorder.Code)
	}
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

	// The panel writes rules, never rsyslog configuration. What lands on disk
	// is the file the apply step reads as root.
	content, err := os.ReadFile(filepath.Join(env.siemDir, "siem-rules.conf"))
	if err != nil {
		t.Fatalf("cannot read the rules file: %v", err)
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

func TestASaveThatCannotWriteTheFileIsAServerError(t *testing.T) {
	// A backend fault answered as a client fault never reaches a log alert
	// that counts server errors, and the panel would carry it silently.
	if os.Geteuid() == 0 {
		t.Skip("root writes a read only file regardless of its mode")
	}
	env := newFleetEnv(t)

	if recorder := env.saveRules(t, "local6.*    @@siem-sink:514"); recorder.Code != http.StatusOK {
		t.Fatalf("the first save returned %d", recorder.Code)
	}

	conf := filepath.Join(env.siemDir, "siem-rules.conf")
	if err := os.Chmod(conf, 0o400); err != nil {
		t.Fatalf("cannot make the rules file read only: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(conf, 0o600) })

	recorder := env.saveRules(t, "local6.*    @@other.example.net:514")
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", recorder.Code)
	}

	// The panel swaps nothing on a 500, so the message travels in the header
	// and the client raises it as a toast.
	if !strings.Contains(recorder.Header().Get("HX-Trigger"), "toast") {
		t.Errorf("the failure carries no message: %q", recorder.Header().Get("HX-Trigger"))
	}
	// The body of a server error names nothing about the host.
	if strings.Contains(recorder.Body.String(), conf) {
		t.Errorf("the response names the configuration path:\n%s", recorder.Body.String())
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

func TestTheViewerShowsTheTrailNewestFirst(t *testing.T) {
	// It reads the audit trail rather than a log file, so what it shows is what
	// a receiver was given rather than what a local daemon happened to write.
	env := newFleetEnv(t)
	env.seedLog(t)

	body := env.siemPanel(t)
	if !strings.Contains(body, "CEF:0|JBound|JBoundDNSPanel") {
		t.Fatalf("the viewer shows no events:\n%s", body)
	}

	// The newest row of the seed is the reload that follows the record change.
	reload := strings.Index(body, audit.ActionDNSRestart)
	added := strings.Index(body, audit.ActionDNSAdd)
	if reload < 0 || added < 0 {
		t.Fatalf("the viewer does not show both seeded actions:\n%s", body)
	}
	if reload > added {
		t.Error("the older event is shown above the newer one")
	}
}

func TestTheViewerShowsWhatTheReceiverWasGiven(t *testing.T) {
	// The same rendering the sender uses. Two renderings would drift, and this
	// page would become a picture of something nobody received.
	env := newFleetEnv(t)
	env.seedLog(t)

	body := env.siemPanel(t)
	if !strings.Contains(body, "suser=dnsadmin") {
		t.Errorf("the line does not name the actor:\n%s", body)
	}
	if !strings.Contains(body, "dvchost=") {
		t.Errorf("the line does not name the panel host:\n%s", body)
	}
}

func TestAViewerWithNothingToShowSaysSo(t *testing.T) {
	// Reachable two ways: a trail that holds nothing, and a read of it that
	// failed. Both leave the same empty list, and an empty box with no sentence
	// reads as a broken page.
	env := newFleetEnv(t)

	if _, err := env.db.Exec("DELETE FROM audit_logs"); err != nil {
		t.Fatalf("cannot empty the trail: %v", err)
	}

	body := env.siemPanel(t)
	if !strings.Contains(body, env.app.Catalogs.Catalog(i18n.Default).T("siem.no_events")) {
		t.Errorf("the viewer does not explain the empty state:\n%s", body)
	}
}

func TestTurningTheMirrorOffReachesTheMirror(t *testing.T) {
	// Everything after this entry is silence, so a receiver that never sees it
	// cannot tell a silenced panel from a quiet one.
	env := newFleetEnv(t)

	before := len(env.forwarder.sent())
	if recorder := env.setForwarding(t, false); recorder.Code != http.StatusOK {
		t.Fatalf("POST /siem/forwarding = %d, want 200", recorder.Code)
	}

	sent := env.forwarder.sent()[before:]
	if len(sent) != 1 {
		t.Fatalf("%d entry(s) reached the mirror, want the one that silenced it", len(sent))
	}
	if !strings.Contains(sent[0].Details, "disabled") {
		t.Errorf("the forwarded entry reads %q, want the disabling one", sent[0].Details)
	}
}

func TestTurningTheMirrorOffTwiceForwardsNothingTheSecondTime(t *testing.T) {
	// The switch was already off, so nobody is listening and the entry has no
	// receiver to reach. Forwarding it anyway would defeat the switch.
	env := newFleetEnv(t)
	env.setForwarding(t, false)

	before := len(env.forwarder.sent())
	env.setForwarding(t, false)

	if after := len(env.forwarder.sent()); after != before {
		t.Errorf("%d entry(s) were forwarded with the switch already off, want none",
			after-before)
	}
}

func TestTheSettingsPageCannotSilenceTheMirrorUnnoticed(t *testing.T) {
	// The same switch lives on the settings page, and it saves every setting
	// in one submission.
	env := newFleetEnv(t)

	before := len(env.forwarder.sent())
	// An unchecked switch sends nothing at all, which is how the handler reads
	// a false.
	body := env.settingsForm(t, map[string]string{appsettings.SIEMForwardingEnabled: ""})

	if recorder := env.do(t, postForm("/settings", body), env.adminCookie(t)); recorder.Code != http.StatusOK {
		t.Fatalf("POST /settings = %d, want 200", recorder.Code)
	}

	var forwarded bool
	for _, entry := range env.forwarder.sent()[before:] {
		if entry.Action == audit.ActionSettingsUpdate {
			forwarded = true
		}
	}
	if !forwarded {
		t.Error("the save that silenced the mirror never reached it")
	}
}

// --- The receiver the panel reaches itself --------------------------------

// saveReceiver submits the receiver card.
func (e *fleetEnv) saveReceiver(t *testing.T, protocol, host, port string) *httptest.ResponseRecorder {
	t.Helper()

	return e.adminForm(t, http.MethodPost, "/siem/receiver", e.cookie, url.Values{
		"protocol":      {protocol},
		"receiver_host": {host},
		"receiver_port": {port},
	})
}

func TestTheReceiverCardOffersEveryProtocol(t *testing.T) {
	env := newFleetEnv(t)
	body := env.siemPanel(t)

	for _, field := range []string{"protocol", "receiver-host", "receiver-port"} {
		if !strings.Contains(body, `data-field="`+field+`"`) {
			t.Errorf("the card has no %s control:\n%s", field, body)
		}
	}
	for _, protocol := range []string{"off", "udp", "tcp", "tls"} {
		if !strings.Contains(body, `value="`+protocol+`"`) {
			t.Errorf("the card does not offer %q", protocol)
		}
	}
}

func TestAReceiverWithNoProtocolReadsAsOff(t *testing.T) {
	// The default, and what every existing install starts as.
	env := newFleetEnv(t)
	body := env.siemPanel(t)

	if !strings.Contains(body, `data-field="receiver-state"`) {
		t.Fatalf("the card does not report its state:\n%s", body)
	}
	catalog := env.app.Catalogs.Catalog(i18n.Default)
	if !strings.Contains(body, catalog.T("siem.receiver_off")) {
		t.Errorf("a receiver that was never configured does not read as off:\n%s", body)
	}
}

func TestTheSavedReceiverComesBackInTheCard(t *testing.T) {
	env := newFleetEnv(t)

	if recorder := env.saveReceiver(t, "tcp", "siem.example.net", "6514"); recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200:\n%s", recorder.Code, recorder.Body.String())
	}

	body := env.siemPanel(t)
	if !strings.Contains(body, `value="siem.example.net"`) {
		t.Errorf("the host was not kept:\n%s", body)
	}
	if !strings.Contains(body, `value="6514"`) {
		t.Errorf("the port was not kept:\n%s", body)
	}
	if !strings.Contains(body, `value="tcp" selected`) {
		t.Errorf("the protocol was not kept:\n%s", body)
	}

	// The settings page holds the same three values, so a change here is a
	// change there.
	if got := env.app.Settings.String(appsettings.SIEMReceiverHost); got != "siem.example.net" {
		t.Errorf("the stored host is %q", got)
	}
	if got := env.app.Settings.Int(appsettings.SIEMReceiverPort); got != 6514 {
		t.Errorf("the stored port is %d", got)
	}
}

func TestAPortOutsideTheRangeComesBackWithTheReason(t *testing.T) {
	// The operator typed it, so it is a form to correct rather than a server
	// error nobody can act on.
	env := newFleetEnv(t)

	recorder := env.saveReceiver(t, "tcp", "siem.example.net", "70000")
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "65535") {
		t.Errorf("the reason does not name the bound:\n%s", recorder.Body.String())
	}
	if got := env.app.Settings.String(appsettings.SIEMReceiverHost); got != "" {
		t.Errorf("a refused submission stored the host anyway: %q", got)
	}
}

func TestAnUnknownProtocolIsRefused(t *testing.T) {
	env := newFleetEnv(t)

	recorder := env.saveReceiver(t, "carrier-pigeon", "siem.example.net", "514")
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", recorder.Code)
	}
}

func TestTheReceiverGoesBackToOffWithNoHost(t *testing.T) {
	// Off is a state an operator chooses, so the host may be emptied.
	env := newFleetEnv(t)

	if recorder := env.saveReceiver(t, "tcp", "siem.example.net", "514"); recorder.Code != http.StatusOK {
		t.Fatalf("the first save returned %d", recorder.Code)
	}
	if recorder := env.saveReceiver(t, "off", "", "514"); recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}

	if got := env.app.Settings.String(appsettings.SIEMProtocol); got != "off" {
		t.Errorf("the protocol is %q, want off", got)
	}
}

func TestSavingTheReceiverIsAudited(t *testing.T) {
	// It decides where the panel's own trail goes, which is exactly the kind of
	// change the trail has to carry.
	env := newFleetEnv(t)

	env.saveReceiver(t, "tls", "siem.example.net", "6514")

	body := env.logTable(t, "action="+audit.ActionSIEMConfig)
	if !strings.Contains(body, "tls siem.example.net:6514") {
		t.Errorf("the trail does not name the receiver:\n%s", body)
	}
}
