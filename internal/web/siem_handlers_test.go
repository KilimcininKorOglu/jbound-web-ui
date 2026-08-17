package web

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"jbound/internal/audit"
	"jbound/internal/i18n"
	appsettings "jbound/internal/settings"
	"jbound/internal/siem"
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

// useTestReceiver points the panel at the listener the harness opened and
// settles the queue on the trail as it stands.
//
// The settling matters: a newly named receiver is given what happens next
// rather than everything the panel has ever logged, so a test that skipped it
// would assert against an empty delivery.
func (e *fleetEnv) useTestReceiver(t *testing.T) {
	t.Helper()

	host, port, err := net.SplitHostPort(e.receiver.address)
	if err != nil {
		t.Fatalf("cannot read the receiver address: %v", err)
	}
	if recorder := e.saveReceiver(t, "tcp", host, port); recorder.Code != http.StatusOK {
		t.Fatalf("cannot name the receiver: %d", recorder.Code)
	}
	e.backlog.Drain(context.Background())
}

// drain sends what the trail owes the receiver, and returns every line it has
// been given since the count the caller passed.
func (e *fleetEnv) drain(t *testing.T, before, want int) []string {
	t.Helper()

	e.backlog.Drain(context.Background())
	lines := e.receiver.lines(t, before+want)
	if len(lines) < before {
		t.Fatalf("the receiver lost %d line(s)", before-len(lines))
	}
	return lines[before:]
}

func TestTheForwardingSwitchStopsTheMirror(t *testing.T) {
	env := newFleetEnv(t)
	env.useTestReceiver(t)

	if recorder := env.setForwarding(t, false); recorder.Code != http.StatusOK {
		t.Fatalf("POST /siem/forwarding = %d, want 200", recorder.Code)
	}
	// The entry that silenced it goes out whatever the switch says.
	before := len(env.drain(t, 0, 1))

	// An ordinary action, which is what the switch is there to stop.
	env.seedLog(t)

	if sent := env.drain(t, before, 0); len(sent) != 0 {
		t.Errorf("%d line(s) went out with the switch off, want none:\n%v",
			len(sent), sent)
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

func TestTheTestEventsGoOutAndAreAudited(t *testing.T) {
	env := newFleetEnv(t)
	env.useTestReceiver(t)
	before := len(env.receiver.lines(t, 0))

	recorder := env.adminForm(t, http.MethodPost, "/siem/test", env.cookie, url.Values{})
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200:\n%s", recorder.Code, recorder.Body.String())
	}

	// The test events go straight to the receiver rather than through the
	// queue, because an operator checking a collector must not be writing to
	// the trail every time they press the button.
	sent := env.receiver.lines(t, before+siem.TestEventCount)[before:]
	if len(sent) != siem.TestEventCount {
		t.Fatalf("the panel sent %d events, want %d", len(sent), siem.TestEventCount)
	}

	actions := map[string]bool{}
	for _, line := range sent {
		for _, action := range []string{"login", "dns_add", "dns_delete", "login_failed"} {
			if strings.Contains(line, "|"+action+"|") {
				actions[action] = true
			}
		}
	}
	for _, want := range []string{"login", "dns_add", "dns_delete", "login_failed"} {
		if !actions[want] {
			t.Errorf("the run sent no %s event", want)
		}
	}

	// The run itself is a row in the trail, which is what says who pressed it.
	body := env.logTable(t, "action="+audit.ActionSIEMTest)
	if !strings.Contains(body, "test events sent") {
		t.Errorf("the trail does not carry the run:\n%s", body)
	}
	if !strings.Contains(recorder.Body.String(), "4 test events sent to the receiver.") {
		t.Errorf("the panel does not report what it sent:\n%s", recorder.Body.String())
	}
}

func TestATestWithNoReceiverSaysSoRatherThanFailing(t *testing.T) {
	// Nothing to test. Naming the missing receiver is more use than a failure
	// from a socket that was never opened.
	env := newFleetEnv(t)

	recorder := env.adminForm(t, http.MethodPost, "/siem/test", env.cookie, url.Values{})
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", recorder.Code)
	}
	catalog := env.app.Catalogs.Catalog(i18n.Default)
	if !strings.Contains(recorder.Body.String(), catalog.T("siem.test_needs_receiver")) {
		t.Errorf("the card does not say a receiver is missing:\n%s", recorder.Body.String())
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
	env.useTestReceiver(t)
	before := len(env.receiver.lines(t, 0))

	if recorder := env.setForwarding(t, false); recorder.Code != http.StatusOK {
		t.Fatalf("POST /siem/forwarding = %d, want 200", recorder.Code)
	}

	sent := env.drain(t, before, 1)
	if len(sent) != 1 {
		t.Fatalf("%d line(s) reached the receiver, want the one that silenced it", len(sent))
	}
	if !strings.Contains(sent[0], "disabled") {
		t.Errorf("the line reads %q, want the disabling one", sent[0])
	}
}

func TestTheSettingsPageCannotSilenceTheMirrorUnnoticed(t *testing.T) {
	// The same switch lives on the settings page, and it saves every setting
	// in one submission.
	env := newFleetEnv(t)
	env.useTestReceiver(t)
	before := len(env.receiver.lines(t, 0))

	// An unchecked switch sends nothing at all, which is how the handler reads
	// a false.
	body := env.settingsForm(t, map[string]string{appsettings.SIEMForwardingEnabled: ""})

	if recorder := env.do(t, postForm("/settings", body), env.adminCookie(t)); recorder.Code != http.StatusOK {
		t.Fatalf("POST /settings = %d, want 200", recorder.Code)
	}

	var forwarded bool
	for _, line := range env.drain(t, before, 1) {
		if strings.Contains(line, "|"+audit.ActionSettingsUpdate+"|") {
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

func TestSavingTheReceiverNeedsACSRFToken(t *testing.T) {
	// It decides where the panel's own trail goes, so a cross site submission
	// could send the trail somewhere the operator never named.
	env := newFleetEnv(t)

	recorder := env.do(t,
		postForm("/siem/receiver", "protocol=tcp&receiver_host=evil.example&receiver_port=514"),
		env.cookie)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", recorder.Code)
	}
	if got := env.app.Settings.String(appsettings.SIEMReceiverHost); got != "" {
		t.Errorf("the submission stored the host anyway: %q", got)
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
