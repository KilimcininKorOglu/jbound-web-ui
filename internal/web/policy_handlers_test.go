package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"jbound/internal/transport"
)

func TestTheFormOffersTheTwoBlockingBehaviours(t *testing.T) {
	// They sit in the type list rather than on a page of their own, because
	// what the operator is deciding is what one name answers.
	env := newFleetEnv(t)

	recorder := env.do(t, httptest.NewRequest(http.MethodGet, "/dns/records/new", nil), env.cookie)
	body := recorder.Body.String()

	for _, want := range []string{`value="NXDOMAIN"`, `value="REFUSED"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the form does not offer %s:\n%s", want, body)
		}
	}
}

func TestTheValueFieldIsMarkedSoItCanBeHidden(t *testing.T) {
	// The selector switches between the two shapes without a round trip, and
	// the content security policy allows no inline script to find the field.
	env := newFleetEnv(t)

	recorder := env.do(t, httptest.NewRequest(http.MethodGet, "/dns/records/new", nil), env.cookie)
	body := recorder.Body.String()

	if !strings.Contains(body, `data-field="value"`) {
		t.Errorf("the value field carries no marker:\n%s", body)
	}
}

func TestBlockingANameFromThePanelWritesAZoneLine(t *testing.T) {
	env := newFleetEnv(t)

	recorder := env.adminForm(t, http.MethodPost, "/dns/records", env.cookie, groupForm(url.Values{
		"fqdn": {"ads.example.local"}, "type": {"NXDOMAIN"},
	}))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200:\n%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "Name blocked") {
		t.Errorf("the result does not say what happened:\n%s", recorder.Body.String())
	}

	for id := int64(1); id <= 3; id++ {
		file := env.target(id).file()
		if !strings.Contains(file, `local-zone: "ads.example.local." always_nxdomain`) {
			t.Errorf("server %d did not receive the block:\n%s", id, file)
		}
	}
}

func TestARecordUnderABlockedNameIsRefusedWithTheReason(t *testing.T) {
	// The record would be written, pass the check, survive the reload and
	// answer nothing, and the panel would go on listing it.
	env := newFleetEnv(t)

	if recorder := env.adminForm(t, http.MethodPost, "/dns/records", env.cookie,
		groupForm(url.Values{"fqdn": {"ads.example.local"}, "type": {"NXDOMAIN"}})); recorder.Code != http.StatusOK {
		t.Fatalf("cannot block the name: %d", recorder.Code)
	}

	recorder := env.adminForm(t, http.MethodPost, "/dns/records", env.cookie, groupForm(url.Values{
		"fqdn": {"www.ads.example.local"}, "type": {"A"}, "value": {"10.0.0.50"},
	}))
	if recorder.Code == http.StatusOK {
		t.Fatalf("the record was accepted:\n%s", recorder.Body.String())
	}

	body := recorder.Body.String()
	if !strings.Contains(body, "ads.example.local") {
		t.Errorf("the refusal does not name the block:\n%s", body)
	}
	for id := int64(1); id <= 3; id++ {
		if strings.Contains(env.target(id).file(), "www.ads.example.local") {
			t.Errorf("server %d took the record anyway", id)
		}
	}
}

func TestABlockedNameCarriesNoValueIntoTheForm(t *testing.T) {
	// A value that reached the file would reach nothing, so the panel refuses
	// it rather than dropping it quietly.
	env := newFleetEnv(t)

	recorder := env.adminForm(t, http.MethodPost, "/dns/records", env.cookie, groupForm(url.Values{
		"fqdn": {"ads.example.local"}, "type": {"NXDOMAIN"}, "value": {"10.0.0.50"},
	}))
	// The same 400 every other invalid record earns, so one refusal reads one
	// way whatever was wrong with it.
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400:\n%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "no value") {
		t.Errorf("the refusal does not say why:\n%s", recorder.Body.String())
	}
}

func TestABlockIsAcceptedWithTheFormsOwnDefaults(t *testing.T) {
	// The preference is a hidden field and the add form fills it with ten
	// before anybody chooses a type. Refusing the block over it would be the
	// panel rejecting a number it wrote itself, which no operator can see or
	// correct.
	env := newFleetEnv(t)

	recorder := env.adminForm(t, http.MethodPost, "/dns/records", env.cookie, groupForm(url.Values{
		"fqdn": {"ads.example.local"}, "type": {"NXDOMAIN"}, "priority": {"10"},
	}))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200:\n%s", recorder.Code, recorder.Body.String())
	}
}

func TestTheTableShowsABlockAsADecision(t *testing.T) {
	// A row with an empty value column reads as a record whose address went
	// missing.
	env := newFleetEnv(t)

	if recorder := env.adminForm(t, http.MethodPost, "/dns/records", env.cookie,
		groupForm(url.Values{"fqdn": {"ads.example.local"}, "type": {"NXDOMAIN"}})); recorder.Code != http.StatusOK {
		t.Fatalf("cannot block the name: %d", recorder.Code)
	}

	body := env.table(t, "scope=group&group_id=1")
	if !strings.Contains(body, "ads.example.local") {
		t.Fatalf("the block is not listed:\n%s", body)
	}
	if !strings.Contains(body, `bg-label-danger">NXDOMAIN`) {
		t.Errorf("the block carries no badge of its own:\n%s", body)
	}
	if !strings.Contains(body, `data-field="blocked"`) {
		t.Errorf("the value column says nothing about the block:\n%s", body)
	}
}

func TestABlockIsRemovedThroughTheSameTable(t *testing.T) {
	env := newFleetEnv(t)

	if recorder := env.adminForm(t, http.MethodPost, "/dns/records", env.cookie,
		groupForm(url.Values{"fqdn": {"ads.example.local"}, "type": {"NXDOMAIN"}})); recorder.Code != http.StatusOK {
		t.Fatalf("cannot block the name: %d", recorder.Code)
	}

	recorder := env.deleteRecord(t, groupForm(url.Values{
		"fqdn": {"ads.example.local"}, "type": {"NXDOMAIN"}, "value": {""}, "priority": {"0"},
	}))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200:\n%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "Block removed") {
		t.Errorf("the result does not say what happened:\n%s", recorder.Body.String())
	}

	for id := int64(1); id <= 3; id++ {
		if strings.Contains(env.target(id).file(), "always_nxdomain") {
			t.Errorf("server %d still holds the block", id)
		}
	}
}

// --- Reporting a failure ---------------------------------------------------

func TestAReportReachesThePageEvenWhenEveryServerFailed(t *testing.T) {
	// htmx swaps no error response by default, and a fleet operation where
	// every server failed answers 500. Without the marker the body reaches the
	// browser and is thrown away, leaving the operator with a toast that
	// vanishes and no way to find out which server said what.
	env := newFleetEnv(t)

	if recorder := env.adminForm(t, http.MethodPost, "/dns/records", env.cookie,
		groupForm(url.Values{"fqdn": {"ads.example.local"}, "type": {"NXDOMAIN"}})); recorder.Code != http.StatusOK {
		t.Fatalf("cannot block the name: %d", recorder.Code)
	}

	recorder := env.adminForm(t, http.MethodPost, "/dns/records", env.cookie, groupForm(url.Values{
		"fqdn": {"www.ads.example.local"}, "type": {"A"}, "value": {"10.0.0.50"},
	}))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", recorder.Code)
	}
	if recorder.Header().Get(FragmentHeader) == "" {
		t.Errorf("the body is not marked as one the page should show")
	}

	body := recorder.Body.String()
	for _, want := range []string{"dns1", "dns2", "dns3", `data-field="status">failed<`} {
		if !strings.Contains(body, want) {
			t.Errorf("the report does not carry %q:\n%s", want, body)
		}
	}
}

func TestEveryFailureSaysWhoRefused(t *testing.T) {
	// A change the panel refused is the operator's to correct, and a server
	// the panel could not reach is a matter for that host. The message says
	// what happened, and this says where to look.
	env := newFleetEnv(t)
	env.target(3).writeErr = transport.ErrCommandFailed

	recorder := env.adminForm(t, http.MethodPost, "/dns/records", env.cookie, groupForm(url.Values{
		"fqdn": {"new.example.local"}, "type": {"A"}, "value": {"10.0.0.50"},
	}))
	if recorder.Code != http.StatusMultiStatus {
		t.Fatalf("status = %d, want 207:\n%s", recorder.Code, recorder.Body.String())
	}

	body := recorder.Body.String()
	if !strings.Contains(body, `data-field="source"`) {
		t.Errorf("the report names no source:\n%s", body)
	}
	if !strings.Contains(body, "resolver") {
		t.Errorf("a command the resolver refused is not reported as its own:\n%s", body)
	}
}

func TestARefusedChangeIsReportedAsThePanelsOwn(t *testing.T) {
	// It would fail the same way on every server, so sending the operator to
	// look at one of them would be sending them to the wrong place.
	env := newFleetEnv(t)

	if recorder := env.adminForm(t, http.MethodPost, "/dns/records", env.cookie,
		groupForm(url.Values{"fqdn": {"ads.example.local"}, "type": {"NXDOMAIN"}})); recorder.Code != http.StatusOK {
		t.Fatalf("cannot block the name: %d", recorder.Code)
	}

	recorder := env.adminForm(t, http.MethodPost, "/dns/records", env.cookie, groupForm(url.Values{
		"fqdn": {"www.ads.example.local"}, "type": {"A"}, "value": {"10.0.0.50"},
	}))

	source := between(t, recorder.Body.String(), `data-field="source">`, "</span>")
	if source != "panel" {
		t.Errorf("the source reads %q, want the panel's own", source)
	}
}

func TestTheReportCountsWhatHappened(t *testing.T) {
	// The rows say which server did what. The line above them says how many,
	// which is the first thing an operator reads on a fleet of seven.
	env := newFleetEnv(t)
	env.target(3).writeErr = transport.ErrCommandFailed

	recorder := env.adminForm(t, http.MethodPost, "/dns/records", env.cookie, groupForm(url.Values{
		"fqdn": {"new.example.local"}, "type": {"A"}, "value": {"10.0.0.50"},
	}))

	body := recorder.Body.String()
	if !strings.Contains(body, `data-field="counts"`) {
		t.Fatalf("the report carries no summary:\n%s", body)
	}
	counts := between(t, body, `data-field="counts">`, "</p>")
	if !strings.Contains(counts, "2 succeeded") || !strings.Contains(counts, "1 failed") {
		t.Errorf("the summary reads %q", counts)
	}
}
