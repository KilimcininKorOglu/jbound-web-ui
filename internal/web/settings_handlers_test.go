package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"unbound-web/internal/settings"
)

// settingsForm returns the current values as a form body, so a test can change
// one field and submit the page as a browser does.
func (e *testEnv) settingsForm(t *testing.T, changes map[string]string) string {
	t.Helper()

	form := url.Values{}
	for key, value := range e.app.Settings.Values().All() {
		definition, ok := settings.Lookup(key)
		if !ok {
			continue
		}
		// An unchecked switch sends nothing at all, which is how the handler
		// reads a false.
		if definition.Kind == settings.KindBool && value != "true" {
			continue
		}
		form.Set(key, value)
	}
	for key, value := range changes {
		if value == "" {
			form.Del(key)
			continue
		}
		form.Set(key, value)
	}
	form.Set("csrf_token", e.csrfTokenOf(t, e.adminCookie(t)))
	return form.Encode()
}

// adminCookie signs the administrator in once per test.
func (e *testEnv) adminCookie(t *testing.T) *http.Cookie {
	t.Helper()
	if e.settingsCookie == nil {
		e.settingsCookie = e.login(t, "dnsadmin")
	}
	return e.settingsCookie
}

func TestTheSettingsPageIsAdminTerritory(t *testing.T) {
	// A plain user changing the session timeout or the rate limit would be
	// changing how everybody else signs in.
	env := newTestEnv(t)
	cookie := env.login(t, "dnsuser")

	recorder := env.do(t, httptest.NewRequest(http.MethodGet, "/settings", nil), cookie)
	if recorder.Code != http.StatusForbidden {
		t.Errorf("GET /settings as a plain user = %d, want 403", recorder.Code)
	}

	recorder = env.do(t, postForm("/settings", env.settingsForm(t, nil)), cookie)
	if recorder.Code != http.StatusForbidden {
		t.Errorf("POST /settings as a plain user = %d, want 403", recorder.Code)
	}
}

func TestTheSettingsPageNeedsASession(t *testing.T) {
	env := newTestEnv(t)

	recorder := env.do(t, httptest.NewRequest(http.MethodGet, "/settings", nil))
	if recorder.Code != http.StatusSeeOther {
		t.Errorf("GET /settings = %d, want a redirect to the login page", recorder.Code)
	}
}

// The page is built from the registry, so every setting has to reach it. A key
// that is stored and never shown cannot be corrected.
func TestTheSettingsPageShowsEverySetting(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.adminCookie(t)

	recorder := env.do(t, httptest.NewRequest(http.MethodGet, "/settings", nil), cookie)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /settings = %d, want 200", recorder.Code)
	}
	body := recorder.Body.String()

	for _, definition := range settings.Definitions() {
		if !strings.Contains(body, `data-field="`+definition.Key+`"`) {
			t.Errorf("the page has no control for %s", definition.Key)
		}
		if !strings.Contains(body, definition.Label) {
			t.Errorf("the page does not label %s", definition.Key)
		}
	}
}

func TestASavedSettingIsInEffectWithoutARestart(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.adminCookie(t)

	body := env.settingsForm(t, map[string]string{settings.RecordsPerPage: "50"})
	recorder := env.do(t, postForm("/settings", body), cookie)
	if recorder.Code != http.StatusOK {
		t.Fatalf("POST /settings = %d, want 200", recorder.Code)
	}

	if got := env.app.Settings.Int(settings.RecordsPerPage); got != 50 {
		t.Errorf("records per page = %d, want 50", got)
	}
}

// A refused submission comes back with what the operator typed, so the
// correction starts from there rather than from the stored value.
func TestARefusedSettingComesBackWithTheTypedValue(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.adminCookie(t)

	body := env.settingsForm(t, map[string]string{settings.SessionIdleTimeout: "10s"})
	recorder := env.do(t, postForm("/settings", body), cookie)

	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("POST /settings = %d, want 422", recorder.Code)
	}
	if got := env.app.Settings.Duration(settings.SessionIdleTimeout); got != 30*time.Minute {
		t.Errorf("session idle timeout = %s, want the unchanged 30m", got)
	}

	page := recorder.Body.String()
	if !strings.Contains(page, `value="10s"`) {
		t.Error("the refused value is not in the form")
	}
	if !strings.Contains(page, settings.SessionIdleTimeout) {
		t.Error("the message does not name the setting that was refused")
	}
}

// The whole page is one form, so a refusal must not store the half that parsed.
func TestARefusedSubmissionStoresNothing(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.adminCookie(t)

	body := env.settingsForm(t, map[string]string{
		settings.RecordsPerPage:     "50",
		settings.SessionIdleTimeout: "10s",
	})
	if recorder := env.do(t, postForm("/settings", body), cookie); recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("POST /settings = %d, want 422", recorder.Code)
	}

	if got := env.app.Settings.Int(settings.RecordsPerPage); got != 25 {
		t.Errorf("records per page = %d, want the unchanged 25", got)
	}
}

// An unchecked switch sends nothing at all. Reading absence as "leave it as it
// was" would make a switch impossible to turn off.
func TestAnUncheckedSwitchIsStoredAsFalse(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.adminCookie(t)

	body := env.settingsForm(t, map[string]string{settings.SIEMForwardingEnabled: ""})
	if recorder := env.do(t, postForm("/settings", body), cookie); recorder.Code != http.StatusOK {
		t.Fatalf("POST /settings = %d, want 200", recorder.Code)
	}

	if env.app.Settings.Bool(settings.SIEMForwardingEnabled) {
		t.Error("the switch is still on after being submitted unchecked")
	}
}

func TestSavingTheSettingsIsAudited(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.adminCookie(t)

	body := env.settingsForm(t, map[string]string{settings.RecordsPerPage: "40"})
	if recorder := env.do(t, postForm("/settings", body), cookie); recorder.Code != http.StatusOK {
		t.Fatalf("POST /settings = %d, want 200", recorder.Code)
	}

	var action, username string
	err := env.db.QueryRow(
		`SELECT action, username FROM audit_logs
		  WHERE action = ? ORDER BY id DESC LIMIT 1`,
		"settings_update").Scan(&action, &username)
	if err != nil {
		t.Fatalf("cannot read the audit table: %v", err)
	}
	if username != "dnsadmin" {
		t.Errorf("the entry names %s, want dnsadmin", username)
	}
}

// The change has to survive the process, which is the point of storing it.
func TestASavedSettingIsReadBackFromTheDatabase(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.adminCookie(t)

	body := env.settingsForm(t, map[string]string{settings.FleetMaxConcurrent: "9"})
	if recorder := env.do(t, postForm("/settings", body), cookie); recorder.Code != http.StatusOK {
		t.Fatalf("POST /settings = %d, want 200", recorder.Code)
	}

	// A second service over the same database is what the next start reads.
	reloaded := settings.NewService(env.settingsStore)
	if err := reloaded.Load(context.Background()); err != nil {
		t.Fatalf("cannot load the settings: %v", err)
	}
	if got := reloaded.Int(settings.FleetMaxConcurrent); got != 9 {
		t.Errorf("fleet concurrency = %d after a reload, want 9", got)
	}
}

func TestTheSettingsFormIsRefusedWithoutTheToken(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.adminCookie(t)

	recorder := env.do(t, postForm("/settings", "records_per_page=50"), cookie)
	if recorder.Code != http.StatusForbidden {
		t.Errorf("POST /settings without a token = %d, want 403", recorder.Code)
	}
	if got := env.app.Settings.Int(settings.RecordsPerPage); got != 25 {
		t.Errorf("records per page = %d, want the unchanged 25", got)
	}
}
