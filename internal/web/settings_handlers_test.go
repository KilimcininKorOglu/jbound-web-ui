package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"unbound-web/internal/i18n"
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
		label := env.app.Catalogs.Catalog(i18n.Default).T("setting." + definition.Key + ".label")
		if !strings.Contains(body, label) {
			t.Errorf("the page does not label %s", definition.Key)
		}
	}
}

// A choice list that reads "en" and "system" asks the operator to know the
// stored values. The names come from the same keys the layout controls use.
func TestTheChoicesOfASettingAreNamed(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.adminCookie(t)

	body := env.do(t, httptest.NewRequest(http.MethodGet, "/settings", nil), cookie).Body.String()

	for _, raw := range []string{">en</option>", ">system</option>"} {
		if strings.Contains(body, raw) {
			t.Errorf("a choice reads %s rather than its name", raw)
		}
	}

	catalog := env.app.Catalogs.Catalog(i18n.Default)
	for _, key := range []string{"layout.language.en", "layout.theme.system"} {
		if !strings.Contains(body, ">"+catalog.T(key)+"</option>") {
			t.Errorf("the page does not name %s", key)
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

// A message above fifteen fields does not say which one to correct, so the
// control that was refused says it itself and says it to a screen reader.
func TestARefusedFieldIsMarked(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.adminCookie(t)

	body := env.settingsForm(t, map[string]string{settings.SessionIdleTimeout: "10s"})
	recorder := env.do(t, postForm("/settings", body), cookie)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("POST /settings = %d, want 422", recorder.Code)
	}
	page := recorder.Body.String()

	control := regexp.MustCompile(
		`(?s)<input[^>]*id="` + settings.SessionIdleTimeout + `"[^>]*>`).FindString(page)
	if control == "" {
		t.Fatalf("the form carries no control for %s", settings.SessionIdleTimeout)
	}
	if !strings.Contains(control, `aria-invalid="true"`) {
		t.Error("the refused control is not marked as refused")
	}
	if !strings.Contains(control, settings.SessionIdleTimeout+"-error") {
		t.Error("the refused control does not point at its own problem")
	}
	if !strings.Contains(page, `id="`+settings.SessionIdleTimeout+`-error"`) {
		t.Error("the problem the control points at is not on the page")
	}

	// Only the refused one. Marking every field would say nothing.
	other := regexp.MustCompile(
		`(?s)<input[^>]*id="` + settings.SessionLifetime + `"[^>]*>`).FindString(page)
	if strings.Contains(other, "aria-invalid") {
		t.Error("a field that parsed is marked as refused")
	}
}

// A rule that reads two settings marks both, because either one of them is the
// correction.
func TestABrokenRuleMarksEverySettingItReads(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.adminCookie(t)

	body := env.settingsForm(t, map[string]string{
		settings.CacheRefreshInterval: "30m",
		settings.CacheStaleAfter:      "5m",
	})
	recorder := env.do(t, postForm("/settings", body), cookie)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("POST /settings = %d, want 422", recorder.Code)
	}

	page := recorder.Body.String()
	for _, key := range []string{settings.CacheRefreshInterval, settings.CacheStaleAfter} {
		if !strings.Contains(page, `id="`+key+`-error"`) {
			t.Errorf("%s carries no problem, and the rule reads it", key)
		}
	}
}

// A code with no text reads as its own key in front of the operator.
func TestEveryProblemCodeIsTranslated(t *testing.T) {
	env := newTestEnv(t)

	for _, language := range env.app.Catalogs.Languages() {
		catalog := env.app.Catalogs.Catalog(language)
		for _, code := range settings.Codes() {
			if !catalog.Has("settings.problem." + code) {
				t.Errorf("%s carries no text for the %s problem", language, code)
			}
		}
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

func TestTheSourceServerOffersTheEnabledServers(t *testing.T) {
	// A disabled server joins no operation, so naming it as the reference
	// would point at a machine nothing can be copied from.
	env := newFleetEnv(t)

	recorder := env.do(t, httptest.NewRequest(http.MethodGet, "/settings", nil), env.cookie)
	body := recorder.Body.String()

	if !strings.Contains(body, `data-field="source_server_id"`) {
		t.Fatalf("the settings page carries no source control:\n%s", body)
	}
	for _, name := range []string{"dns1", "dns2", "dns3"} {
		if !strings.Contains(body, ">"+name+"<") {
			t.Errorf("the source control does not offer %s:\n%s", name, body)
		}
	}
	if !strings.Contains(body, "No source server") {
		t.Errorf("the source control has no empty choice:\n%s", body)
	}
}

func TestASourceServerThatDoesNotExistIsRefused(t *testing.T) {
	env := newFleetEnv(t)

	body := env.settingsForm(t, map[string]string{settings.SourceServerID: "4711"})
	recorder := env.do(t, postForm("/settings", body), env.adminCookie(t))

	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422:\n%s", recorder.Code, recorder.Body.String())
	}
	if env.app.Settings.String(settings.SourceServerID) != "" {
		t.Error("a source nobody could reach was stored")
	}
}

func TestTheChosenSourceServerIsStored(t *testing.T) {
	env := newFleetEnv(t)

	body := env.settingsForm(t, map[string]string{settings.SourceServerID: "2"})
	recorder := env.do(t, postForm("/settings", body), env.adminCookie(t))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200:\n%s", recorder.Code, recorder.Body.String())
	}
	if got := env.app.Settings.Values().Int64(settings.SourceServerID); got != 2 {
		t.Errorf("stored source = %d, want 2", got)
	}
}
