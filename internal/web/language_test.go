package web

import (
	"encoding/json"
	"html"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"unbound-web/internal/i18n"
	"unbound-web/internal/settings"
)

// turkish returns the Turkish text of one key, which is what a page in that
// language has to carry.
func turkish(t *testing.T, env *testEnv, key string) string {
	t.Helper()

	catalog := env.app.Catalogs.Catalog("tr")
	if !catalog.Has(key) {
		t.Fatalf("the Turkish catalogue has no %s", key)
	}
	return catalog.T(key)
}

func TestThePanelStartsInEnglish(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")

	recorder := env.do(t, httptest.NewRequest(http.MethodGet, "/dns", nil), cookie)
	body := recorder.Body.String()

	if !strings.Contains(body, `lang="en"`) {
		t.Error("the html element does not name the language")
	}
	if !strings.Contains(body, "DNS Records") {
		t.Error("the page is not in English")
	}
}

func TestAChosenLanguageIsStoredInACookieAndUsed(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")

	recorder := env.adminForm(t, http.MethodPost, "/language", cookie,
		url.Values{"language": {"tr"}})
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("POST /language = %d, want 204", recorder.Code)
	}
	if recorder.Header().Get("HX-Refresh") != "true" {
		t.Error("the browser was not asked to reload")
	}

	language := findResponseCookie(t, recorder, LanguageCookieName)
	if language.Value != "tr" {
		t.Fatalf("the cookie holds %q, want tr", language.Value)
	}
	if !language.HttpOnly {
		t.Error("the language cookie is readable from JavaScript")
	}

	page := env.do(t, httptest.NewRequest(http.MethodGet, "/dns", nil), cookie, language)
	body := page.Body.String()

	if !strings.Contains(body, `lang="tr"`) {
		t.Error("the html element still names the old language")
	}
	if !strings.Contains(body, turkish(t, env, "nav.dns_records")) {
		t.Error("the page is not in Turkish")
	}
}

func TestAnUnknownLanguageIsRefused(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")

	recorder := env.adminForm(t, http.MethodPost, "/language", cookie,
		url.Values{"language": {"de"}})
	if recorder.Code != http.StatusBadRequest {
		t.Errorf("POST /language with an unknown language = %d, want 400", recorder.Code)
	}
}

func TestATamperedLanguageCookieIsIgnored(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")

	page := env.do(t, httptest.NewRequest(http.MethodGet, "/dns", nil), cookie,
		&http.Cookie{Name: LanguageCookieName, Value: `tr" onload="alert(1)`})

	body := page.Body.String()
	if strings.Contains(body, "onload=") {
		t.Fatal("the cookie reached the page")
	}
	if !strings.Contains(body, `lang="en"`) {
		t.Error("the panel default did not answer for the refused cookie")
	}
}

// The default is a setting, so an operator can run a Turkish panel without
// asking every reader to pick the language again.
func TestTheDefaultLanguageSettingAnswersWithoutACookie(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.adminCookie(t)

	body := env.settingsForm(t, map[string]string{settings.DefaultLanguage: "tr"})
	if recorder := env.do(t, postForm("/settings", body), cookie); recorder.Code != http.StatusOK {
		t.Fatalf("POST /settings = %d, want 200", recorder.Code)
	}

	page := env.do(t, httptest.NewRequest(http.MethodGet, "/dns", nil), cookie)
	if !strings.Contains(page.Body.String(), `lang="tr"`) {
		t.Error("the panel default language did not reach a browser with no cookie")
	}
}

// A fragment carries no page data, so the language has to come from the
// request. Without that a swapped table would arrive in the wrong language.
func TestAnHTMXFragmentIsRenderedInTheChosenLanguage(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")
	language := &http.Cookie{Name: LanguageCookieName, Value: "tr"}

	recorder := env.do(t, httptest.NewRequest(http.MethodGet, "/dns/records", nil),
		cookie, language)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /dns/records = %d, want 200", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), turkish(t, env, "common.value")) {
		t.Error("the fragment is not in Turkish")
	}
}

// The login page has no session, and it is the first page anybody sees.
func TestTheLoginPageFollowsTheLanguageCookie(t *testing.T) {
	env := newTestEnv(t)

	recorder := env.do(t, httptest.NewRequest(http.MethodGet, "/", nil),
		&http.Cookie{Name: LanguageCookieName, Value: "tr"})

	body := recorder.Body.String()
	if !strings.Contains(body, `lang="tr"`) {
		t.Error("the login page ignores the language cookie")
	}
	if !strings.Contains(body, turkish(t, env, "login.submit")) {
		t.Error("the login form is not in Turkish")
	}
}

// The rejection is the one sentence on that page that matters most, and it was
// the one sentence the panel answered in English.
func TestTheLoginRejectionFollowsTheLanguageCookie(t *testing.T) {
	env := newTestEnv(t)

	request := postForm("/login", "username=dnsadmin&password=wrong")
	request.Header.Set("Origin", "http://example.test")
	request.Host = "example.test"

	recorder := env.do(t, request, &http.Cookie{Name: LanguageCookieName, Value: "tr"})
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401:\n%s", recorder.Code, recorder.Body.String())
	}

	body := recorder.Body.String()
	if !strings.Contains(body, turkish(t, env, msgLoginFailed)) {
		t.Errorf("the rejection is not in Turkish:\n%s", body)
	}
	// One wording for every rejection, in every language. Naming the accounts
	// that exist would turn the form into a directory.
	if strings.Contains(body, "Invalid username or password") {
		t.Error("the English wording came through as well")
	}
}

func TestTheExpiredSessionNoticeFollowsTheLanguageCookie(t *testing.T) {
	env := newTestEnv(t)

	recorder := env.do(t, httptest.NewRequest(http.MethodGet, "/?timeout=1", nil),
		&http.Cookie{Name: LanguageCookieName, Value: "tr"})

	if !strings.Contains(recorder.Body.String(), turkish(t, env, msgSessionExpired)) {
		t.Errorf("the expiry notice is not in Turkish:\n%s", recorder.Body.String())
	}
}

// The dialogs are raised by a script, which the content security policy stops
// from carrying its own texts. They ride on the body element instead.
func TestTheClientTextsTravelWithThePage(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")
	language := &http.Cookie{Name: LanguageCookieName, Value: "tr"}

	recorder := env.do(t, httptest.NewRequest(http.MethodGet, "/dns", nil), cookie, language)
	body := recorder.Body.String()

	attribute := regexp.MustCompile(`data-strings="([^"]*)"`).FindStringSubmatch(body)
	if attribute == nil {
		t.Fatal("the page carries no interface texts")
	}

	texts := map[string]string{}
	if err := json.Unmarshal([]byte(html.UnescapeString(attribute[1])), &texts); err != nil {
		t.Fatalf("the texts are not valid JSON: %v", err)
	}

	if got := texts["client.yes"]; got != turkish(t, env, "client.yes") {
		t.Errorf("client.yes reads %q", got)
	}
	// Only the dialog texts travel. Sending the whole catalogue would put
	// every page of the panel into every response.
	for key := range texts {
		if !strings.HasPrefix(key, "client.") {
			t.Errorf("%s travels to the browser and does not need to", key)
		}
	}
}

// A template that prints a key rather than a sentence is a translation that
// was forgotten. The catalogue answers for every key the templates use.
func TestEveryKeyTheTemplatesUseExists(t *testing.T) {
	catalog := newTestEnv(t).app.Catalogs.Catalog(i18n.Default)

	// {{t "key"}} and {{tf "key" ...}}, which is how a template asks for text.
	pattern := regexp.MustCompile(`{{\s*tf?\s+"([a-z0-9_.]+)"`)

	entries, err := fs.Glob(templateFS, "templates/*/*.html")
	if err != nil {
		t.Fatalf("cannot list the templates: %v", err)
	}

	for _, entry := range entries {
		body, err := fs.ReadFile(templateFS, entry)
		if err != nil {
			t.Fatalf("cannot read %s: %v", entry, err)
		}
		for _, match := range pattern.FindAllStringSubmatch(string(body), -1) {
			if !catalog.Has(match[1]) {
				t.Errorf("%s uses %s, which no catalogue carries", entry, match[1])
			}
		}
	}
}
