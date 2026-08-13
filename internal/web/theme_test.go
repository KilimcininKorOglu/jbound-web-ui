package web

import (
	"io/fs"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"

	"unbound-web/internal/settings"
)

// variablePattern reads one custom property out of a palette block.
var variablePattern = regexp.MustCompile(`(?m)^\s*(--panel-[a-z-]+)\s*:\s*(#[0-9A-Fa-f]{6})\s*;`)

// palette returns the colours one selector declares.
func palette(t *testing.T, selector string) map[string]string {
	t.Helper()

	body, err := fs.ReadFile(staticFS, "static/css/theme-dark.css")
	if err != nil {
		t.Fatalf("cannot read theme-dark.css: %v", err)
	}

	pattern := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(selector) + `\s*\{([^}]*)\}`)
	match := pattern.FindStringSubmatch(string(body))
	if match == nil {
		t.Fatalf("theme-dark.css declares no %s block", selector)
	}

	colours := map[string]string{}
	for _, declaration := range variablePattern.FindAllStringSubmatch(match[1], -1) {
		colours[declaration[1]] = declaration[2]
	}
	if len(colours) == 0 {
		t.Fatalf("the %s block declares no colours", selector)
	}
	return colours
}

// The dark palette is measured the same way the light one is. An eye adapts to
// a low contrast dark theme long before it can read it comfortably.
func TestTheDarkPaletteIsReadable(t *testing.T) {
	colours := palette(t, `html[data-color-scheme="dark"]`)

	cases := []struct {
		name       string
		text       string
		background string
	}{
		{"body text", "--panel-text", "--panel-bg"},
		{"body text on a card", "--panel-text", "--panel-surface"},
		{"heading", "--panel-heading", "--panel-surface"},
		{"muted text", "--panel-text-muted", "--panel-surface"},
		{"muted text on the page", "--panel-text-muted", "--panel-bg"},
		{"link", "--panel-accent", "--panel-surface"},
		{"link hover", "--panel-accent-strong", "--panel-surface"},
		{"success alert", "--panel-success-text", "--panel-success-bg"},
		{"info alert", "--panel-info-text", "--panel-info-bg"},
		{"warning alert", "--panel-warning-text", "--panel-warning-bg"},
		{"danger alert", "--panel-danger-text", "--panel-danger-bg"},
		{"secondary badge", "--panel-secondary-text", "--panel-secondary-bg"},
		// The refusal under a control sits on the card rather than on a tint.
		{"refused field", "--panel-danger-text", "--panel-surface"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			text, ok := colours[testCase.text]
			if !ok {
				t.Fatalf("the palette declares no %s", testCase.text)
			}
			background, ok := colours[testCase.background]
			if !ok {
				t.Fatalf("the palette declares no %s", testCase.background)
			}

			ratio, err := contrast(text, background)
			if err != nil {
				t.Fatalf("%v", err)
			}
			if ratio < aaThreshold {
				t.Errorf("%s reads %s on %s at %.2f:1, want at least %.1f:1",
					testCase.name, text, background, ratio, aaThreshold)
			}
		})
	}
}

// The system theme is the same palette behind a media query. Declaring it twice
// is what keeps the rules free of JavaScript, and this is what keeps the two
// copies from drifting.
func TestTheSystemPaletteMatchesTheDarkOne(t *testing.T) {
	explicit := palette(t, `html[data-color-scheme="dark"]`)
	system := palette(t, `html[data-color-scheme="system"]`)

	if !maps.Equal(explicit, system) {
		for _, name := range slices.Sorted(maps.Keys(explicit)) {
			if system[name] != explicit[name] {
				t.Errorf("%s is %s in the dark block and %s in the system block",
					name, explicit[name], system[name])
			}
		}
		for _, name := range slices.Sorted(maps.Keys(system)) {
			if _, ok := explicit[name]; !ok {
				t.Errorf("%s is only in the system block", name)
			}
		}
	}
}

// Nothing in the theme runs in the browser, so the first paint is already
// correct. A script that applies a class after load makes every page flash.
func TestTheThemeReachesTheHTMLElement(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")

	recorder := env.do(t, httptest.NewRequest(http.MethodGet, "/dns", nil), cookie)
	if !strings.Contains(recorder.Body.String(), `data-color-scheme="system"`) {
		t.Error("the default theme does not reach the html element")
	}
}

func TestAChosenThemeIsStoredInACookieAndUsed(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")

	recorder := env.adminForm(t, http.MethodPost, "/theme", cookie,
		url.Values{"theme": {"dark"}})
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("POST /theme = %d, want 204", recorder.Code)
	}
	if recorder.Header().Get("HX-Refresh") != "true" {
		t.Error("the browser was not asked to reload")
	}

	theme := findResponseCookie(t, recorder, ThemeCookieName)
	if theme.Value != "dark" {
		t.Fatalf("the cookie holds %q, want dark", theme.Value)
	}
	if !theme.HttpOnly {
		t.Error("the theme cookie is readable from JavaScript")
	}
	if theme.MaxAge < int((30 * 24 * 60 * 60)) {
		t.Errorf("MaxAge = %d, want a preference that outlives the session", theme.MaxAge)
	}

	// The panel stores the choice nowhere else, so the cookie is what the next
	// page has to read it from.
	page := env.do(t, httptest.NewRequest(http.MethodGet, "/dns", nil), cookie, theme)
	if !strings.Contains(page.Body.String(), `data-color-scheme="dark"`) {
		t.Error("the chosen theme did not reach the next page")
	}
}

// A theme nobody offers is refused rather than written into the page.
func TestAnUnknownThemeIsRefused(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")

	recorder := env.adminForm(t, http.MethodPost, "/theme", cookie,
		url.Values{"theme": {"neon"}})
	if recorder.Code != http.StatusBadRequest {
		t.Errorf("POST /theme with an unknown theme = %d, want 400", recorder.Code)
	}
}

// A tampered cookie falls back to the panel default rather than reaching the
// html element, where it would be an attribute the operator never chose.
func TestATamperedThemeCookieIsIgnored(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")

	page := env.do(t, httptest.NewRequest(http.MethodGet, "/dns", nil), cookie,
		&http.Cookie{Name: ThemeCookieName, Value: `dark" onload="alert(1)`})

	body := page.Body.String()
	if strings.Contains(body, "onload=") {
		t.Fatal("the cookie reached the page")
	}
	if !strings.Contains(body, `data-color-scheme="system"`) {
		t.Error("the panel default did not answer for the refused cookie")
	}
}

// The default theme is a setting, so an operator can decide what a browser
// with no cookie gets.
func TestTheDefaultThemeSettingAnswersWithoutACookie(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.adminCookie(t)

	body := env.settingsForm(t, map[string]string{settings.DefaultTheme: "dark"})
	if recorder := env.do(t, postForm("/settings", body), cookie); recorder.Code != http.StatusOK {
		t.Fatalf("POST /settings = %d, want 200", recorder.Code)
	}

	page := env.do(t, httptest.NewRequest(http.MethodGet, "/dns", nil), cookie)
	if !strings.Contains(page.Body.String(), `data-color-scheme="dark"`) {
		t.Error("the panel default theme did not reach a browser with no cookie")
	}
}

// The login page carries the theme as well. Signing in should not mean a white
// flash for somebody who chose dark.
func TestTheLoginPageCarriesTheTheme(t *testing.T) {
	env := newTestEnv(t)

	recorder := env.do(t, httptest.NewRequest(http.MethodGet, "/", nil),
		&http.Cookie{Name: ThemeCookieName, Value: "dark"})

	if !strings.Contains(recorder.Body.String(), `data-color-scheme="dark"`) {
		t.Error("the login page ignores the theme cookie")
	}
}

// findResponseCookie returns one cookie the response set.
func findResponseCookie(t *testing.T, recorder *httptest.ResponseRecorder,
	name string) *http.Cookie {

	t.Helper()
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("the response carries no %s cookie", name)
	return nil
}
