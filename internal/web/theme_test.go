package web

import (
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"

	"jbound/internal/settings"
)

// variablePattern reads one custom property out of a palette block.
var variablePattern = regexp.MustCompile(`(?m)^\s*(--panel-[a-z-]+)\s*:\s*(#[0-9A-Fa-f]{6})\s*;`)

// palette returns the colours one selector declares.
func palette(t *testing.T, selector string) map[string]string {
	t.Helper()

	pattern := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(selector) + `\s*\{([^}]*)\}`)
	match := pattern.FindStringSubmatch(sheet(t, "panel.css"))
	if match == nil {
		t.Fatalf("panel.css declares no %s block", selector)
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

// The colours a rule may name without going through a token.
//
// Both belong to something that is deliberately the same in either theme: the
// skip link, which is drawn in the light accent with a white ring so the ring
// stays visible on top of it, and the block of machine output, which keeps its
// dark field so the eye can tell where the output ends.
var literalColours = map[string]string{
	"#0B6FC4": "the skip link",
	"#FFFFFF": "the skip link",
	"#0B0B0F": "the log viewer",
	"#D7DBDF": "the log viewer",
	"#000000": "the page behind a scrim",
}

// Colour lives in the token section and nowhere else.
//
// A hex further down the sheet is a colour that answers to neither theme, which
// is how a panel ends up with one rule that stays light when everything around
// it goes dark.
func TestNothingBelowTheTokensNamesItsOwnColour(t *testing.T) {
	body := sheet(t, "panel.css")

	// The token section ends where the base section begins. Both are named in
	// the header of the file, so this fails loudly if the sections move.
	const marker = "2. Base"
	start := strings.Index(body, marker)
	if start < 0 {
		t.Fatalf("panel.css carries no %q section", marker)
	}
	// Past the header comment as well, which names the sections in order.
	next := strings.Index(body[start+len(marker):], marker)
	if next < 0 {
		t.Fatalf("panel.css names %q once, so the sections cannot be told apart", marker)
	}
	start += len(marker) + next

	hex := regexp.MustCompile(`#[0-9A-Fa-f]{6}`)
	for _, colour := range hex.FindAllString(body[start:], -1) {
		if _, ok := literalColours[strings.ToUpper(colour)]; !ok {
			t.Errorf("%s is named outside the palette and follows neither theme", colour)
		}
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
