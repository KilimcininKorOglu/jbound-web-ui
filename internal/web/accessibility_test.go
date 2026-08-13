package web

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// uiThreshold is the contrast ratio WCAG 2.2 AA asks of a control and of the
// ring that marks the focused one.
const uiThreshold = 3.0

// sheet returns one stylesheet.
func sheet(t *testing.T, name string) string {
	t.Helper()

	body, err := fs.ReadFile(staticFS, "static/css/"+name)
	if err != nil {
		t.Fatalf("cannot read %s: %v", name, err)
	}
	return string(body)
}

// templates returns every template file with its path.
func templates(t *testing.T) map[string]string {
	t.Helper()

	entries, err := fs.Glob(templateFS, "templates/*/*.html")
	if err != nil {
		t.Fatalf("cannot list the templates: %v", err)
	}

	files := map[string]string{}
	for _, entry := range entries {
		body, err := fs.ReadFile(templateFS, entry)
		if err != nil {
			t.Fatalf("cannot read %s: %v", entry, err)
		}
		files[entry] = string(body)
	}
	if len(files) == 0 {
		t.Fatal("no template was found")
	}
	return files
}

// The ring is what a keyboard reader follows through the page. The vendor
// sheets replace the browser outline with a shadow that disappears on a
// coloured field, so the panel draws its own and measures it here.
func TestTheFocusRingIsVisibleInBothThemes(t *testing.T) {
	panel := sheet(t, "panel.css")

	fallback := regexp.MustCompile(`var\(--panel-focus,\s*(#[0-9A-Fa-f]{6})\)`).
		FindStringSubmatch(panel)
	if fallback == nil {
		t.Fatal("panel.css declares no focus ring colour")
	}

	// The light theme has no palette of its own, so the ring is measured
	// against the card and the page, both white.
	ratio, err := contrast(fallback[1], "#ffffff")
	if err != nil {
		t.Fatalf("%v", err)
	}
	if ratio < uiThreshold {
		t.Errorf("the light focus ring reads %s on white at %.2f:1, want at least %.1f:1",
			fallback[1], ratio, uiThreshold)
	}

	colours := palette(t, `html[data-color-scheme="dark"]`)
	ring, ok := colours["--panel-focus"]
	if !ok {
		t.Fatal("the dark palette declares no focus ring colour")
	}
	for _, behind := range []string{"--panel-bg", "--panel-surface"} {
		ratio, err := contrast(ring, colours[behind])
		if err != nil {
			t.Fatalf("%v", err)
		}
		if ratio < uiThreshold {
			t.Errorf("the dark focus ring reads %s on %s at %.2f:1, want at least %.1f:1",
				ring, colours[behind], ratio, uiThreshold)
		}
	}
}

// The skip link is green, so the green ring would sit on top of it unseen.
func TestTheSkipLinkRingIsVisibleOnTheLink(t *testing.T) {
	panel := sheet(t, "panel.css")

	background := regexp.MustCompile(`(?s)\.skip-link\s*\{[^}]*background:\s*(#[0-9A-Fa-f]{6})`).
		FindStringSubmatch(panel)
	if background == nil {
		t.Fatal("the skip link declares no background")
	}
	ring := regexp.MustCompile(`(?s)\.skip-link:focus-visible\s*\{[^}]*outline-color:\s*(#[0-9A-Fa-f]{6})`).
		FindStringSubmatch(panel)
	if ring == nil {
		t.Fatal("the skip link keeps the ring of everything else, which is its own colour")
	}

	ratio, err := contrast(ring[1], background[1])
	if err != nil {
		t.Fatalf("%v", err)
	}
	if ratio < uiThreshold {
		t.Errorf("the skip link ring reads %s on %s at %.2f:1, want at least %.1f:1",
			ring[1], background[1], ratio, uiThreshold)
	}
}

// A reader who asked the system for less movement gets none.
func TestMotionFollowsTheSystemPreference(t *testing.T) {
	if !strings.Contains(sheet(t, "panel.css"), "prefers-reduced-motion: reduce") {
		t.Error("the panel animates regardless of what the system asks for")
	}
}

// Every page names itself once at the top. A page whose first heading is an h5
// leaves a reader jumping by heading with nothing to jump to.
func TestEveryPageCarriesOneTopHeading(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")

	paths := []string{"/dns", "/diff", "/servers", "/logs", "/siem", "/settings", "/system"}
	heading := regexp.MustCompile(`<h1[\s>]`)

	for _, path := range paths {
		recorder := env.do(t, httptest.NewRequest(http.MethodGet, path, nil), cookie)
		if recorder.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", path, recorder.Code)
		}

		if got := len(heading.FindAllString(recorder.Body.String(), -1)); got != 1 {
			t.Errorf("%s carries %d top headings, want 1", path, got)
		}
	}

	login := env.do(t, httptest.NewRequest(http.MethodGet, "/", nil))
	if got := len(heading.FindAllString(login.Body.String(), -1)); got != 1 {
		t.Errorf("the login page carries %d top headings, want 1", got)
	}
}

// An icon next to a word says the word twice to a screen reader, so it is
// hidden from the accessibility tree.
func TestEveryDecorativeIconIsHidden(t *testing.T) {
	icon := regexp.MustCompile(`<i\s[^>]*class="[^"]*bx[^"]*"[^>]*>`)

	for path, body := range templates(t) {
		for _, tag := range icon.FindAllString(body, -1) {
			if !strings.Contains(tag, "aria-hidden") {
				t.Errorf("%s: %s is announced and does not need to be", path, tag)
			}
		}
	}
}

// A table read out of order is a table nobody can follow. The caption names it
// and the header cells name their columns.
func TestEveryTableNamesItselfAndItsColumns(t *testing.T) {
	header := regexp.MustCompile(`<th[\s>]`)

	for path, body := range templates(t) {
		if !strings.Contains(body, "<table") {
			continue
		}
		if !strings.Contains(body, "<caption") {
			t.Errorf("%s: the table carries no caption", path)
		}
		for _, cell := range header.FindAllStringIndex(body, -1) {
			tag := body[cell[0]:min(cell[0]+120, len(body))]
			tag = tag[:strings.Index(tag, ">")+1]
			if !strings.Contains(tag, "scope=") {
				t.Errorf("%s: %s names no column", path, tag)
			}
		}
	}
}

// A link that navigates nowhere is announced as one that does.
func TestNothingPretendsToBeALink(t *testing.T) {
	for path, body := range templates(t) {
		if strings.Contains(body, `href="#"`) {
			t.Errorf("%s: a link goes nowhere and should be a button", path)
		}
	}
}

// A span with a role is not a button. A keyboard cannot press it with the space
// bar, and nothing on the page teaches it to.
func TestNothingImitatesAButton(t *testing.T) {
	imitation := regexp.MustCompile(`<(?:span|div|a)\s[^>]*role="button"`)

	for path, body := range templates(t) {
		for _, tag := range imitation.FindAllString(body, -1) {
			t.Errorf("%s: %s imitates a button and should be one", path, tag)
		}
	}
}

// An image with no text is an image a reader is told nothing about.
func TestEveryImageCarriesItsOwnText(t *testing.T) {
	image := regexp.MustCompile(`<img\s[^>]*>`)

	for path, body := range templates(t) {
		for _, tag := range image.FindAllString(body, -1) {
			if !strings.Contains(tag, "alt=") {
				t.Errorf("%s: %s carries no alternative text", path, tag)
			}
		}
	}
}
