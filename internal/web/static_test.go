package web

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestStaticAssetsAreServedFromTheBinary(t *testing.T) {
	// Everything ships inside the binary. A missing asset here means the
	// interface would load without its stylesheet on a machine with no
	// network route to a CDN.
	env := newTestEnv(t)

	assets := []string{
		"/static/css/core.css",
		"/static/css/theme-default.css",
		"/static/css/brand.css",
		"/static/css/panel.css",
		"/static/css/publicsans.css",
		"/static/css/boxicons.css",
		"/static/css/sweetalert2.min.css",
		"/static/css/page-auth.css",
		"/static/js/htmx.min.js",
		"/static/js/app.js",
		"/static/js/layout.js",
		"/static/js/bootstrap.bundle.min.js",
		"/static/js/perfect-scrollbar.min.js",
		"/static/js/sweetalert2.min.js",
		"/static/js/helpers.js",
		"/static/js/menu.js",
		"/static/fonts/publicsans/publicsans-latin-ext.woff2",
		"/static/fonts/boxicons/boxicons.woff2",
		"/static/img/favicon.svg",
	}

	for _, asset := range assets {
		t.Run(asset, func(t *testing.T) {
			recorder := env.do(t, httptest.NewRequest(http.MethodGet, asset, nil))
			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", recorder.Code)
			}
			if recorder.Body.Len() == 0 {
				t.Error("the asset is empty")
			}
			if recorder.Header().Get("ETag") == "" {
				t.Error("the asset carries no entity tag")
			}
			if got := recorder.Header().Get("Cache-Control"); got != "no-cache" {
				t.Errorf("Cache-Control = %q, want no-cache", got)
			}
		})
	}
}

func TestStaticServesNoDirectoryListing(t *testing.T) {
	env := newTestEnv(t)

	for _, path := range []string{"/static/", "/static/js/", "/static/css/"} {
		recorder := env.do(t, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusNotFound {
			t.Errorf("%s returned %d, want 404", path, recorder.Code)
		}
	}
}

func TestStaticAnswersAConditionalRequestWithoutABody(t *testing.T) {
	// The assets change with the binary while their paths stay the same, so a
	// browser must revalidate. This is what makes that cheap.
	env := newTestEnv(t)

	first := env.do(t, httptest.NewRequest(http.MethodGet, "/static/js/app.js", nil))
	tag := first.Header().Get("ETag")
	if tag == "" {
		t.Fatal("the asset carries no entity tag")
	}

	request := httptest.NewRequest(http.MethodGet, "/static/js/app.js", nil)
	request.Header.Set("If-None-Match", tag)
	second := env.do(t, request)

	if second.Code != http.StatusNotModified {
		t.Fatalf("status = %d, want 304", second.Code)
	}
	if second.Body.Len() != 0 {
		t.Error("a 304 carried a body")
	}
}

func TestStaticRejectsAMissingFile(t *testing.T) {
	env := newTestEnv(t)

	recorder := env.do(t, httptest.NewRequest(http.MethodGet, "/static/js/nothing.js", nil))
	if recorder.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", recorder.Code)
	}
}

func TestStaticAssetsNeedNoSession(t *testing.T) {
	// The login page needs its stylesheet before anyone has signed in.
	env := newTestEnv(t)

	recorder := env.do(t, httptest.NewRequest(http.MethodGet, "/static/css/core.css", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
}

// inlineHandler matches an HTML event attribute such as onclick.
var inlineHandler = regexp.MustCompile(`\son[a-z]+\s*=\s*["']`)

func TestRenderedPagesCarryNoInlineScriptOrStyle(t *testing.T) {
	// The content security policy allows neither. A page that breaks this
	// would fail in the browser with nothing more than a console message, so
	// the check belongs here.
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")

	pages := []struct {
		path   string
		cookie *http.Cookie
	}{
		{"/", nil},
		{"/dns", cookie},
		{"/servers", cookie},
		{"/logs", cookie},
	}

	for _, page := range pages {
		t.Run(page.path, func(t *testing.T) {
			var recorder *httptest.ResponseRecorder
			request := httptest.NewRequest(http.MethodGet, page.path, nil)
			if page.cookie != nil {
				recorder = env.do(t, request, page.cookie)
			} else {
				recorder = env.do(t, request)
			}

			body := recorder.Body.String()
			if strings.Contains(body, "<style") {
				t.Error("the page carries a style element")
			}
			if strings.Contains(body, "style=\"") {
				t.Error("the page carries an inline style attribute")
			}
			if inlineHandler.MatchString(body) {
				t.Errorf("the page carries an inline event handler: %s",
					inlineHandler.FindString(body))
			}
			if strings.Contains(body, "javascript:") {
				t.Error("the page carries a javascript URI")
			}
			// Anything loaded from elsewhere would break an air gapped
			// install and leak the reader's address to a third party.
			if strings.Contains(body, "https://") || strings.Contains(body, "//cdn.") {
				t.Error("the page loads a resource from another host")
			}
		})
	}
}

func TestAuthenticatedPagesCarryTheNavigationAndTheToken(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")
	token := env.csrfTokenOf(t, cookie)

	recorder := env.do(t, httptest.NewRequest(http.MethodGet, "/dns", nil), cookie)
	body := recorder.Body.String()

	if !strings.Contains(body, token) {
		t.Error("the page does not carry the CSRF token")
	}
	if !strings.Contains(body, `href="/servers"`) {
		t.Error("an admin does not see the servers link")
	}
	if !strings.Contains(body, "dnsadmin") {
		t.Error("the navbar does not name the signed in account")
	}
}

func TestAPlainUserSeesNoAdminLinks(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.login(t, "dnsuser")

	body := env.do(t, httptest.NewRequest(http.MethodGet, "/dns", nil), cookie).Body.String()

	for _, hidden := range []string{`href="/servers"`, `href="/siem"`} {
		if strings.Contains(body, hidden) {
			t.Errorf("a plain user sees %s", hidden)
		}
	}
}
