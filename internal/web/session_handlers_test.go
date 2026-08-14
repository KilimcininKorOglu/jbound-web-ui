package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"jbound/internal/audit"
)

func TestTheSessionsPageIsAdminOnly(t *testing.T) {
	// Signing somebody else out is an administrator's action, and the page
	// names every account that is currently signed in.
	env := newTestEnv(t)
	cookie := env.login(t, "dnsuser")
	token := env.csrfTokenOf(t, cookie)

	requests := map[string]*http.Request{
		"GET /sessions":             httptest.NewRequest(http.MethodGet, "/sessions", nil),
		"GET /sessions/table":       httptest.NewRequest(http.MethodGet, "/sessions/table", nil),
		"POST /sessions/revoke":     postForm("/sessions/revoke", "csrf_token="+token+"&uid=1001"),
		"POST /sessions/revoke-all": postForm("/sessions/revoke-all", "csrf_token="+token),
	}
	for name, request := range requests {
		t.Run(name, func(t *testing.T) {
			if recorder := env.do(t, request, cookie); recorder.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", recorder.Code)
			}
		})
	}
}

func TestTheSessionsPageNamesTheSignedInAccounts(t *testing.T) {
	env := newTestEnv(t)
	admin := env.login(t, "dnsadmin")
	env.login(t, "dnsuser")

	recorder := env.do(t, httptest.NewRequest(http.MethodGet, "/sessions", nil), admin)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}

	body := recorder.Body.String()
	for _, name := range []string{"dnsadmin", "dnsuser"} {
		if !strings.Contains(body, name) {
			t.Errorf("the page does not name %s", name)
		}
	}

	// The identifier is the credential the browser presents. A page that
	// printed one would be handing it out to whoever reads the page.
	if strings.Contains(body, admin.Value) {
		t.Error("a session identifier reached the page")
	}
}

func TestRevokingAnAccountSignsItOutEverywhere(t *testing.T) {
	env := newTestEnv(t)
	admin := env.login(t, "dnsadmin")
	victim := env.login(t, "dnsuser")
	token := env.csrfTokenOf(t, admin)

	session, err := env.sessions.Get(context.Background(), victim.Value)
	if err != nil {
		t.Fatalf("cannot read the session of the account: %v", err)
	}

	body := "csrf_token=" + token + "&uid=" + strconv.Itoa(session.UID) + "&username=dnsuser"
	if recorder := env.do(t, postForm("/sessions/revoke", body), admin); recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}

	// The revoked browser is signed out on its next request.
	recorder := env.do(t, httptest.NewRequest(http.MethodGet, "/dns", nil), victim)
	if recorder.Code != http.StatusSeeOther {
		t.Errorf("the revoked session still works: %d", recorder.Code)
	}

	// The administrator who pressed the button keeps working.
	recorder = env.do(t, httptest.NewRequest(http.MethodGet, "/sessions", nil), admin)
	if recorder.Code != http.StatusOK {
		t.Errorf("the caller was signed out by their own revocation: %d", recorder.Code)
	}
}

func TestRevokingEverythingLeavesTheCallerSignedIn(t *testing.T) {
	env := newTestEnv(t)
	admin := env.login(t, "dnsadmin")
	other := env.login(t, "dnsuser")
	token := env.csrfTokenOf(t, admin)

	recorder := env.do(t, postForm("/sessions/revoke-all", "csrf_token="+token), admin)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}

	if got := env.do(t, httptest.NewRequest(http.MethodGet, "/dns", nil), other); got.Code != http.StatusSeeOther {
		t.Errorf("another session survived: %d", got.Code)
	}
	if got := env.do(t, httptest.NewRequest(http.MethodGet, "/sessions", nil), admin); got.Code != http.StatusOK {
		t.Errorf("the caller was signed out by their own revocation: %d", got.Code)
	}
}

func TestARevocationIsAudited(t *testing.T) {
	// Signing somebody else out is an administrative action against another
	// account, which is exactly what the trail is for.
	env := newTestEnv(t)
	admin := env.login(t, "dnsadmin")
	victim := env.login(t, "dnsuser")
	token := env.csrfTokenOf(t, admin)

	session, err := env.sessions.Get(context.Background(), victim.Value)
	if err != nil {
		t.Fatalf("cannot read the session of the account: %v", err)
	}

	body := "csrf_token=" + token + "&uid=" + strconv.Itoa(session.UID) + "&username=dnsuser"
	env.do(t, postForm("/sessions/revoke", body), admin)

	var action, username, details string
	row := env.db.QueryRow(
		"SELECT action, username, details FROM audit_logs ORDER BY id DESC LIMIT 1")
	if err := row.Scan(&action, &username, &details); err != nil {
		t.Fatalf("cannot read the audit table: %v", err)
	}

	if action != audit.ActionSessionRevoke {
		t.Errorf("action = %q", action)
	}
	if username != "dnsadmin" {
		t.Errorf("the entry names %q as the actor", username)
	}
	if !strings.Contains(details, "dnsuser") {
		t.Errorf("the details do not name the target: %q", details)
	}
}
