package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCSRFRequiredCoversEveryStateChangingMethod(t *testing.T) {
	safe := []string{http.MethodGet, http.MethodHead, http.MethodOptions}
	unsafe := []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}

	for _, method := range safe {
		if CSRFRequired(method) {
			t.Errorf("%s should not need a token", method)
		}
	}
	for _, method := range unsafe {
		if !CSRFRequired(method) {
			t.Errorf("%s must need a token", method)
		}
	}
}

func TestCSRFTokenPrefersTheHeader(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/records",
		strings.NewReader("csrf_token=from-form"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set(CSRFHeader, "from-header")

	if got := CSRFToken(r); got != "from-header" {
		t.Errorf("CSRFToken = %q, want the header value", got)
	}
}

func TestCSRFTokenFallsBackToTheForm(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/records",
		strings.NewReader("csrf_token=from-form"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if got := CSRFToken(r); got != "from-form" {
		t.Errorf("CSRFToken = %q, want the form value", got)
	}
}

func TestValidCSRFRejectsEmptyAndMismatchedTokens(t *testing.T) {
	cases := []struct {
		name               string
		expected, provided string
		want               bool
	}{
		{"match", "abc123", "abc123", true},
		{"mismatch", "abc123", "abc124", false},
		{"empty session token", "", "", false},
		{"empty request token", "abc123", "", false},
		{"session token missing", "", "abc123", false},
		{"prefix only", "abc123", "abc", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ValidCSRF(tc.expected, tc.provided); got != tc.want {
				t.Errorf("ValidCSRF(%q, %q) = %v, want %v",
					tc.expected, tc.provided, got, tc.want)
			}
		})
	}
}
