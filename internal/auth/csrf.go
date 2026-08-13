package auth

import (
	"crypto/hmac"
	"net/http"
)

// CSRFHeader is what htmx sends. The layout puts the token on the body element
// with hx-headers, so every htmx request carries it without per form wiring.
const CSRFHeader = "X-CSRF-Token"

// CSRFField is the fallback for plain HTML forms, which cannot set a header.
const CSRFField = "csrf_token"

// csrfSafeMethods never change state, so they carry no token.
var csrfSafeMethods = map[string]bool{
	http.MethodGet:     true,
	http.MethodHead:    true,
	http.MethodOptions: true,
}

// CSRFRequired reports whether the request must carry a token.
func CSRFRequired(method string) bool { return !csrfSafeMethods[method] }

// CSRFToken reads the token from the request, preferring the header.
//
// Reading the form would consume the body, so that path only runs when the
// header is absent.
func CSRFToken(r *http.Request) string {
	if token := r.Header.Get(CSRFHeader); token != "" {
		return token
	}
	return r.PostFormValue(CSRFField)
}

// ValidCSRF compares the session token with the one the request supplied.
//
// The comparison is constant time. A byte by byte comparison would leak the
// expected token through response timing.
func ValidCSRF(expected, provided string) bool {
	if expected == "" || provided == "" {
		return false
	}
	return hmac.Equal([]byte(expected), []byte(provided))
}
