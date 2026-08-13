// Package web wires the HTTP surface of the panel.
package web

import (
	"net/http"

	"unbound-web/internal/config"
)

// NewRouter builds the panel handler.
//
// Faz 1 only serves the readiness endpoint. Later phases register the
// authentication, DNS, server management, log and SIEM routes here.
func NewRouter(cfg *config.Config) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	// Placeholder for the login page. Faz 3 replaces it with the real handler
	// and Faz 4 gives it the Sneat layout.
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(
			"<!doctype html><title>JanBound DNS Panel</title>" +
				"<p>Panel skeleton is running. Login arrives in Faz 3.</p>\n"))
	})

	return securityHeaders(mux)
}

// securityHeaders sets the response headers that apply to every route.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; style-src 'self'; "+
				"script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}
