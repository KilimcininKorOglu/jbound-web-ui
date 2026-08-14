package web

import (
	"compress/gzip"
	"net/http"
	"strings"

	"jbound/internal/logging"
)

// minCompressSize is the body below which compression is not attempted.
//
// A short fragment travels in one packet either way, and the gzip header plus
// the checksum are most of what a few hundred bytes would become.
const minCompressSize = 1 << 10

// compressibleType reports whether a content type is worth compressing.
//
// Fonts and images arrive compressed. Running deflate over them spends time to
// produce more bytes than the original.
func compressibleType(contentType string) bool {
	kind, _, _ := strings.Cut(contentType, ";")
	kind = strings.TrimSpace(kind)

	if strings.HasPrefix(kind, "text/") {
		return true
	}
	switch kind {
	case "application/javascript", "text/javascript",
		"application/json", "image/svg+xml":
		return true
	default:
		return false
	}
}

// acceptsGzip reports whether the client asked for the compressed copy.
//
// A substring match is enough here. The panel offers exactly one encoding, so
// there is no ranking to resolve, and a client that lists gzip at all accepts
// it.
func acceptsGzip(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept-Encoding"), "gzip")
}

// writeCompressed sends a body that may be compressed, and reports whether it
// was.
//
// The caller decides whether the body may be compressed at all. That is a
// question about what the response carries rather than about its size: a
// response that holds a stable secret and also echoes something the reader
// typed leaks the secret through its compressed length, one character at a
// time, to anybody who can watch the connection and make the browser repeat
// the request. Every full page of the panel carries the session CSRF token and
// most of them echo a filter, which is exactly that shape, so pages are sent
// as they are and fragments, which carry no token, are not.
func writeCompressed(w http.ResponseWriter, r *http.Request, status int,
	body []byte, allowed bool) {

	if !allowed || len(body) < minCompressSize || !acceptsGzip(r) {
		writeBody(w, r, status, body)
		return
	}

	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Set("Vary", "Accept-Encoding")
	w.WriteHeader(status)

	writer := gzip.NewWriter(w)
	if _, err := writer.Write(body); err != nil {
		// The status and the headers are already gone, so there is no failure
		// left to report to the reader. htmx sees a truncated swap and the
		// operator sees this line.
		logging.From(r.Context()).Error("cannot write the compressed response", "error", err)
		return
	}
	if err := writer.Close(); err != nil {
		logging.From(r.Context()).Error("cannot finish the compressed response", "error", err)
	}
}

// writeBody sends a body as it is.
func writeBody(w http.ResponseWriter, r *http.Request, status int, body []byte) {
	w.WriteHeader(status)
	if _, err := w.Write(body); err != nil {
		logging.From(r.Context()).Error("cannot write the response", "error", err)
	}
}
