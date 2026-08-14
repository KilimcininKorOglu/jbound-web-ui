package web

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// gunzip reads a compressed response body back.
func gunzip(t *testing.T, recorder *httptest.ResponseRecorder) string {
	t.Helper()

	reader, err := gzip.NewReader(recorder.Body)
	if err != nil {
		t.Fatalf("the body is not gzip: %v", err)
	}
	defer reader.Close()

	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("cannot read the compressed body: %v", err)
	}
	return string(body)
}

// getWithGzip asks for a path the way a browser that accepts compression does.
func getWithGzip(target string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, target, nil)
	request.Header.Set("Accept-Encoding", "gzip, deflate, br")
	return request
}

func TestAStylesheetIsSentCompressed(t *testing.T) {
	env := newTestEnv(t)
	const asset = "/static/css/core.css"

	plain := env.do(t, httptest.NewRequest(http.MethodGet, asset, nil))
	if plain.Header().Get("Content-Encoding") != "" {
		t.Fatalf("a client that asked for nothing got %q",
			plain.Header().Get("Content-Encoding"))
	}

	packed := env.do(t, getWithGzip(asset))
	if got := packed.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
	if packed.Body.Len() >= plain.Body.Len() {
		t.Errorf("the compressed copy is %d bytes against %d uncompressed",
			packed.Body.Len(), plain.Body.Len())
	}
	if gunzip(t, packed) != plain.Body.String() {
		t.Error("the compressed copy does not read back as the original")
	}

	// A cache in front of the panel has to keep the two apart, and a client
	// holding one copy must not be told the other one matches.
	if got := packed.Header().Get("Vary"); !strings.Contains(got, "Accept-Encoding") {
		t.Errorf("Vary = %q, want Accept-Encoding", got)
	}
	if packed.Header().Get("ETag") == plain.Header().Get("ETag") {
		t.Error("both copies carry the same entity tag")
	}
}

func TestAFontIsSentAsItIs(t *testing.T) {
	// woff2 is compressed already. Running deflate over it spends time to send
	// more bytes than the file holds.
	env := newTestEnv(t)

	recorder := env.do(t, getWithGzip("/static/fonts/boxicons/boxicons.woff2"))
	if got := recorder.Header().Get("Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding = %q, want none", got)
	}
}

func TestTheRecordTableIsSentCompressed(t *testing.T) {
	env := newFleetEnv(t)

	recorder := env.do(t, getWithGzip("/dns/records"), env.cookie)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if got := recorder.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
	if !strings.Contains(gunzip(t, recorder), "www.example.local") {
		t.Error("the compressed table does not carry the records")
	}
}

func TestAPageIsNotCompressed(t *testing.T) {
	// A full page carries the session CSRF token and echoes the filter the
	// reader typed. A response holding both gives the token away through its
	// compressed length, to anybody who can watch the connection and make the
	// browser repeat the request.
	env := newFleetEnv(t)

	recorder := env.do(t, getWithGzip("/dns"), env.cookie)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if got := recorder.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want none", got)
	}
	if !strings.Contains(recorder.Body.String(), "X-CSRF-Token") {
		t.Error("the page carries no token, so the rule above needs revisiting")
	}
}

func TestAShortFragmentIsSentAsItIs(t *testing.T) {
	// A few hundred bytes travel in one packet either way, and the gzip header
	// and checksum are most of what they would become.
	env := newTestEnv(t)
	cookie := env.login(t, "dnsadmin")

	// The alert fragment is a sentence in a box, which is the shortest thing
	// the panel renders.
	recorder := httptest.NewRecorder()
	env.app.RenderPartial(recorder, signedInWithGzip(cookie),
		http.StatusOK, "alert", &Alert{Severity: ToastError, Message: "short"})

	if recorder.Body.Len() >= minCompressSize {
		t.Fatalf("the alert is %d bytes, which is over the threshold", recorder.Body.Len())
	}
	if got := recorder.Header().Get("Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding = %q, want none", got)
	}
}

// signedInWithGzip builds a signed in request that accepts compression.
func signedInWithGzip(cookie *http.Cookie) *http.Request {
	request := getWithGzip("/servers/table")
	request.AddCookie(cookie)
	return request
}
