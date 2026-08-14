package web

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"unbound-web/internal/settings"
)

// captureLog sends the structured stream to a buffer for the length of one
// test, so an assertion can read what an operator would read.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()

	var buffer bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buffer, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &buffer
}

func TestACrashedHandlerAnswersAndIsLogged(t *testing.T) {
	// Without a recovery layer the panic reaches net/http, which drops the
	// connection with no response at all.
	logged := captureLog(t)

	chain := requestLog(recoverPanic(http.HandlerFunc(
		func(http.ResponseWriter, *http.Request) {
			panic("the record table exploded")
		})))

	recorder := httptest.NewRecorder()
	chain.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/dns/records", nil))

	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", recorder.Code)
	}

	output := logged.String()
	if !strings.Contains(output, "handler panicked") {
		t.Errorf("the panic was not logged:\n%s", output)
	}
	if !strings.Contains(output, "the record table exploded") {
		t.Errorf("the log does not name the cause:\n%s", output)
	}
	if !strings.Contains(output, "recoverPanic") {
		t.Errorf("the log carries no stack:\n%s", output)
	}
}

func TestTheRequestOfACrashedHandlerStillLeavesALine(t *testing.T) {
	// The request an operator most needs to find used to be the one request
	// with no line naming its path.
	logged := captureLog(t)

	chain := requestLog(recoverPanic(http.HandlerFunc(
		func(http.ResponseWriter, *http.Request) { panic("boom") })))

	chain.ServeHTTP(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/dns/apply", nil))

	output := logged.String()
	if !strings.Contains(output, `msg=request`) {
		t.Fatalf("no request line was written:\n%s", output)
	}
	if !strings.Contains(output, "path=/dns/apply") {
		t.Errorf("the request line does not name the path:\n%s", output)
	}
	if !strings.Contains(output, "status=500") {
		t.Errorf("the request line does not carry the status:\n%s", output)
	}
}

func TestAPanicAfterTheResponseStartedWritesNoSecondStatus(t *testing.T) {
	// The status is already on the wire. Writing another one would only
	// produce a superfluous header warning.
	captureLog(t)

	chain := requestLog(recoverPanic(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("half a page"))
			panic("mid render")
		})))

	recorder := httptest.NewRecorder()
	chain.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/dns", nil))

	if recorder.Code != http.StatusOK {
		t.Errorf("status = %d, want the 200 that was already sent", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), "internal error") {
		t.Errorf("a second body was appended:\n%s", recorder.Body.String())
	}
}

func TestADeliberateAbortIsLeftToTheServer(t *testing.T) {
	// net/http treats ErrAbortHandler as a deliberate abort and logs nothing.
	// Swallowing it here would turn a cancelled response into a 500.
	logged := captureLog(t)

	chain := recoverPanic(http.HandlerFunc(
		func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) }))

	defer func() {
		cause := recover()
		if cause != http.ErrAbortHandler {
			t.Errorf("the abort was swallowed, got %v", cause)
		}
		if strings.Contains(logged.String(), "handler panicked") {
			t.Error("a deliberate abort was logged as a fault")
		}
	}()

	chain.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/dns", nil))
}

func TestAFleetRouteCarriesTheConfiguredDeadline(t *testing.T) {
	// A fan-out route can outlast the write timeout of the server, and a
	// request that dies there leaves the operator with no report at all. The
	// deadline the panel sets is what turns that into a per-server result.
	env := newTestEnv(t)

	var deadline time.Time
	var ok bool
	handler := env.app.withFleetDeadline(func(_ http.ResponseWriter, r *http.Request) {
		deadline, ok = r.Context().Deadline()
	})

	before := time.Now()
	handler(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/dns/apply", nil))
	if !ok {
		t.Fatal("the request carries no deadline")
	}

	want := env.app.Settings.Duration(settings.FleetOperationTimeout)
	if got := deadline.Sub(before); got < want-time.Second || got > want+time.Second {
		t.Errorf("deadline in %s, want the configured %s", got, want)
	}
}

func TestEveryFanOutRouteReachesTheServersWithADeadline(t *testing.T) {
	// Wrapping the middleware is only half of the fix. The route has to carry
	// it, or the deadline is a function nobody calls.
	env := newFleetEnv(t)

	env.adminForm(t, http.MethodPost, "/dns/refresh", env.cookie, url.Values{})

	for id := int64(1); id <= 3; id++ {
		if !env.target(id).hadDeadline() {
			t.Errorf("the refresh reached server %d with no deadline", id)
		}
	}
}
