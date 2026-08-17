//go:build integration

// The fleet gate. It drives the panel over HTTP against the development
// targets, because the two things it checks only exist end to end: a change
// that reaches three servers and reports the one it could not, and a file that
// somebody broke by hand behind the panel's back.
//
// Run it with: make dev-itest

package web

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"

	"jbound/internal/auth"
	"jbound/internal/dnsfile"
	"jbound/internal/fleet"
	"jbound/internal/server"
)

const (
	// devKeyPath is the key the development stack installs on every target.
	devKeyPath = "/var/lib/jbound/keys/dev_ed25519"

	// devStatusCmd is what answers in a container with no systemd.
	devStatusCmd = "/usr/sbin/service unbound status"

	// entriesPath is the file the panel manages on every target.
	entriesPath = "/etc/unbound/local_records.conf"

	// downHost is from the RFC 5737 documentation block, so a connection there
	// times out rather than landing somewhere real.
	downHost = "192.0.2.1"
)

// gateFleet is the panel with four servers registered: three that answer and
// one that never will.
type gateFleet struct {
	app     *App
	server  *httptest.Server
	client  *http.Client
	cookie  *http.Cookie
	token   string
	servers *server.Service
	records *fleet.Service
	groupID int64
}

func newGateFleet(t *testing.T) *gateFleet {
	t.Helper()
	ctx := context.Background()

	app := newLiveApp(t)
	live := liveServer(t, app)

	fleetEnv := &gateFleet{
		app:     app,
		server:  live,
		client:  live.Client(),
		servers: app.Servers,
		records: app.Records,
	}
	// The client keeps no cookie jar, so the session travels by hand and the
	// test can see exactly what each request carries.
	fleetEnv.client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	fleetEnv.signIn(t)
	for i, name := range []string{"dns1", "dns2", "dns3"} {
		fleetEnv.register(t, name, name)
		fleetEnv.approve(t, int64(i+1))
	}
	// The fourth is registered and never answers, so its host key stays
	// unapproved and every write to it is refused. That is what the partial
	// failure report is measured against.
	fleetEnv.register(t, "dns-down", downHost)

	group, err := app.Servers.CreateGroup(ctx, gateActor(),
		server.Group{Name: "resolvers", ServerIDs: []int64{1, 2, 3, 4}})
	if err != nil {
		t.Fatalf("cannot create the group: %v", err)
	}
	fleetEnv.groupID = group.ID

	if _, err := app.Records.Refresh(ctx); err != nil {
		t.Fatalf("cannot fill the cache: %v", err)
	}
	return fleetEnv
}

func gateActor() server.Actor {
	return server.Actor{UID: 1001, Username: "dnsadmin", IPAddress: "203.0.113.5"}
}

// signIn logs the admin account in and keeps its session and token.
func (g *gateFleet) signIn(t *testing.T) {
	t.Helper()

	password := os.Getenv("DEV_PASSWORD_DNSADMIN")
	if password == "" {
		t.Fatal("no password configured for dnsadmin, check .env.dev")
	}

	response, err := g.client.PostForm(g.server.URL+"/login",
		url.Values{"username": {"dnsadmin"}, "password": {password}})
	if err != nil {
		t.Fatalf("the login request failed: %v", err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d, want 200", response.StatusCode)
	}
	for _, cookie := range response.Cookies() {
		if cookie.Name == auth.SessionCookieName {
			g.cookie = cookie
		}
	}
	if g.cookie == nil {
		t.Fatal("the login returned no session cookie")
	}
	g.token = g.csrfToken(t)
}

// csrfToken reads the token the layout hands to htmx.
func (g *gateFleet) csrfToken(t *testing.T) string {
	t.Helper()

	body := g.get(t, "/dns", http.StatusOK)
	const marker = `hx-headers='{"X-CSRF-Token": "`

	start := strings.Index(body, marker)
	if start < 0 {
		t.Fatal("the page carries no CSRF token")
	}
	rest := body[start+len(marker):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		t.Fatal("the CSRF token is not terminated")
	}
	return rest[:end]
}

// get sends one authenticated read.
func (g *gateFleet) get(t *testing.T, path string, want int) string {
	t.Helper()
	return g.do(t, http.MethodGet, path, nil, want)
}

// post sends one authenticated form.
func (g *gateFleet) post(t *testing.T, path string, form url.Values, want int) string {
	t.Helper()
	return g.do(t, http.MethodPost, path, form, want)
}

func (g *gateFleet) do(t *testing.T, method, path string,
	form url.Values, want int) string {

	t.Helper()

	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}

	request, err := http.NewRequest(method, g.server.URL+path, body)
	if err != nil {
		t.Fatalf("cannot build the request: %v", err)
	}
	request.AddCookie(g.cookie)
	if form != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if g.token != "" {
		request.Header.Set("X-CSRF-Token", g.token)
	}
	// Same origin, the way a browser would send it.
	request.Header.Set("Origin", g.server.URL)

	response, err := g.client.Do(request)
	if err != nil {
		t.Fatalf("%s %s failed: %v", method, path, err)
	}
	defer func() { _ = response.Body.Close() }()

	content, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("cannot read the response: %v", err)
	}
	if want != 0 && response.StatusCode != want {
		t.Fatalf("%s %s = %d, want %d:\n%s",
			method, path, response.StatusCode, want, content)
	}
	return string(content)
}

// register adds one server with the development key.
func (g *gateFleet) register(t *testing.T, name, host string) {
	t.Helper()

	material, err := os.ReadFile(devKeyPath)
	if err != nil {
		t.Fatalf("the development key is missing, run inside the stack: %v", err)
	}

	_, _, err = g.servers.Create(context.Background(), gateActor(), server.CreateInput{
		Server: server.Server{
			Name: name, Host: host, SSHUser: "dnsops", Enabled: true,
			StatusCmd: devStatusCmd,
		},
		PrivateKey: string(material),
	})
	if err != nil {
		t.Fatalf("cannot register %s: %v", name, err)
	}
}

// approve stores the key the target offers, the way an operator would after
// comparing the fingerprint.
func (g *gateFleet) approve(t *testing.T, id int64) {
	t.Helper()

	offer, err := g.servers.ScanHostKey(context.Background(), id)
	if err != nil {
		t.Fatalf("cannot read the host key of server %d: %v", id, err)
	}
	if err := g.servers.TrustHostKey(context.Background(),
		gateActor(), id, offer.Fingerprint); err != nil {
		t.Fatalf("cannot approve the host key of server %d: %v", id, err)
	}
}

// groupForm is the target every change in this file uses.
func (g *gateFleet) groupForm(values url.Values) url.Values {
	values.Set("scope", "group")
	values.Set("group_id", fmt.Sprint(g.groupID))
	return values
}

// fileOf reads the records file of one target, outside the panel.
func (g *gateFleet) fileOf(t *testing.T, name string) string {
	t.Helper()

	output, err := runOnTarget(name, "cat "+entriesPath)
	if err != nil {
		t.Fatalf("cannot read the file on %s: %v\n%s", name, err, output)
	}
	return output
}

// runOnTarget runs one command on a development target over the ssh client.
//
// It goes around the panel on purpose. A check that used the panel's own
// transport would prove only that the panel agrees with itself. The host key
// is not checked here for the same reason: this is the test looking at the
// stack, not the panel deciding whom to trust.
func runOnTarget(host, command string) (string, error) {
	output, err := exec.Command("ssh",
		"-i", devKeyPath,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "LogLevel=ERROR",
		"-o", "ConnectTimeout=5",
		"-l", "dnsops", host, command).CombinedOutput()

	return string(output), err
}

func TestGateAChangeReachesEveryServerAndNamesTheOneItMissed(t *testing.T) {
	// The report is the whole point of a multi server panel: three files
	// changed, one machine refused, and the operator told which is which. The
	// fourth server offers no host key anybody could approve, because nothing
	// answers at its address.
	g := newGateFleet(t)

	record := dnsfile.Record{
		FQDN: "gate-fleet.example.local", Type: "A", Value: "10.0.0.81"}
	t.Cleanup(func() {
		_, _ = g.records.Apply(context.Background(), gateActor(),
			fleet.Target{Scope: fleet.ScopeGroup, GroupID: g.groupID},
			fleet.Operation{Kind: fleet.OpDelete, Record: record})
	})

	body := g.post(t, "/dns/records", g.groupForm(url.Values{
		"fqdn": {record.FQDN}, "type": {record.Type}, "value": {record.Value},
	}), http.StatusMultiStatus)

	// One server failed, so the response is a 207 and the body names it.
	if !strings.Contains(body, "dns-down") {
		t.Errorf("the report does not name the server that failed:\n%s", body)
	}
	for _, name := range []string{"dns1", "dns2", "dns3"} {
		if !strings.Contains(g.fileOf(t, name), record.Value) {
			t.Errorf("the record did not reach %s", name)
		}
	}
}

func TestGateADifferenceIsFoundAndRepaired(t *testing.T) {
	// Somebody edits one file by hand. The panel has to see it and put it
	// back, and it may not touch the servers that already agree.
	g := newGateFleet(t)

	record := dnsfile.Record{
		FQDN: "gate-repair.example.local", Type: "A", Value: "10.0.0.82"}
	t.Cleanup(func() {
		_, _ = g.records.Apply(context.Background(), gateActor(),
			fleet.Target{Scope: fleet.ScopeGroup, GroupID: g.groupID},
			fleet.Operation{Kind: fleet.OpDelete, Record: record})
	})

	g.post(t, "/dns/records", g.groupForm(url.Values{
		"fqdn": {record.FQDN}, "type": {record.Type}, "value": {record.Value},
	}), http.StatusMultiStatus)

	// The line leaves dns1 behind the panel's back. The two sudo rules the
	// target grants are the only way to write the file, so the edit goes
	// through them rather than through the panel.
	if output, err := runOnTarget("dns1", fmt.Sprintf(
		"grep -v %s %s | sudo tee /etc/unbound/.local_records.conf.tmp >/dev/null"+
			" && sudo mv /etc/unbound/.local_records.conf.tmp %s",
		record.FQDN, entriesPath, entriesPath)); err != nil {
		t.Fatalf("cannot break the file on dns1: %v\n%s", err, output)
	}
	if strings.Contains(g.fileOf(t, "dns1"), record.FQDN) {
		t.Fatal("the record is still on dns1, the test broke nothing")
	}

	if _, err := g.records.Refresh(context.Background()); err != nil {
		t.Fatalf("cannot refresh the cache: %v", err)
	}

	table := g.get(t, fmt.Sprintf(
		"/diff/table?view=1&scope=group&group_id=%d&only_mismatches=1&search=%s",
		g.groupID, record.FQDN), http.StatusOK)
	if !strings.Contains(table, "missing") {
		t.Fatalf("the diff does not report the missing record:\n%s", table)
	}

	report := g.post(t, "/diff/repair", g.groupForm(url.Values{
		"fqdn": {record.FQDN}, "type": {record.Type}, "value": {record.Value},
	}), 0)

	if !strings.Contains(g.fileOf(t, "dns1"), record.Value) {
		t.Errorf("the repair did not restore the record on dns1:\n%s", report)
	}
	// The two that already agreed were left alone, which is what the report
	// calls skipped.
	if strings.Count(report, "skipped") < 2 {
		t.Errorf("the repair did not skip the servers that agreed:\n%s", report)
	}
}
