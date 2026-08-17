package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"jbound/internal/agentapi"
)

const theToken = "3PxTGZlhkQ0nR7wUVs9bFYcJdMeAoLiK"

// harness is an agent over a temporary directory that stands in for /etc.
type harness struct {
	agent       *Agent
	server      *httptest.Server
	recordsPath string
	mainPath    string
}

func newHarness(t *testing.T, records, main string) *harness {
	t.Helper()

	dir := t.TempDir()
	h := &harness{
		recordsPath: filepath.Join(dir, "local_records.conf"),
		mainPath:    filepath.Join(dir, "unbound.conf"),
	}

	if records != "" {
		if err := os.WriteFile(h.recordsPath, []byte(records), 0o644); err != nil {
			t.Fatalf("cannot write the records file: %v", err)
		}
	}
	if err := os.WriteFile(h.mainPath, []byte(main), 0o644); err != nil {
		t.Fatalf("cannot write the main configuration: %v", err)
	}

	cfg := &Config{
		RecordsPath:    h.recordsPath,
		MainConfig:     h.mainPath,
		CommandTimeout: 5 * time.Second,
		StatusCmd:      Command{"/usr/bin/true"},
	}

	h.agent = NewAgent(cfg, theToken,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.server = httptest.NewServer(h.agent.Routes())
	t.Cleanup(h.server.Close)
	return h
}

// call sends one authenticated request.
func (h *harness) call(t *testing.T, method, path string, body any) *http.Response {
	t.Helper()
	return h.callWithToken(t, method, path, body, theToken)
}

func (h *harness) callWithToken(t *testing.T, method, path string,
	body any, token string) *http.Response {

	t.Helper()

	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("cannot encode the request: %v", err)
		}
		reader = strings.NewReader(string(encoded))
	}

	request, err := http.NewRequest(method, h.server.URL+path, reader)
	if err != nil {
		t.Fatalf("cannot build the request: %v", err)
	}
	if token != "" {
		request.Header.Set("Authorization", agentapi.AuthScheme+" "+token)
	}

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("the request failed: %v", err)
	}
	t.Cleanup(func() { _ = response.Body.Close() })
	return response
}

func (h *harness) records(t *testing.T) string {
	t.Helper()

	data, err := os.ReadFile(h.recordsPath)
	if err != nil {
		t.Fatalf("cannot read the records file: %v", err)
	}
	return string(data)
}

func (h *harness) main(t *testing.T) string {
	t.Helper()

	data, err := os.ReadFile(h.mainPath)
	if err != nil {
		t.Fatalf("cannot read the main configuration: %v", err)
	}
	return string(data)
}

func decode[T any](t *testing.T, response *http.Response) T {
	t.Helper()

	var value T
	if err := json.NewDecoder(response.Body).Decode(&value); err != nil {
		t.Fatalf("cannot read the answer: %v", err)
	}
	return value
}

func digestString(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

// --- Tests -----------------------------------------------------------------

func TestEveryEndpointRefusesTheWrongToken(t *testing.T) {
	// The token is the whole of the panel's authority over this resolver. A
	// route added later must not be able to escape the check by forgetting a
	// line, so the guard wraps the mux and a test walks every path.
	h := newHarness(t, "server:\n", "server:\n")

	for _, route := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, agentapi.PathInfo},
		{http.MethodGet, agentapi.PathRecords},
		{http.MethodPut, agentapi.PathRecords},
		{http.MethodPost, agentapi.PathEnsureInclude},
		{http.MethodPost, agentapi.PathCheckConf},
		{http.MethodPost, agentapi.PathReload},
		{http.MethodPost, agentapi.PathReloadBack},
		{http.MethodPost, agentapi.PathRestart},
		{http.MethodGet, agentapi.PathStatus},
	} {
		t.Run(route.path+" "+route.method, func(t *testing.T) {
			for _, token := range []string{"", "wrong", theToken + "x"} {
				response := h.callWithToken(t, route.method, route.path, nil, token)
				if response.StatusCode != http.StatusUnauthorized {
					t.Errorf("token %q got %d, want 401", token, response.StatusCode)
				}
			}
		})
	}
}

func TestARefusalNeverQuotesWhatWasOffered(t *testing.T) {
	// A near miss written into a log or an answer is a token to rotate. The
	// agent says the token is wrong and nothing else.
	h := newHarness(t, "server:\n", "server:\n")

	response := h.callWithToken(t, http.MethodGet, agentapi.PathInfo, nil, "almost-right")
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("cannot read the answer: %v", err)
	}

	for _, secret := range []string{"almost-right", theToken} {
		if strings.Contains(string(body), secret) {
			t.Errorf("the refusal carries %q: %s", secret, body)
		}
	}
}

func TestTheAgentSaysWhichFileItManages(t *testing.T) {
	// The path travels from here to the panel and never the other way, so this
	// answer is how the panel learns it at all.
	h := newHarness(t, "server:\n", "server:\ninclude: ")
	if err := os.WriteFile(h.mainPath,
		[]byte("server:\ninclude: "+h.recordsPath+"\n"), 0o644); err != nil {
		t.Fatalf("cannot write the main configuration: %v", err)
	}

	response := h.call(t, http.MethodGet, agentapi.PathInfo, nil)
	info := decode[agentapi.Info](t, response)

	if info.RecordsPath != h.recordsPath {
		t.Errorf("records path = %q, want %q", info.RecordsPath, h.recordsPath)
	}
	if !info.IncludeOK {
		t.Error("a main configuration that includes the file was reported as not")
	}
	if info.Version != agentapi.Version {
		t.Errorf("version = %q", info.Version)
	}
	if !info.Steps.Status {
		t.Error("a configured status command was reported as absent")
	}
	if info.Steps.Reload {
		t.Error("a step with no command was reported as configured")
	}
}

func TestNoRequestCanChooseWhichFileIsWritten(t *testing.T) {
	// The one property everything else rests on. A stolen token has to stay a
	// way to change DNS records rather than a way to write any file on this
	// host, so a body carrying a path is written to the configured file and
	// the named one is never touched.
	h := newHarness(t, "server:\n", "server:\n")

	elsewhere := filepath.Join(t.TempDir(), "authorized_keys")
	body := map[string]string{
		"content":       base64.StdEncoding.EncodeToString([]byte("server:\n# owned\n")),
		"expect_sha256": digestString("server:\n"),
		"path":          elsewhere,
		"records_path":  elsewhere,
		"file":          elsewhere,
	}

	response := h.call(t, http.MethodPut, agentapi.PathRecords, body)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}

	if _, err := os.Stat(elsewhere); !os.IsNotExist(err) {
		t.Fatalf("the agent wrote the file the request named: %v", err)
	}
	if !strings.Contains(h.records(t), "# owned") {
		t.Errorf("the configured file was not written:\n%s", h.records(t))
	}
}

func TestAWriteThatLostTheRaceChangesNothing(t *testing.T) {
	// Another operator wrote between the panel's read and its write. Taking
	// this one would silently drop their change.
	const before = "server:\nlocal-data: \"a.example.local. A 10.0.0.1\"\n"
	h := newHarness(t, before, "server:\n")

	response := h.call(t, http.MethodPut, agentapi.PathRecords, agentapi.WriteRequest{
		Content:      base64.StdEncoding.EncodeToString([]byte("server:\n# replaced\n")),
		ExpectSHA256: digestString("something else entirely"),
	})

	if response.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d, want 409", response.StatusCode)
	}
	if got := h.records(t); got != before {
		t.Errorf("the file changed despite the conflict:\n%s", got)
	}
}

func TestAWriteWithNoExpectedDigestIsTaken(t *testing.T) {
	// A first write to a target the panel has not read yet. Refusing it would
	// mean a freshly added server can never be written to.
	h := newHarness(t, "server:\n", "server:\n")

	response := h.call(t, http.MethodPut, agentapi.PathRecords, agentapi.WriteRequest{
		Content: base64.StdEncoding.EncodeToString([]byte("server:\n# first\n")),
	})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
	if !strings.Contains(h.records(t), "# first") {
		t.Errorf("the write did not land:\n%s", h.records(t))
	}
}

func TestAReadAndAWriteCarryTheFileUnchanged(t *testing.T) {
	const content = "server:\nlocal-data: \"a.example.local. A 10.0.0.1\"\n# ünïcödé\n"
	h := newHarness(t, content, "server:\n")

	response := h.call(t, http.MethodGet, agentapi.PathRecords, nil)
	answer := decode[agentapi.Records](t, response)

	data, err := base64.StdEncoding.DecodeString(answer.Content)
	if err != nil {
		t.Fatalf("the content is not base64: %v", err)
	}
	if string(data) != content {
		t.Errorf("read back %q, want %q", data, content)
	}
	if answer.SHA256 != digestString(content) {
		t.Errorf("digest = %q", answer.SHA256)
	}
}

func TestAStepWithNoCommandIsSkippedRatherThanFailed(t *testing.T) {
	// A resolver without a control socket has no reload command. The panel's
	// ladder moves on to the next rung, which only works if this is its own
	// answer rather than a failure.
	h := newHarness(t, "server:\n", "server:\n")

	response := h.call(t, http.MethodPost, agentapi.PathReload, nil)
	if response.StatusCode != agentapi.StatusStepSkipped {
		t.Fatalf("status = %d, want %d", response.StatusCode, agentapi.StatusStepSkipped)
	}

	failure := decode[agentapi.Error](t, response)
	if failure.Class != agentapi.ClassSkipped {
		t.Errorf("class = %q", failure.Class)
	}
}

func TestARefusedCommandCarriesWhatItSaid(t *testing.T) {
	// "The change failed" would send the operator to this host to read what
	// the resolver already said.
	h := newHarness(t, "server:\n", "server:\n")
	h.agent.cfg.CheckConfCmd = Command{"/bin/sh", "-c", "echo refused-on-line-12 >&2; exit 1"}

	response := h.call(t, http.MethodPost, agentapi.PathCheckConf, nil)
	if response.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", response.StatusCode)
	}

	failure := decode[agentapi.Error](t, response)
	if !strings.Contains(failure.Message, "refused-on-line-12") {
		t.Errorf("the answer drops what the command said: %q", failure.Message)
	}
}

func TestAStoppedResolverIsAnAnswerRatherThanAFailure(t *testing.T) {
	// systemctl is-active exits 3 for a stopped unit. The panel's ladder needs
	// that as information, because it is how a reload that left the resolver
	// down is caught.
	h := newHarness(t, "server:\n", "server:\n")
	h.agent.cfg.StatusCmd = Command{"/bin/sh", "-c", "echo inactive; exit 3"}

	response := h.call(t, http.MethodGet, agentapi.PathStatus, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}

	answer := decode[agentapi.StatusResult](t, response)
	if answer.Active {
		t.Error("a stopped resolver was reported as running")
	}
	if !strings.Contains(answer.Detail, "inactive") {
		t.Errorf("detail = %q", answer.Detail)
	}
}

func TestAMissingIncludeIsAddedAndSaidSo(t *testing.T) {
	h := newHarness(t, "server:\n", "server:\n    verbosity: 1\n")

	response := h.call(t, http.MethodPost, agentapi.PathEnsureInclude, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}

	answer := decode[agentapi.CommandResult](t, response)
	if answer.Output != "added" {
		t.Errorf("output = %q, want it to say the line was added", answer.Output)
	}
	if !strings.Contains(h.main(t), "include: "+h.recordsPath) {
		t.Errorf("the include line was not added:\n%s", h.main(t))
	}
}

func TestARepairThatWasAlreadyDoneChangesNothing(t *testing.T) {
	// The panel asks before every change. A second line on every one of them
	// would turn a repair into a growing configuration.
	h := newHarness(t, "server:\n",
		"server:\n    verbosity: 1\n")

	for range 3 {
		h.call(t, http.MethodPost, agentapi.PathEnsureInclude, nil)
	}

	if count := strings.Count(h.main(t), "include: "+h.recordsPath); count != 1 {
		t.Errorf("the main configuration holds %d include lines, want one:\n%s",
			count, h.main(t))
	}
	if count := strings.Count(h.records(t), clauseHeader); count != 1 {
		t.Errorf("the records file holds %d clause headers, want one:\n%s",
			count, h.records(t))
	}
}

func TestAHeaderlessRecordsFileIsRepairedWithoutLosingRecords(t *testing.T) {
	// A file somebody set up by hand holds bare local-data lines. The header
	// goes on top; the records stay where they are.
	const before = "local-data: \"a.example.local. A 10.0.0.1\"\n"
	h := newHarness(t, before, "server:\n")

	h.call(t, http.MethodPost, agentapi.PathEnsureInclude, nil)

	after := h.records(t)
	if !strings.HasPrefix(after, clauseHeader+"\n") {
		t.Errorf("the header is not at the top:\n%s", after)
	}
	if !strings.Contains(after, before) {
		t.Errorf("the records did not survive:\n%s", after)
	}
}

func TestAnIncludeOfAnotherFileIsNotMistakenForThisOne(t *testing.T) {
	// A substring match would call this done and leave a resolver reading
	// nothing the panel writes.
	h := newHarness(t, "server:\n",
		"server:\n    include: /etc/unbound/other_records.conf\n")

	response := h.call(t, http.MethodPost, agentapi.PathEnsureInclude, nil)
	answer := decode[agentapi.CommandResult](t, response)

	if answer.Output != "added" {
		t.Errorf("output = %q, want the line to have been added", answer.Output)
	}
}

func TestAQuotedIncludeCounts(t *testing.T) {
	// Unbound accepts the path either way and operators write both. Adding a
	// second line for a file that is already included would be a change the
	// agent makes for nothing.
	h := newHarness(t, "server:\n", "")
	if err := os.WriteFile(h.mainPath,
		[]byte("server:\n    include: \""+h.recordsPath+"\"\n"), 0o644); err != nil {
		t.Fatalf("cannot write the main configuration: %v", err)
	}

	response := h.call(t, http.MethodPost, agentapi.PathEnsureInclude, nil)
	answer := decode[agentapi.CommandResult](t, response)

	if answer.Output != "ok" {
		t.Errorf("output = %q, want a quoted include to count", answer.Output)
	}
}

func TestTheRecordsFileIsLeftReadableByTheResolver(t *testing.T) {
	// The resolver drops privileges and still has to open it. A file the
	// umask of whoever started this process decided on is not something to
	// leave a daemon depending on.
	h := newHarness(t, "server:\n", "server:\n")

	h.call(t, http.MethodPut, agentapi.PathRecords, agentapi.WriteRequest{
		Content: base64.StdEncoding.EncodeToString([]byte("server:\n# written\n")),
	})

	info, err := os.Stat(h.recordsPath)
	if err != nil {
		t.Fatalf("cannot read the records file: %v", err)
	}
	if mode := info.Mode().Perm(); mode != recordsMode {
		t.Errorf("the file is mode %o, want %o", mode, recordsMode)
	}
}

func TestNoTemporaryFileIsLeftBehind(t *testing.T) {
	// A write leaves the directory as it found it, minus the change. A
	// leftover staging file in /etc/unbound would be swept into any config
	// that includes a wildcard.
	h := newHarness(t, "server:\n", "server:\n")

	h.call(t, http.MethodPut, agentapi.PathRecords, agentapi.WriteRequest{
		Content: base64.StdEncoding.EncodeToString([]byte("server:\n# written\n")),
	})

	entries, err := os.ReadDir(filepath.Dir(h.recordsPath))
	if err != nil {
		t.Fatalf("cannot list the directory: %v", err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".tmp") {
			t.Errorf("a staging file was left behind: %s", entry.Name())
		}
	}
}

func TestABodyLargerThanTheLimitIsRefused(t *testing.T) {
	// The agent runs as root on a resolver. A body nobody bounded is the
	// cheapest way to stop one.
	h := newHarness(t, "server:\n", "server:\n")

	// A body that parses as far as it goes, so the refusal comes from the
	// limit rather than from the first character not being a brace.
	body := io.MultiReader(
		strings.NewReader(`{"content":"`),
		io.LimitReader(filler{}, agentapi.MaxBodyBytes*2))

	request, err := http.NewRequest(http.MethodPut, h.server.URL+agentapi.PathRecords, body)
	if err != nil {
		t.Fatalf("cannot build the request: %v", err)
	}
	request.Header.Set("Authorization", agentapi.AuthScheme+" "+theToken)
	request.Header.Set("Content-Type", "application/json")

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("the request failed: %v", err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", response.StatusCode)
	}
}

// filler is base64 that never stops.
type filler struct{}

func (filler) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'A'
	}
	return len(p), nil
}

func TestAConfigurationWithARelativePathDoesNotStart(t *testing.T) {
	// A relative path resolves against whatever directory systemd gave the
	// process, which is not where a resolver keeps its configuration.
	t.Setenv("RECORDS_PATH", "local_records.conf")

	if _, err := Load(); err == nil {
		t.Fatal("a relative records path was accepted")
	}
}

func TestACommandWithAShellMetacharacterDoesNotStart(t *testing.T) {
	// There is no shell in this binary, so one of these can only come from a
	// misconfiguration or from somebody trying to make it into one. Failing at
	// startup surfaces both, on the host where they can be corrected.
	t.Setenv("RELOAD_CMD", "/usr/sbin/unbound-control reload; rm -rf /")

	if _, err := Load(); err == nil {
		t.Fatal("a command carrying a shell metacharacter was accepted")
	}
}

func TestATokenFileOthersCanReadIsRefused(t *testing.T) {
	// The token is the whole of the panel's authority over this resolver, and
	// a world readable file hands it to every account on the host.
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(theToken), 0o644); err != nil {
		t.Fatalf("cannot write the token: %v", err)
	}

	if _, err := readToken(path); err == nil {
		t.Fatal("a token file other accounts can read was accepted")
	}
}

func TestATokenIsNeverQuotedBackWhenItsFileIsWrong(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(theToken), 0o604); err != nil {
		t.Fatalf("cannot write the token: %v", err)
	}

	_, err := readToken(path)
	if err == nil {
		t.Fatal("a token file other accounts can read was accepted")
	}
	if strings.Contains(err.Error(), theToken) {
		t.Errorf("the failure carries the token: %v", err)
	}
}

func TestAnEmptyTokenFileIsRefused(t *testing.T) {
	// An empty token would compare equal to an empty header, which is every
	// request that arrives without one.
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("   \n"), 0o600); err != nil {
		t.Fatalf("cannot write the token: %v", err)
	}

	if _, err := readToken(path); err == nil {
		t.Fatal("an empty token file was accepted")
	}
}

// --- What may be written ---------------------------------------------------

func TestARecordsFileOfRecordsIsTaken(t *testing.T) {
	// Everything the panel and an operator legitimately put in this file: the
	// clause header, comments, blank lines and the three record directives.
	h := newHarness(t, "", "server:\n")

	content := `# Seeded by hand.

server:
local-data: "www.example.net. A 192.0.2.10"
local-data-ptr: "192.0.2.10 www.example.net."
local-zone: "example.net." transparent
local-zone: "ads.example.net." always_nxdomain
`

	response := h.call(t, http.MethodPut, agentapi.PathRecords,
		agentapi.WriteRequest{Content: base64.StdEncoding.EncodeToString([]byte(content))})

	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}
	if h.records(t) != content {
		t.Errorf("the file does not hold what was sent:\n%s", h.records(t))
	}
}

func TestADirectiveThatIsNotARecordIsRefused(t *testing.T) {
	// The reason this check exists. The file is included inside a server
	// clause, unbound reads it as root, and the Debian build carries the
	// python module, so one directive here is a way to run code on the host.
	cases := map[string]string{
		"a module that runs code": "server:\nmodule-config: \"python iterator\"\n",
		"the account to run as":   "server:\nusername: root\n",
		"another file to read":    "server:\ninclude: /tmp/anything.conf\n",
		"a chroot":                "server:\nchroot: \"\"\n",
	}

	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, "server:\n", "server:\n")

			response := h.call(t, http.MethodPut, agentapi.PathRecords,
				agentapi.WriteRequest{Content: base64.StdEncoding.EncodeToString([]byte(content))})

			if response.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", response.StatusCode)
			}
			if h.records(t) != "server:\n" {
				t.Errorf("the file was written anyway:\n%s", h.records(t))
			}
		})
	}
}

func TestARefusedWriteNamesTheLineAndTheDirective(t *testing.T) {
	// An operator has to be able to find it. The line number and the directive
	// are enough for that, and the rest of the line is not something to copy
	// into a log.
	h := newHarness(t, "server:\n", "server:\n")

	content := "server:\nlocal-data: \"www.example.net. A 192.0.2.10\"\nmodule-config: \"python iterator\"\n"
	response := h.call(t, http.MethodPut, agentapi.PathRecords,
		agentapi.WriteRequest{Content: base64.StdEncoding.EncodeToString([]byte(content))})

	answer := decode[agentapi.Error](t, response)
	if answer.Class != agentapi.ClassBadInput {
		t.Errorf("class = %q, want %q", answer.Class, agentapi.ClassBadInput)
	}
	if !strings.Contains(answer.Message, "line 3") {
		t.Errorf("the message does not name the line: %q", answer.Message)
	}
	if !strings.Contains(answer.Message, "module-config") {
		t.Errorf("the message does not name the directive: %q", answer.Message)
	}
	if strings.Contains(answer.Message, "python iterator") {
		t.Errorf("the message repeats what was sent: %q", answer.Message)
	}
}

func TestAFileThatAlreadyHoldsSomethingElseCanStillBeRead(t *testing.T) {
	// The check guards the write and not the read. A target prepared before
	// this rule existed has to stay readable, or the panel could not show the
	// operator what is on it.
	h := newHarness(t, "server:\nmodule-config: \"python iterator\"\n", "server:\n")

	response := h.call(t, http.MethodGet, agentapi.PathRecords, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}

	answer := decode[agentapi.Records](t, response)
	data, err := base64.StdEncoding.DecodeString(answer.Content)
	if err != nil {
		t.Fatalf("the content is not base64: %v", err)
	}
	if !strings.Contains(string(data), "module-config") {
		t.Errorf("the read did not carry the file as it is:\n%s", data)
	}
}

// --- What a rewrite leaves behind ------------------------------------------

func TestTheMainConfigurationKeepsItsMode(t *testing.T) {
	// A rename replaces the inode, so a file this agent rewrites would come
	// back with whatever mode the agent felt like. The main configuration is
	// not the agent's file to normalise: 0640 stays 0640.
	h := newHarness(t, "server:\n", "server:\n")
	if err := os.Chmod(h.mainPath, 0o640); err != nil {
		t.Fatalf("cannot set the mode: %v", err)
	}

	response := h.call(t, http.MethodPost, agentapi.PathEnsureInclude, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}
	if !strings.Contains(h.main(t), "include:") {
		t.Fatalf("the include line was not added:\n%s", h.main(t))
	}

	info, err := os.Stat(h.mainPath)
	if err != nil {
		t.Fatalf("cannot stat the main configuration: %v", err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Errorf("mode = %o, want 640", info.Mode().Perm())
	}
}

func TestARecordsFileNobodyCouldReadIsMadeReadableAgain(t *testing.T) {
	// The other direction. The resolver drops privileges and still has to open
	// this one, so a mode that would keep it shut is not carried over.
	h := newHarness(t, "server:\n", "server:\n")
	if err := os.Chmod(h.recordsPath, 0o600); err != nil {
		t.Fatalf("cannot set the mode: %v", err)
	}

	content := "server:\nlocal-data: \"www.example.net. A 192.0.2.10\"\n"
	response := h.call(t, http.MethodPut, agentapi.PathRecords,
		agentapi.WriteRequest{Content: base64.StdEncoding.EncodeToString([]byte(content))})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}

	info, err := os.Stat(h.recordsPath)
	if err != nil {
		t.Fatalf("cannot stat the records file: %v", err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("mode = %o, want 644", info.Mode().Perm())
	}
}

func TestARecordsFileKeepsAModeTheResolverCanRead(t *testing.T) {
	// A mode somebody chose on purpose survives, as long as the resolver can
	// still open the file.
	h := newHarness(t, "server:\n", "server:\n")
	if err := os.Chmod(h.recordsPath, 0o664); err != nil {
		t.Fatalf("cannot set the mode: %v", err)
	}

	content := "server:\nlocal-data: \"www.example.net. A 192.0.2.10\"\n"
	h.call(t, http.MethodPut, agentapi.PathRecords,
		agentapi.WriteRequest{Content: base64.StdEncoding.EncodeToString([]byte(content))})

	info, err := os.Stat(h.recordsPath)
	if err != nil {
		t.Fatalf("cannot stat the records file: %v", err)
	}
	if info.Mode().Perm() != 0o664 {
		t.Errorf("mode = %o, want 664", info.Mode().Perm())
	}
}

func TestARewrittenFileKeepsItsGroup(t *testing.T) {
	// The owner cannot be carried over by a process that is not root, and the
	// group is what is left. A group this account belongs to but does not write
	// files under is one the rewrite has to put back deliberately.
	other := aSecondaryGroup(t)
	h := newHarness(t, "server:\n", "server:\n")
	if err := os.Chown(h.recordsPath, -1, other); err != nil {
		t.Skipf("cannot set the group: %v", err)
	}

	content := "server:\nlocal-data: \"www.example.net. A 192.0.2.10\"\n"
	response := h.call(t, http.MethodPut, agentapi.PathRecords,
		agentapi.WriteRequest{Content: base64.StdEncoding.EncodeToString([]byte(content))})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}

	info, err := os.Stat(h.recordsPath)
	if err != nil {
		t.Fatalf("cannot stat the records file: %v", err)
	}
	if gid := int(info.Sys().(*syscall.Stat_t).Gid); gid != other {
		t.Errorf("gid = %d, want %d", gid, other)
	}
}

// aSecondaryGroup names a group this account is in that a file it creates would
// not land in by itself. Without one there is nothing to observe, so the test
// asking for it has no run.
func aSecondaryGroup(t *testing.T) int {
	t.Helper()

	groups, err := os.Getgroups()
	if err != nil {
		t.Skipf("cannot read the groups: %v", err)
	}
	own := os.Getegid()
	for _, gid := range groups {
		if gid != own {
			return gid
		}
	}
	t.Skip("this account is in one group only")
	return -1
}
