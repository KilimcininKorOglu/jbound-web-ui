package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"jbound/internal/agentapi"
)

// theToken is what every fake agent in this file expects.
const theToken = "3PxTGZlhkQ0nR7wUVs9bFYcJdMeAoLiK"

// agentHarness is a fake agent over TLS, with the fingerprint the panel has to
// pin and a token it has to send.
type agentHarness struct {
	server      *httptest.Server
	fingerprint string
	tokenPath   string

	// requests records the path of every call, so a test can prove which
	// endpoint ran and which did not.
	requests []string
}

func newAgentHarness(t *testing.T, handler http.HandlerFunc) *agentHarness {
	t.Helper()

	harness := &agentHarness{}
	server := httptest.NewUnstartedServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			harness.requests = append(harness.requests, r.URL.Path)

			if r.Header.Get("Authorization") != agentapi.AuthScheme+" "+theToken {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(agentapi.Error{
					Class: agentapi.ClassAuth, Message: "the token is wrong"})
				return
			}
			handler(w, r)
		}))

	server.TLS = &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}}
	server.StartTLS()
	t.Cleanup(server.Close)

	harness.server = server
	harness.fingerprint = CertFingerprint(server.Certificate().Raw)

	dir := t.TempDir()
	harness.tokenPath = filepath.Join(dir, "server-1.token")
	if err := os.WriteFile(harness.tokenPath, []byte(theToken+"\n"), 0o600); err != nil {
		t.Fatalf("cannot write the token: %v", err)
	}
	return harness
}

// config builds a panel side configuration pointed at this harness.
func (h *agentHarness) config(t *testing.T) Config {
	t.Helper()

	parsed, err := url.Parse(h.server.URL)
	if err != nil {
		t.Fatalf("cannot read the harness address: %v", err)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatalf("cannot read the harness port: %v", err)
	}

	return Config{
		ID:             1,
		Name:           "dns4",
		Kind:           KindAgent,
		Host:           parsed.Hostname(),
		AgentPort:      port,
		HostKey:        h.fingerprint,
		TokenPath:      h.tokenPath,
		ConnectTimeout: 5 * time.Second,
		CommandTimeout: 5 * time.Second,
	}
}

func (h *agentHarness) transport(t *testing.T) *AgentTransport {
	t.Helper()

	client, err := NewAgent(h.config(t))
	if err != nil {
		t.Fatalf("NewAgent returned an error: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

// selfSigned builds a certificate for 127.0.0.1, which is where httptest binds.
func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate a key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "jbound-agent"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cannot sign the certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// answerJSON writes one value as the agent would.
func answerJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func TestACertificateNobodyApprovedStopsTheConnection(t *testing.T) {
	// The same rule the SSH path holds. There is no trust on first sight: an
	// operator approves a fingerprint, and until they do the panel refuses to
	// talk rather than deciding for them.
	harness := newAgentHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		answerJSON(w, agentapi.Info{Version: agentapi.Version})
	})

	cfg := harness.config(t)
	cfg.HostKey = ""

	client, err := NewAgent(cfg)
	if err != nil {
		t.Fatalf("NewAgent returned an error: %v", err)
	}
	defer client.Close()

	_, err = client.Info(context.Background())
	if !errors.Is(err, ErrHostKeyUnknown) {
		t.Fatalf("error = %v, want an unapproved certificate", err)
	}

	var hostKeyErr *HostKeyError
	if !errors.As(err, &hostKeyErr) {
		t.Fatalf("error = %v, want it to carry the fingerprint", err)
	}
	if hostKeyErr.Observed != harness.fingerprint {
		t.Errorf("reported %q, want %q", hostKeyErr.Observed, harness.fingerprint)
	}
}

func TestACertificateThatChangedStopsTheConnection(t *testing.T) {
	// An agent whose certificate is not the approved one is either a rebuilt
	// host or somebody in the middle, and the panel cannot tell which. It
	// stops and says what it saw.
	harness := newAgentHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		answerJSON(w, agentapi.Info{Version: agentapi.Version})
	})

	cfg := harness.config(t)
	cfg.HostKey = "SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32))

	client, err := NewAgent(cfg)
	if err != nil {
		t.Fatalf("NewAgent returned an error: %v", err)
	}
	defer client.Close()

	if _, err := client.Info(context.Background()); !errors.Is(err, ErrHostKeyMismatch) {
		t.Fatalf("error = %v, want a mismatch", err)
	}
}

func TestARefusedTokenIsReportedWithoutTheToken(t *testing.T) {
	// The message reaches a page. An agent that echoed the token into its
	// refusal would put the token in front of whoever is looking, and the
	// panel is the last place that can stop it.
	harness := newAgentHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		answerJSON(w, agentapi.Info{Version: agentapi.Version})
	})

	cfg := harness.config(t)
	wrong := filepath.Join(t.TempDir(), "wrong.token")
	if err := os.WriteFile(wrong, []byte("not-the-token"), 0o600); err != nil {
		t.Fatalf("cannot write the token: %v", err)
	}
	cfg.TokenPath = wrong

	client, err := NewAgent(cfg)
	if err != nil {
		t.Fatalf("NewAgent returned an error: %v", err)
	}
	defer client.Close()

	_, err = client.Info(context.Background())
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("error = %v, want an authentication failure", err)
	}
	for _, secret := range []string{"not-the-token", theToken} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("the error carries a token: %v", err)
		}
	}
}

func TestNoTokenReachesAnErrorMessage(t *testing.T) {
	// The failure the operator sees when the file is missing names the path
	// and nothing else, so a token that was there is never quoted back.
	harness := newAgentHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		answerJSON(w, agentapi.Info{Version: agentapi.Version})
	})

	cfg := harness.config(t)
	cfg.TokenPath = filepath.Join(t.TempDir(), "absent.token")

	client, err := NewAgent(cfg)
	if err != nil {
		t.Fatalf("NewAgent returned an error: %v", err)
	}
	defer client.Close()

	_, err = client.Info(context.Background())
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("error = %v, want an authentication failure", err)
	}
	if !strings.Contains(err.Error(), "absent.token") {
		t.Errorf("the error does not name the file: %v", err)
	}
}

func TestAWriteThatLostTheRaceIsReportedAsAConflict(t *testing.T) {
	// Another operator wrote between this panel's read and its write. The
	// answer has to be its own class, because the correction is a fresh read
	// rather than a retry of the same bytes.
	harness := newAgentHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		answerJSON(w, agentapi.Error{
			Class: agentapi.ClassConflict, Message: "the file changed"})
	})

	client := harness.transport(t)
	err := client.WriteRecords(context.Background(), []byte("server:\n"), "abc")
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("error = %v, want a conflict", err)
	}
}

func TestAStepTheAgentHasNoCommandForIsSkipped(t *testing.T) {
	// An agent whose configuration names no restart command is not broken. The
	// ladder moves on to the next rung, the same as an empty command on the
	// SSH path.
	harness := newAgentHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(agentapi.StatusStepSkipped)
		answerJSON(w, agentapi.Error{Class: agentapi.ClassSkipped})
	})

	client := harness.transport(t)
	if _, err := client.Restart(context.Background()); !errors.Is(err, ErrStepSkipped) {
		t.Fatalf("error = %v, want a skipped step", err)
	}
}

func TestARefusedConfigurationCarriesWhatTheResolverSaid(t *testing.T) {
	// "The change failed" sends the operator to the server to find out why.
	// The resolver already said why.
	harness := newAgentHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		answerJSON(w, agentapi.Error{
			Class:   agentapi.ClassCommand,
			Message: "unbound-checkconf: syntax error at line 12"})
	})

	client := harness.transport(t)
	_, err := client.CheckConfig(context.Background())
	if !errors.Is(err, ErrCommandFailed) {
		t.Fatalf("error = %v, want a failed command", err)
	}
	if !strings.Contains(err.Error(), "line 12") {
		t.Errorf("the error drops what the resolver said: %v", err)
	}
}

func TestAnAnswerLargerThanTheLimitIsRefused(t *testing.T) {
	// How much the panel sets aside is not a decision the far end makes. A
	// server writing to a group holds one of these per member.
	harness := newAgentHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		// Streamed rather than built, so the test does not hold the whole
		// thing either.
		_, _ = w.Write([]byte(`{"content":"`))
		chunk := strings.Repeat("A", 1<<16)
		for written := 0; written < agentapi.MaxBodyBytes+(1<<16); written += len(chunk) {
			if _, err := w.Write([]byte(chunk)); err != nil {
				return
			}
		}
		_, _ = w.Write([]byte(`"}`))
	})

	client := harness.transport(t)
	_, _, err := client.ReadRecords(context.Background())
	if !errors.Is(err, ErrRemoteOutput) {
		t.Fatalf("error = %v, want the answer refused for its size", err)
	}
}

func TestAReadAndAWriteCarryTheFileUnchanged(t *testing.T) {
	// Base64 on the wire, so a records file holding any byte survives the
	// round trip. A file that came back altered would be drift the panel
	// caused.
	content := []byte("server:\nlocal-data: \"a.example.local. A 10.0.0.1\"\n# ünïcödé\n")
	var written []byte

	harness := newAgentHarness(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			answerJSON(w, agentapi.Records{
				Content: base64.StdEncoding.EncodeToString(content),
				SHA256:  "the-digest",
			})
			return
		}

		var request agentapi.WriteRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		written, _ = base64.StdEncoding.DecodeString(request.Content)
		answerJSON(w, agentapi.CommandResult{Output: "written"})
	})

	client := harness.transport(t)
	got, digest, err := client.ReadRecords(context.Background())
	if err != nil {
		t.Fatalf("ReadRecords returned an error: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("read back %q, want %q", got, content)
	}
	if digest != "the-digest" {
		t.Errorf("digest = %q", digest)
	}

	if err := client.WriteRecords(context.Background(), content, digest); err != nil {
		t.Fatalf("WriteRecords returned an error: %v", err)
	}
	if string(written) != string(content) {
		t.Errorf("the agent received %q, want %q", written, content)
	}
}

func TestAnAgentThatIsNotThereIsUnreachableRatherThanUnknown(t *testing.T) {
	// The operator action differs. An unreachable server is a network or a
	// stopped agent; anything else would send them looking at the token.
	cfg := Config{
		ID: 1, Name: "dns4", Kind: KindAgent,
		Host:           "127.0.0.1",
		AgentPort:      1,
		HostKey:        "SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32)),
		TokenPath:      filepath.Join(t.TempDir(), "t.token"),
		ConnectTimeout: time.Second,
		CommandTimeout: time.Second,
	}
	if err := os.WriteFile(cfg.TokenPath, []byte(theToken), 0o600); err != nil {
		t.Fatalf("cannot write the token: %v", err)
	}

	client, err := NewAgent(cfg)
	if err != nil {
		t.Fatalf("NewAgent returned an error: %v", err)
	}
	defer client.Close()

	if _, err := client.Info(context.Background()); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("error = %v, want unreachable", err)
	}
}

func TestAnAgentConfigurationNeedsNoShellFields(t *testing.T) {
	// Nothing the panel holds becomes a command on an agent target, so
	// demanding tool paths and a reload command would be asking the operator
	// to fill in fields that reach nothing.
	cfg := Config{
		ID: 1, Name: "dns4", Kind: KindAgent,
		Host:      "dns4.example.net",
		AgentPort: 8443,
		TokenPath: "/var/lib/jbound/keys/server-1.token",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate refused an agent configuration: %v", err)
	}
}

func TestAnAgentHostCannotRewriteTheURL(t *testing.T) {
	// The host goes into a URL. A value carrying a slash, a userinfo marker or
	// a query would point the panel somewhere the record does not name.
	for _, host := range []string{
		"dns4.example.net/../evil",
		"dns4.example.net@attacker.example",
		"dns4.example.net?x=1",
		"dns4.example.net#fragment",
		"dns4 example.net",
	} {
		t.Run(host, func(t *testing.T) {
			cfg := Config{
				ID: 1, Kind: KindAgent, Host: host,
				AgentPort: 8443, TokenPath: "/var/lib/jbound/keys/server-1.token",
			}
			if err := cfg.Validate(); err == nil {
				t.Errorf("Validate accepted %q", host)
			}
		})
	}
}

func TestAnAgentTokenPathHasToBeAbsolute(t *testing.T) {
	// A relative path would resolve against whatever directory the panel
	// happens to run in, which is not somewhere a secret should be looked for.
	cfg := Config{
		ID: 1, Kind: KindAgent, Host: "dns4.example.net",
		AgentPort: 8443, TokenPath: "keys/server-1.token",
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate accepted a relative token path")
	}
}

func TestTheProbeStopsAtTheStepThatFailed(t *testing.T) {
	// Which step failed is what tells the operator where to look. A probe that
	// only said "it did not work" would send them through the whole path.
	harness := newAgentHarness(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case agentapi.PathInfo:
			answerJSON(w, agentapi.Info{
				Version:     agentapi.Version,
				RecordsPath: "/etc/unbound/local_records.conf",
			})
		default:
			w.WriteHeader(http.StatusInternalServerError)
			answerJSON(w, agentapi.Error{
				Class: agentapi.ClassInternal, Message: "permission denied"})
		}
	})

	client := harness.transport(t)
	err := client.Probe(context.Background())

	var probeErr *ProbeError
	if !errors.As(err, &probeErr) {
		t.Fatalf("error = %v, want a probe failure", err)
	}
	if probeErr.Step != StepRead {
		t.Errorf("step = %q, want %q", probeErr.Step, StepRead)
	}
}

func TestAnAgentThatNamesNoFileFailsTheProbe(t *testing.T) {
	// The panel takes the path from the agent, so an agent that reports none
	// is one the panel cannot manage. Finding that out while the operator is
	// adding the server is the whole point of a probe.
	harness := newAgentHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		answerJSON(w, agentapi.Info{Version: agentapi.Version})
	})

	client := harness.transport(t)
	if err := client.Probe(context.Background()); err == nil {
		t.Fatal("the probe passed an agent that manages no file")
	}
}

func TestScanningReportsTheFingerprintWithoutTrustingIt(t *testing.T) {
	// The operator has to see what is there before they approve it, which is
	// the same act ssh-keyscan supports on the other path.
	harness := newAgentHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		answerJSON(w, agentapi.Info{Version: agentapi.Version})
	})

	cfg := harness.config(t)
	cfg.HostKey = ""

	got, err := ScanAgentCertificate(context.Background(), cfg)
	if err != nil {
		t.Fatalf("ScanAgentCertificate returned an error: %v", err)
	}
	if got != harness.fingerprint {
		t.Errorf("reported %q, want %q", got, harness.fingerprint)
	}
	if !strings.HasPrefix(got, "SHA256:") {
		t.Errorf("the fingerprint is not in the format the operator reads: %q", got)
	}
}

func TestTheConnectionPoolBuildsWhicheverTransportTheRecordNames(t *testing.T) {
	// The layer above never learns which one it got, which is what the
	// interface was put there for.
	pool := NewPool(t.Context(), func() time.Duration { return time.Minute })
	defer pool.Close()

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "server-2.token")
	if err := os.WriteFile(tokenPath, []byte(theToken), 0o600); err != nil {
		t.Fatalf("cannot write the token: %v", err)
	}

	agent, err := pool.Get(Config{
		ID: 2, Name: "dns4", Kind: KindAgent, Host: "dns4.example.net",
		AgentPort: 8443, TokenPath: tokenPath,
		ConnectTimeout: time.Second, CommandTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("Get returned an error: %v", err)
	}
	if _, ok := agent.(*AgentTransport); !ok {
		t.Errorf("the pool built a %T for an agent record", agent)
	}

	ssh, err := pool.Get(validConfig())
	if err != nil {
		t.Fatalf("Get returned an error: %v", err)
	}
	if _, ok := ssh.(*SSHTransport); !ok {
		t.Errorf("the pool built a %T for an ssh record", ssh)
	}
}

func TestChangingTheTransportOfAServerReplacesItsConnection(t *testing.T) {
	// The pooled connection talks to sshd. Keeping it after the record says
	// agent would leave the panel managing the server the old way while the
	// interface says otherwise.
	pool := NewPool(t.Context(), func() time.Duration { return time.Minute })
	defer pool.Close()

	first, err := pool.Get(validConfig())
	if err != nil {
		t.Fatalf("Get returned an error: %v", err)
	}

	tokenPath := filepath.Join(t.TempDir(), "server-1.token")
	if err := os.WriteFile(tokenPath, []byte(theToken), 0o600); err != nil {
		t.Fatalf("cannot write the token: %v", err)
	}

	moved := validConfig()
	moved.Kind = KindAgent
	moved.AgentPort = 8443
	moved.TokenPath = tokenPath

	second, err := pool.Get(moved)
	if err != nil {
		t.Fatalf("Get returned an error: %v", err)
	}
	if first == second {
		t.Error("the pool kept the ssh connection for an agent record")
	}
	if _, ok := second.(*AgentTransport); !ok {
		t.Errorf("the pool returned a %T", second)
	}
}
