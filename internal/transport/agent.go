package transport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"jbound/internal/agentapi"
)

// AgentTransport speaks to one server through the agent running on it.
//
// The difference from the SSH path is what does not travel. No command text
// reaches the far end, so there is no login shell to escape and no sudoers
// rule holding the line. No path travels either: the agent reports which file
// it manages and the panel asks. What the panel sends is the name of a step
// and, for a write, the bytes.
//
// The connection is authenticated twice over, and the two prove different
// things. The bearer token proves the panel is who it says; the pinned
// certificate proves the server on the other end is the one an operator
// approved. Neither substitutes for the other.
type AgentTransport struct {
	cfg    Config
	client *http.Client
	base   string

	// mu serialises writes to this server, the same way it does on the SSH
	// path. The read before a write and the write itself have to be one
	// operation, otherwise two panel users could each read the same file and
	// overwrite each other.
	mu sync.Mutex

	// tokenOnce reads the token file at most once per transport. It is read
	// lazily rather than in the constructor so that building a transport for a
	// server whose token is not written yet does not fail.
	tokenOnce sync.Once
	token     string
	tokenErr  error
}

// NewAgent prepares a transport. No connection is made until it is needed.
func NewAgent(cfg Config) (*AgentTransport, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	transport := &http.Transport{
		// The panel talks to one server through this transport, so one idle
		// connection is all it can use and more would only sit open.
		MaxIdleConns:          1,
		MaxIdleConnsPerHost:   1,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   cfg.ConnectTimeout,
		ExpectContinueTimeout: time.Second,
		DialContext: (&net.Dialer{
			Timeout:   cfg.ConnectTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,

		// The certificate is pinned rather than chained to a public authority.
		// An agent on an internal resolver has no name a public issuer would
		// sign, and requiring one would push every operator into either a
		// private authority or turning verification off. Pinning gives the same
		// answer the SSH path gives: the operator approves a fingerprint once
		// and a change after that stops the connection.
		TLSClientConfig: &tls.Config{
			MinVersion:            tls.VersionTLS12,
			InsecureSkipVerify:    true, //nolint:gosec // VerifyPeerCertificate pins instead
			VerifyPeerCertificate: pinnedCertificate(cfg.HostKey),
		},
	}

	return &AgentTransport{
		cfg:    cfg,
		client: &http.Client{Transport: transport},
		base:   "https://" + net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.AgentPort)),
	}, nil
}

// CertFingerprint renders a certificate the way the panel stores and shows it.
//
// The format matches what OpenSSH prints for a host key, because an operator
// approving a fingerprint should not have to learn a second notation for the
// same act.
func CertFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// pinnedCertificate builds the verification callback for one approved
// fingerprint.
//
// An empty fingerprint is not "accept anything". It is a server no operator
// has approved yet, and the connection stops with the fingerprint it saw so
// they can approve it.
func pinnedCertificate(approved string) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("%w: the agent offered no certificate", ErrUnreachable)
		}
		observed := CertFingerprint(rawCerts[0])

		if strings.TrimSpace(approved) == "" {
			return &HostKeyError{Observed: observed, Err: ErrHostKeyUnknown}
		}

		// Constant time, for the same reason the token comparison is. The
		// fingerprint is public, but a comparison that leaks its prefix is a
		// free gift to anyone standing in the middle.
		if subtle.ConstantTimeCompare([]byte(observed), []byte(strings.TrimSpace(approved))) != 1 {
			return &HostKeyError{Observed: observed, Err: ErrHostKeyMismatch}
		}
		return nil
	}
}

// ScanAgentCertificate opens a TLS connection and reports the fingerprint the
// agent offers, without trusting it.
//
// It is the agent's answer to ssh-keyscan: the operator sees what is there and
// decides, rather than the panel deciding for them.
func ScanAgentCertificate(ctx context.Context, cfg Config) (string, error) {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: cfg.ConnectTimeout},
		Config: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, //nolint:gosec // the fingerprint is the point
		},
	}

	address := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.AgentPort))
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	defer conn.Close()

	state := conn.(*tls.Conn).ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "", fmt.Errorf("%w: the agent offered no certificate", ErrUnreachable)
	}
	return CertFingerprint(state.PeerCertificates[0].Raw), nil
}

// bearer returns the token, reading it from disk at most once.
func (t *AgentTransport) bearer() (string, error) {
	t.tokenOnce.Do(func() {
		material, err := os.ReadFile(t.cfg.TokenPath)
		if err != nil {
			// The path is named, the contents never are. A token in a log line
			// is a token an operator has to rotate.
			t.tokenErr = fmt.Errorf("%w: cannot read the agent token %s: %v",
				ErrAuth, t.cfg.TokenPath, err)
			return
		}
		t.token = strings.TrimSpace(string(material))
		if t.token == "" {
			t.tokenErr = fmt.Errorf("%w: the agent token %s is empty",
				ErrAuth, t.cfg.TokenPath)
		}
	})
	return t.token, t.tokenErr
}

// Info asks the agent what it manages.
func (t *AgentTransport) Info(ctx context.Context) (agentapi.Info, error) {
	var info agentapi.Info
	err := t.call(ctx, http.MethodGet, agentapi.PathInfo, nil, &info)
	return info, err
}

// ReadRecords fetches the records file.
func (t *AgentTransport) ReadRecords(ctx context.Context) ([]byte, string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	var answer agentapi.Records
	if err := t.call(ctx, http.MethodGet, agentapi.PathRecords, nil, &answer); err != nil {
		return nil, "", err
	}

	data, err := base64.StdEncoding.DecodeString(answer.Content)
	if err != nil {
		return nil, "", fmt.Errorf("%w: the agent sent content that is not base64: %v",
			ErrRemoteOutput, err)
	}
	return data, answer.SHA256, nil
}

// WriteRecords replaces the records file.
//
// The request names no file. Which file is written is the agent's own
// configuration, so a token in the wrong hands is not a way to write anywhere
// on the server.
func (t *AgentTransport) WriteRecords(ctx context.Context, data []byte, expectSHA256 string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	request := agentapi.WriteRequest{
		Content:      base64.StdEncoding.EncodeToString(data),
		ExpectSHA256: expectSHA256,
	}
	return t.call(ctx, http.MethodPut, agentapi.PathRecords, request, nil)
}

// EnsureInclude asks the agent to make the resolver read the records file.
func (t *AgentTransport) EnsureInclude(ctx context.Context) (string, error) {
	return t.step(ctx, agentapi.PathEnsureInclude)
}

// CheckConfig asks the resolver to validate its configuration.
func (t *AgentTransport) CheckConfig(ctx context.Context) (string, error) {
	return t.step(ctx, agentapi.PathCheckConf)
}

// Reload is the first rung of a reload.
func (t *AgentTransport) Reload(ctx context.Context) (string, error) {
	return t.step(ctx, agentapi.PathReload)
}

// ReloadFallback is the second rung.
func (t *AgentTransport) ReloadFallback(ctx context.Context) (string, error) {
	return t.step(ctx, agentapi.PathReloadBack)
}

// Restart is the third rung.
func (t *AgentTransport) Restart(ctx context.Context) (string, error) {
	return t.step(ctx, agentapi.PathRestart)
}

// step runs one operation and returns what it said.
func (t *AgentTransport) step(ctx context.Context, path string) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	var answer agentapi.CommandResult
	if err := t.call(ctx, http.MethodPost, path, nil, &answer); err != nil {
		return answer.Output, err
	}
	return strings.TrimSpace(answer.Output), nil
}

// ServiceStatus reports whether the resolver is running.
//
// A stopped resolver is an answer rather than a failure, the same as on the
// SSH path where a non zero exit from systemctl is-active is information.
func (t *AgentTransport) ServiceStatus(ctx context.Context) (bool, string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	var answer agentapi.StatusResult
	if err := t.call(ctx, http.MethodGet, agentapi.PathStatus, nil, &answer); err != nil {
		return false, answer.Detail, err
	}
	return answer.Active, strings.TrimSpace(answer.Detail), nil
}

// Probe walks every step the panel depends on and reports the first failure.
//
// The write step is the reason this exists. An agent whose configuration names
// an unwritable file fails here, while the operator is adding the server,
// rather than during the first record change.
func (t *AgentTransport) Probe(ctx context.Context) error {
	info, err := t.Info(ctx)
	if err != nil {
		return &ProbeError{Step: StepConnect, Err: err}
	}
	if strings.TrimSpace(info.RecordsPath) == "" {
		return &ProbeError{Step: StepConnect, Err: fmt.Errorf(
			"%w: the agent names no records file", ErrRemoteOutput)}
	}

	data, sum, err := t.ReadRecords(ctx)
	if err != nil {
		return &ProbeError{Step: StepRead, Err: err}
	}

	// Write the file back byte for byte. The whole path is exercised and the
	// content does not change.
	if err := t.WriteRecords(ctx, data, sum); err != nil {
		return &ProbeError{Step: StepWrite, Err: err}
	}

	_, after, err := t.ReadRecords(ctx)
	if err != nil {
		return &ProbeError{Step: StepWrite, Err: err}
	}
	if after != sum {
		return &ProbeError{Step: StepWrite, Err: fmt.Errorf(
			"the file changed during a write that should have preserved it")}
	}

	if info.Steps.CheckConf {
		if _, err := t.CheckConfig(ctx); err != nil {
			return &ProbeError{Step: StepCheckConf, Err: err}
		}
	}
	if _, _, err := t.ServiceStatus(ctx); err != nil {
		return &ProbeError{Step: StepStatus, Err: err}
	}
	return nil
}

// Close releases the idle connections.
//
// There is no long lived session to end. The HTTP transport keeps at most one
// idle connection and this hands it back.
func (t *AgentTransport) Close() error {
	t.client.CloseIdleConnections()
	return nil
}

// call performs one request and reads the answer.
//
// Everything the far end sends is bounded before it is read, because how much
// memory the panel sets aside is not a decision the agent gets to make.
func (t *AgentTransport) call(ctx context.Context, method, path string,
	request, answer any) error {

	token, err := t.bearer()
	if err != nil {
		return err
	}

	var body io.Reader
	if request != nil {
		encoded, err := json.Marshal(request)
		if err != nil {
			return fmt.Errorf("cannot encode the request: %w", err)
		}
		if len(encoded) > agentapi.MaxBodyBytes {
			return fmt.Errorf("%w: the file is %d bytes, over the %d byte limit",
				ErrCommandFailed, len(encoded), agentapi.MaxBodyBytes)
		}
		body = bytes.NewReader(encoded)
	}

	ctx, cancel := context.WithTimeout(ctx, t.cfg.CommandTimeout)
	defer cancel()

	// The path is a constant from the protocol package rather than anything a
	// record holds, so nothing an operator types decides which endpoint is
	// called.
	req, err := http.NewRequestWithContext(ctx, method, t.base+path, body)
	if err != nil {
		return fmt.Errorf("cannot build the request: %w", err)
	}
	req.Header.Set("Authorization", agentapi.AuthScheme+" "+token)
	req.Header.Set("Accept", "application/json")
	if request != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	response, err := t.client.Do(req)
	if err != nil {
		return dialFailure(err)
	}
	defer response.Body.Close()

	payload, err := io.ReadAll(io.LimitReader(response.Body, agentapi.MaxBodyBytes+1))
	if err != nil {
		return fmt.Errorf("%w: cannot read the answer: %v", ErrUnreachable, err)
	}
	if len(payload) > agentapi.MaxBodyBytes {
		return fmt.Errorf("%w: the agent sent more than %d bytes",
			ErrRemoteOutput, agentapi.MaxBodyBytes)
	}

	if response.StatusCode >= 300 {
		return agentFailure(response.StatusCode, payload)
	}
	if answer == nil {
		return nil
	}
	if err := json.Unmarshal(payload, answer); err != nil {
		return fmt.Errorf("%w: the agent sent an answer that will not parse: %v",
			ErrRemoteOutput, err)
	}
	return nil
}

// dialFailure turns a transport error into one of the panel's classes.
//
// The pinning callback runs inside the TLS handshake, so its error arrives
// wrapped in a url.Error and has to be unwrapped before the class survives.
func dialFailure(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		err = urlErr.Err
	}

	var hostKeyErr *HostKeyError
	if errors.As(err, &hostKeyErr) {
		return hostKeyErr
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return err
	}
	return fmt.Errorf("%w: %v", ErrUnreachable, err)
}

// agentFailure maps a refused answer onto the panel's failure classes.
//
// The class travels in the body rather than being inferred from the status
// code alone, so the panel does not have to read English to tell a refused
// configuration from a step nobody configured.
func agentFailure(status int, payload []byte) error {
	var failure agentapi.Error
	_ = json.Unmarshal(payload, &failure)

	detail := strings.TrimSpace(failure.Message)
	if detail == "" {
		detail = fmt.Sprintf("the agent answered %d", status)
	}

	switch {
	case status == http.StatusUnauthorized || failure.Class == agentapi.ClassAuth:
		// The message is dropped. It came from the far end and the panel shows
		// it, and an agent that echoed the token into it would put the token
		// on a page.
		return fmt.Errorf("%w: the agent refused the token", ErrAuth)
	case status == http.StatusConflict || failure.Class == agentapi.ClassConflict:
		return fmt.Errorf("%w: %s", ErrConflict, detail)
	case status == agentapi.StatusStepSkipped || failure.Class == agentapi.ClassSkipped:
		return ErrStepSkipped
	case status == http.StatusUnprocessableEntity || failure.Class == agentapi.ClassCommand:
		return &CommandError{Command: "agent step", ExitCode: 1, Stderr: detail}
	default:
		return fmt.Errorf("%w: %s", ErrCommandFailed, detail)
	}
}
