//go:build integration

// Exercises the SSH transport against the development targets.
//
// The protocol is the part of this package that cannot be proven with a fake:
// whether sudo accepts the tee and mv rules, whether the remote shell keeps
// its output clean, and whether a reload really reloads. All of that needs a
// real server.
//
// Run it with: make dev-itest

package transport

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	testTarget  = "dns1"
	testUser    = "dnsops"
	testKeyPath = "/var/lib/unbound-web/keys/dev_ed25519"
)

func devConfig(t *testing.T) Config {
	t.Helper()

	if _, err := os.Stat(testKeyPath); err != nil {
		t.Fatalf("the development key is missing, run the tests inside the stack: %v", err)
	}

	return Config{
		ID:              1,
		Name:            testTarget,
		Host:            testTarget,
		Port:            22,
		User:            testUser,
		KeyPath:         testKeyPath,
		HostEntriesPath: "/etc/unbound/host_entries.conf",
		ReloadCmd:       "sudo /usr/sbin/service unbound reload",
		// The containers carry no systemd, so the init script answers instead.
		// Production uses systemctl, and both are configured per server.
		StatusCmd:      "/usr/sbin/service unbound status",
		Sha256Path:     "/usr/bin/sha256sum",
		Base64Path:     "/usr/bin/base64",
		TeePath:        "/usr/bin/tee",
		MvPath:         "/bin/mv",
		ConnectTimeout: 10 * time.Second,
		CommandTimeout: 30 * time.Second,
	}
}

// approvedConfig returns a configuration whose host key is already approved.
func approvedConfig(t *testing.T) Config {
	t.Helper()

	cfg := devConfig(t)
	_, authorized, err := ScanHostKey(cfg)
	if err != nil {
		t.Fatalf("cannot read the host key of %s: %v", testTarget, err)
	}
	cfg.HostKey = authorized
	return cfg
}

func newTransport(t *testing.T) *SSHTransport {
	t.Helper()

	transport, err := NewSSH(approvedConfig(t))
	if err != nil {
		t.Fatalf("cannot build the transport: %v", err)
	}
	t.Cleanup(func() { transport.Close() })
	return transport
}

// preserveHostEntries restores the file after a test changed it.
func preserveHostEntries(t *testing.T, transport *SSHTransport) {
	t.Helper()
	ctx := context.Background()

	original, sum, err := transport.ReadHostEntries(ctx)
	if err != nil {
		t.Fatalf("cannot read the host entries file: %v", err)
	}

	t.Cleanup(func() {
		_, current, err := transport.ReadHostEntries(context.Background())
		if err != nil {
			t.Errorf("cannot read the file back for the restore: %v", err)
			return
		}
		if current == sum {
			return
		}
		if err := transport.WriteHostEntries(context.Background(), original, current); err != nil {
			t.Errorf("cannot restore the host entries file: %v", err)
		}
	})
}

func TestScanHostKeyReportsAFingerprint(t *testing.T) {
	fingerprint, authorized, err := ScanHostKey(devConfig(t))
	if err != nil {
		t.Fatalf("ScanHostKey returned an error: %v", err)
	}

	if !strings.HasPrefix(fingerprint, "SHA256:") {
		t.Errorf("fingerprint = %q", fingerprint)
	}
	if _, err := ParseHostKey(authorized); err != nil {
		t.Errorf("the returned line is not a usable host key: %v", err)
	}
}

func TestScanPrefersTheKeyTheOperatorIsToldToCompare(t *testing.T) {
	// The panel asks the operator to run `ssh-keyscan -t ed25519`. A server
	// holds one key per algorithm, so the scan has to land on the same one or
	// the two fingerprints will never match.
	_, authorized, err := ScanHostKey(devConfig(t))
	if err != nil {
		t.Fatalf("ScanHostKey returned an error: %v", err)
	}

	key, err := ParseHostKey(authorized)
	if err != nil {
		t.Fatalf("the returned line is not a usable host key: %v", err)
	}
	if key.Type() != ssh.KeyAlgoED25519 {
		t.Errorf("key type = %s, want %s", key.Type(), ssh.KeyAlgoED25519)
	}
}

func TestAnApprovedKeyDecidesWhichOneTheServerOffers(t *testing.T) {
	// Approving a key that is not the preferred one must keep working. Without
	// narrowing the handshake, the server would answer with its ed25519 key and
	// the connection would read as a mismatch, which is what an impostor looks
	// like.
	cfg := devConfig(t)

	scan := cfg
	scan.HostKey = ""
	// Ask for the ecdsa key on its own to learn what it is.
	scanned, err := scanWith(scan, ssh.KeyAlgoECDSA256)
	if err != nil {
		t.Fatalf("cannot read the ecdsa host key: %v", err)
	}
	cfg.HostKey = scanned

	transport, err := NewSSH(cfg)
	if err != nil {
		t.Fatalf("cannot build the transport: %v", err)
	}
	defer transport.Close()

	if _, _, err := transport.ReadHostEntries(context.Background()); err != nil {
		t.Fatalf("the approved ecdsa key was refused: %v", err)
	}
}

// scanWith reads one host key of a chosen algorithm.
func scanWith(cfg Config, algorithm string) (string, error) {
	previous := preferredHostKeyAlgorithms
	preferredHostKeyAlgorithms = []string{algorithm}
	defer func() { preferredHostKeyAlgorithms = previous }()

	_, authorized, err := ScanHostKey(cfg)
	return authorized, err
}

func TestConnectingWithoutAnApprovedHostKeyIsRefused(t *testing.T) {
	// There is no first use exception, so a server nobody approved cannot be
	// reached at all.
	transport, err := NewSSH(devConfig(t))
	if err != nil {
		t.Fatalf("cannot build the transport: %v", err)
	}
	defer transport.Close()

	_, _, err = transport.ReadHostEntries(context.Background())
	if !errors.Is(err, ErrHostKeyUnknown) {
		t.Fatalf("got %v, want ErrHostKeyUnknown", err)
	}

	hostKeyErr, ok := errors.AsType[*HostKeyError](err)
	if !ok || hostKeyErr.Observed == "" {
		t.Error("the error carries no fingerprint for the operator to approve")
	}
}

func TestConnectingWithTheWrongHostKeyIsRefused(t *testing.T) {
	cfg := devConfig(t)
	// A syntactically valid key that belongs to another server.
	cfg.HostKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB2hRTPYzKS4Aa8s8bDCLtxUCVBGJVh3vP6mMnA0FfSk"

	transport, err := NewSSH(cfg)
	if err != nil {
		t.Fatalf("cannot build the transport: %v", err)
	}
	defer transport.Close()

	_, _, err = transport.ReadHostEntries(context.Background())
	if !errors.Is(err, ErrHostKeyMismatch) {
		t.Fatalf("got %v, want ErrHostKeyMismatch", err)
	}
}

func TestAuthenticationFailureIsItsOwnClass(t *testing.T) {
	// A refused key needs a key. Reporting it as unreachable would send the
	// operator to check the network instead.
	cfg := approvedConfig(t)
	cfg.User = "nobody-here"

	transport, err := NewSSH(cfg)
	if err != nil {
		t.Fatalf("cannot build the transport: %v", err)
	}
	defer transport.Close()

	_, _, err = transport.ReadHostEntries(context.Background())
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
}

func TestUnreachableServerIsItsOwnClass(t *testing.T) {
	cfg := approvedConfig(t)
	cfg.Port = 2

	transport, err := NewSSH(cfg)
	if err != nil {
		t.Fatalf("cannot build the transport: %v", err)
	}
	defer transport.Close()

	_, _, err = transport.ReadHostEntries(context.Background())
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("got %v, want ErrUnreachable", err)
	}
}

func TestReadReturnsTheSeededRecords(t *testing.T) {
	transport := newTransport(t)

	data, sum, err := transport.ReadHostEntries(context.Background())
	if err != nil {
		t.Fatalf("ReadHostEntries returned an error: %v", err)
	}
	if !strings.Contains(string(data), "local-data") {
		t.Errorf("the file carries no records:\n%s", data)
	}
	if sum != digest(data) {
		t.Error("the digest does not describe the returned bytes")
	}
}

func TestWriteRoundTripsThroughTheTransferProtocol(t *testing.T) {
	transport := newTransport(t)
	preserveHostEntries(t, transport)
	ctx := context.Background()

	original, sum, err := transport.ReadHostEntries(ctx)
	if err != nil {
		t.Fatalf("ReadHostEntries returned an error: %v", err)
	}

	// Content that would not survive a naive transfer: a quote, a backslash,
	// a byte above ASCII and a trailing newline.
	updated := append([]byte(nil), original...)
	updated = append(updated,
		[]byte("local-data: \"round.trip.test. A 10.9.9.9\"\n# tab\tquote\" backslash\\ ü\n")...)

	if err := transport.WriteHostEntries(ctx, updated, sum); err != nil {
		t.Fatalf("WriteHostEntries returned an error: %v", err)
	}

	readBack, _, err := transport.ReadHostEntries(ctx)
	if err != nil {
		t.Fatalf("cannot read the file back: %v", err)
	}
	if string(readBack) != string(updated) {
		t.Errorf("the content changed in transit:\nwrote %q\nread  %q", updated, readBack)
	}
}

func TestWriteRefusesAStaleDigest(t *testing.T) {
	// The read and the write now span a network, so another operator may have
	// written in between. Overwriting them would lose their change without a
	// trace.
	transport := newTransport(t)
	preserveHostEntries(t, transport)
	ctx := context.Background()

	original, sum, err := transport.ReadHostEntries(ctx)
	if err != nil {
		t.Fatalf("ReadHostEntries returned an error: %v", err)
	}

	// Somebody else writes first.
	theirs := append(append([]byte(nil), original...),
		[]byte("local-data: \"theirs.test. A 10.8.8.8\"\n")...)
	if err := transport.WriteHostEntries(ctx, theirs, sum); err != nil {
		t.Fatalf("the first write failed: %v", err)
	}

	// The stale caller still holds the digest from before.
	mine := append(append([]byte(nil), original...),
		[]byte("local-data: \"mine.test. A 10.7.7.7\"\n")...)
	err = transport.WriteHostEntries(ctx, mine, sum)

	if !errors.Is(err, ErrConflict) {
		t.Fatalf("got %v, want ErrConflict", err)
	}

	current, _, readErr := transport.ReadHostEntries(ctx)
	if readErr != nil {
		t.Fatalf("cannot read the file back: %v", readErr)
	}
	if !strings.Contains(string(current), "theirs.test") {
		t.Error("the refused write still changed the file")
	}
}

func TestWriteAcceptsAnEmptyExpectation(t *testing.T) {
	// An empty digest means the caller has no expectation, which is the case
	// when a server is being seeded for the first time.
	transport := newTransport(t)
	preserveHostEntries(t, transport)
	ctx := context.Background()

	original, _, err := transport.ReadHostEntries(ctx)
	if err != nil {
		t.Fatalf("ReadHostEntries returned an error: %v", err)
	}

	if err := transport.WriteHostEntries(ctx, original, ""); err != nil {
		t.Fatalf("WriteHostEntries returned an error: %v", err)
	}
}

func TestReloadRunsTheConfiguredCommand(t *testing.T) {
	transport := newTransport(t)

	if _, err := transport.Reload(context.Background()); err != nil {
		t.Fatalf("Reload returned an error: %v", err)
	}
}

func TestReloadReportsAFailingCommand(t *testing.T) {
	// A reload that reported success whatever the command did would leave the
	// panel showing records the resolver is not serving.
	cfg := approvedConfig(t)
	cfg.ReloadCmd = "/bin/false"

	transport, err := NewSSH(cfg)
	if err != nil {
		t.Fatalf("cannot build the transport: %v", err)
	}
	defer transport.Close()

	if _, err := transport.Reload(context.Background()); !errors.Is(err, ErrCommandFailed) {
		t.Fatalf("got %v, want ErrCommandFailed", err)
	}
}

func TestServiceStatusReportsARunningResolver(t *testing.T) {
	transport := newTransport(t)

	active, detail, err := transport.ServiceStatus(context.Background())
	if err != nil {
		t.Fatalf("ServiceStatus returned an error: %v", err)
	}
	if !active {
		t.Errorf("the resolver is reported as down: %s", detail)
	}
}

func TestServiceStatusTreatsANonZeroExitAsAnAnswer(t *testing.T) {
	// systemctl is-active exits 3 for an inactive unit. That is information,
	// not a broken connection.
	cfg := approvedConfig(t)
	cfg.StatusCmd = "/bin/false"

	transport, err := NewSSH(cfg)
	if err != nil {
		t.Fatalf("cannot build the transport: %v", err)
	}
	defer transport.Close()

	active, _, err := transport.ServiceStatus(context.Background())
	if err != nil {
		t.Fatalf("ServiceStatus returned an error: %v", err)
	}
	if active {
		t.Error("a failing status command was read as a running resolver")
	}
}

func TestProbePassesAgainstAWorkingTarget(t *testing.T) {
	transport := newTransport(t)
	preserveHostEntries(t, transport)

	if err := transport.Probe(context.Background()); err != nil {
		t.Fatalf("Probe returned an error: %v", err)
	}
}

func TestProbeReportsTheWriteStepWhenSudoRefuses(t *testing.T) {
	// This is the step the probe exists for. A sudoers rule that names a
	// different path fails here, while the operator is adding the server,
	// rather than during the first record change.
	// /bin/tee would not do: /bin is a symlink to /usr/bin on Debian, so sudo
	// resolves it to the allowed path. This one is genuinely unlisted.
	cfg := approvedConfig(t)
	cfg.TeePath = "/usr/local/bin/tee"

	transport, err := NewSSH(cfg)
	if err != nil {
		t.Fatalf("cannot build the transport: %v", err)
	}
	defer transport.Close()

	err = transport.Probe(context.Background())
	if err == nil {
		t.Fatal("Probe passed with a tee path the sudoers rules do not allow")
	}

	probeErr, ok := errors.AsType[*ProbeError](err)
	if !ok {
		t.Fatalf("got %v, want a ProbeError", err)
	}
	if probeErr.Step != StepWrite {
		t.Errorf("step = %q, want %q", probeErr.Step, StepWrite)
	}
}

func TestProbeReportsTheReadStepWhenTheFileIsMissing(t *testing.T) {
	cfg := approvedConfig(t)
	cfg.HostEntriesPath = "/etc/unbound/no_such_file.conf"

	transport, err := NewSSH(cfg)
	if err != nil {
		t.Fatalf("cannot build the transport: %v", err)
	}
	defer transport.Close()

	err = transport.Probe(context.Background())
	probeErr, ok := errors.AsType[*ProbeError](err)
	if !ok {
		t.Fatalf("got %v, want a ProbeError", err)
	}
	if probeErr.Step != StepRead {
		t.Errorf("step = %q, want %q", probeErr.Step, StepRead)
	}
}

func TestProbeReportsTheConnectStepForAnUnapprovedServer(t *testing.T) {
	transport, err := NewSSH(devConfig(t))
	if err != nil {
		t.Fatalf("cannot build the transport: %v", err)
	}
	defer transport.Close()

	err = transport.Probe(context.Background())
	probeErr, ok := errors.AsType[*ProbeError](err)
	if !ok {
		t.Fatalf("got %v, want a ProbeError", err)
	}
	if probeErr.Step != StepConnect {
		t.Errorf("step = %q, want %q", probeErr.Step, StepConnect)
	}
}

func TestContextCancellationStopsACommand(t *testing.T) {
	transport := newTransport(t)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// Warm the connection first, so the timeout lands on the command rather
	// than on the handshake.
	if _, _, err := transport.ReadHostEntries(context.Background()); err != nil {
		t.Fatalf("cannot warm the connection: %v", err)
	}

	started := time.Now()
	_, _, err := transport.run(ctx, "sleep 30", nil)
	if err == nil {
		t.Fatal("a cancelled command reported success")
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Errorf("the command ran for %s after the context ended", elapsed)
	}
}

func TestPoolReusesOneConnectionPerServer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool := NewPool(ctx, time.Minute)
	defer pool.Close()

	cfg := approvedConfig(t)

	first, err := pool.Get(cfg)
	if err != nil {
		t.Fatalf("Get returned an error: %v", err)
	}
	second, err := pool.Get(cfg)
	if err != nil {
		t.Fatalf("Get returned an error: %v", err)
	}
	if first != second {
		t.Error("the pool opened a second transport for the same server")
	}

	if _, _, err := first.ReadHostEntries(ctx); err != nil {
		t.Fatalf("the pooled transport does not work: %v", err)
	}
}

func TestPoolReplacesAConnectionWhenTheRecordChanges(t *testing.T) {
	// Reusing the old connection would send the next command to the previous
	// address.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool := NewPool(ctx, time.Minute)
	defer pool.Close()

	cfg := approvedConfig(t)
	first, err := pool.Get(cfg)
	if err != nil {
		t.Fatalf("Get returned an error: %v", err)
	}

	cfg.Host = "dns2"
	second, err := pool.Get(cfg)
	if err != nil {
		t.Fatalf("Get returned an error: %v", err)
	}
	if first == second {
		t.Error("the pool kept the connection to the previous address")
	}
}

func TestKeepaliveKeepsAConnectionUsable(t *testing.T) {
	transport := newTransport(t)
	ctx := context.Background()

	if _, _, err := transport.ReadHostEntries(ctx); err != nil {
		t.Fatalf("cannot open the connection: %v", err)
	}
	if err := transport.keepalive(); err != nil {
		t.Fatalf("keepalive returned an error: %v", err)
	}
	if _, _, err := transport.ReadHostEntries(ctx); err != nil {
		t.Fatalf("the connection stopped working after a keepalive: %v", err)
	}
}

func TestKeepaliveIsQuietOnAnIdleTransport(t *testing.T) {
	// Dialling a connection nobody asked for would turn an unreachable server
	// into a stream of log noise.
	transport := newTransport(t)

	if err := transport.keepalive(); err != nil {
		t.Fatalf("keepalive dialled an idle transport: %v", err)
	}
}

func TestDroppedConnectionIsReopened(t *testing.T) {
	transport := newTransport(t)
	ctx := context.Background()

	if _, _, err := transport.ReadHostEntries(ctx); err != nil {
		t.Fatalf("cannot open the connection: %v", err)
	}

	// Break the connection the way a resolver restart or a firewall would.
	transport.mu.Lock()
	client := transport.client
	transport.mu.Unlock()
	if client == nil {
		t.Fatal("the transport holds no connection")
	}
	client.Close()

	if _, _, err := transport.ReadHostEntries(ctx); err != nil {
		t.Fatalf("the transport did not reconnect: %v", err)
	}
}

// Guards the assumption the whole transfer protocol rests on: the target
// account gets a clean shell, so nothing but base64 comes back.
func TestRemoteShellProducesNoExtraOutput(t *testing.T) {
	transport := newTransport(t)

	stdout, _, err := transport.run(context.Background(), "/usr/bin/base64 -w0 /dev/null", nil)
	if err != nil {
		t.Fatalf("the command failed: %v", err)
	}
	if strings.TrimSpace(stdout) != "" {
		t.Errorf("the shell added output of its own: %q", stdout)
	}
}

var _ Transport = (*SSHTransport)(nil)
var _ ssh.PublicKey = ssh.PublicKey(nil)
