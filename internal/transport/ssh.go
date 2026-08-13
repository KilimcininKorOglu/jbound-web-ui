package transport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

// errHostKeyCaptured stops a dial once the host key is known. ScanHostKey
// wants the key and nothing else.
var errHostKeyCaptured = errors.New("host key captured")

// base64Line is what a clean read looks like.
//
// The pattern carries no (?m) flag on purpose. Without it the anchors bind to
// the whole output rather than to each line, which is what makes a second line
// of shell noise fail the check instead of slipping past it.
var base64Line = regexp.MustCompile(`^[A-Za-z0-9+/=]*$`)

// hexDigest matches the digest field of sha256sum output.
var hexDigest = regexp.MustCompile(`^[0-9a-f]+$`)

// SSHTransport speaks to one server over SSH.
//
// File transfer runs through exec rather than SFTP. SFTP cannot invoke sudo,
// so using it would mean loosening /etc/unbound to group writable, and an
// include of *.conf in that directory turns a writable directory into a
// configuration injection path.
type SSHTransport struct {
	cfg Config

	// mu guards the client and serialises writes to this server. The read
	// before a write and the write itself have to be one operation, otherwise
	// two panel users could each read the same file and overwrite each other.
	mu     sync.Mutex
	client *ssh.Client
}

// NewSSH prepares a transport. No connection is made until it is needed.
func NewSSH(cfg Config) (*SSHTransport, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &SSHTransport{cfg: cfg}, nil
}

// dial opens an SSH connection with the given host key policy.
func dial(cfg Config, callback ssh.HostKeyCallback) (*ssh.Client, error) {
	material, err := os.ReadFile(cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read the private key %s: %w", cfg.KeyPath, err)
	}

	signer, err := ssh.ParsePrivateKey(material)
	if err != nil {
		return nil, fmt.Errorf("cannot parse the private key %s: %w", cfg.KeyPath, err)
	}

	clientConfig := &ssh.ClientConfig{
		User: cfg.User,
		// Public key only. Password authentication would mean the panel holds
		// a password for every managed server.
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback:   callback,
		HostKeyAlgorithms: hostKeyAlgorithms(cfg.HostKey),
		Timeout:           cfg.ConnectTimeout,
	}

	address := net.JoinHostPort(cfg.Host, fmt.Sprint(cfg.Port))
	client, err := ssh.Dial("tcp", address, clientConfig)
	if err != nil {
		return nil, classifyDialError(address, err)
	}
	return client, nil
}

// classifyDialError turns a dial failure into one of the failure classes.
func classifyDialError(address string, err error) error {
	// A host key failure travels as is. It already carries the fingerprints
	// the operator needs.
	if hostKeyErr, ok := errors.AsType[*HostKeyError](err); ok {
		return hostKeyErr
	}
	if errors.Is(err, errHostKeyCaptured) {
		return err
	}

	// The library reports an authentication failure as a plain message, so
	// there is nothing more precise to match on.
	if strings.Contains(err.Error(), "unable to authenticate") ||
		strings.Contains(err.Error(), "no supported methods remain") {
		return fmt.Errorf("%w: %s: %v", ErrAuth, address, err)
	}
	return fmt.Errorf("%w: %s: %v", ErrUnreachable, address, err)
}

// connect returns a live client, opening one if needed.
//
// reused reports whether the client was already open, which is what tells the
// caller a failure might be a stale connection rather than a dead server.
//
// The caller holds the mutex.
func (t *SSHTransport) connect() (client *ssh.Client, reused bool, err error) {
	if t.client != nil {
		return t.client, true, nil
	}

	client, err = dial(t.cfg, hostKeyCallback(t.cfg.HostKey))
	if err != nil {
		return nil, false, err
	}
	t.client = client
	return client, false, nil
}

// newSession opens a session, reconnecting once if the pooled connection died.
//
// A connection dropped by an idle timeout or a firewall only shows itself when
// a session is opened on it. Failing there would turn every quiet period into
// one failed operation, so the retry happens before any command has run. A
// failure later, once bytes are moving, is not retried: the panel cannot know
// how far the remote side got.
func (t *SSHTransport) newSession() (*ssh.Session, error) {
	client, reused, err := t.connect()
	if err != nil {
		return nil, err
	}

	session, err := client.NewSession()
	if err == nil {
		return session, nil
	}
	if !reused {
		t.dropConnection()
		return nil, fmt.Errorf("%w: cannot open a session: %v", ErrUnreachable, err)
	}

	t.dropConnection()
	client, _, err = t.connect()
	if err != nil {
		return nil, err
	}

	session, err = client.NewSession()
	if err != nil {
		t.dropConnection()
		return nil, fmt.Errorf("%w: cannot open a session: %v", ErrUnreachable, err)
	}
	return session, nil
}

// dropConnection closes a client that failed mid operation.
//
// The caller holds the mutex. The next call dials again, which is what turns a
// resolver restart or a network blip into one failed request rather than a
// permanently dead server entry.
func (t *SSHTransport) dropConnection() {
	if t.client != nil {
		t.client.Close()
		t.client = nil
	}
}

// run executes one remote command.
//
// Each command gets its own session, because an SSH session runs exactly one
// command. The sessions share the client connection.
func (t *SSHTransport) run(ctx context.Context, command string,
	stdin io.Reader) (stdout, stderr string, err error) {

	session, err := t.newSession()
	if err != nil {
		return "", "", err
	}
	defer session.Close()

	var outBuf, errBuf bytes.Buffer
	session.Stdout = &outBuf
	session.Stderr = &errBuf
	if stdin != nil {
		session.Stdin = stdin
	}

	done := make(chan error, 1)
	go func() { done <- session.Run(command) }()

	select {
	case <-ctx.Done():
		// Closing the session unblocks Run. The remote command may still be
		// running, which is why a write is built so that an interrupted
		// transfer leaves the target file untouched.
		session.Close()
		<-done
		return outBuf.String(), errBuf.String(),
			fmt.Errorf("%w: %v", ErrUnreachable, ctx.Err())
	case runErr := <-done:
		if runErr != nil {
			if exitErr, ok := errors.AsType[*ssh.ExitError](runErr); ok {
				return outBuf.String(), errBuf.String(), &CommandError{
					Command:  command,
					ExitCode: exitErr.ExitStatus(),
					Stderr:   errBuf.String(),
				}
			}
			t.dropConnection()
			return outBuf.String(), errBuf.String(),
				fmt.Errorf("%w: %v", ErrUnreachable, runErr)
		}
	}
	return outBuf.String(), errBuf.String(), nil
}

// ReadHostEntries fetches the host entries file.
//
// Reading needs no sudo. The file is world readable, and the panel only writes
// through sudo.
func (t *SSHTransport) ReadHostEntries(ctx context.Context) ([]byte, string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	return t.readLocked(ctx)
}

// readLocked performs the read while the caller holds the mutex.
//
// base64 reads the file itself rather than taking it through a pipe from cat.
// A shell pipeline reports the status of its last command, so a cat that could
// not open the file would exit unnoticed and the read would return an empty
// file. The panel would then show no records, and the next write would replace
// the real file with whatever the operator typed into an apparently empty one.
func (t *SSHTransport) readLocked(ctx context.Context) ([]byte, string, error) {
	command := fmt.Sprintf("%s -w0 %s", t.cfg.Base64Path, t.cfg.HostEntriesPath)

	stdout, _, err := t.run(ctx, command, nil)
	if err != nil {
		return nil, "", err
	}

	encoded, err := cleanBase64(stdout)
	if err != nil {
		return nil, "", err
	}

	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, "", fmt.Errorf("%w: the remote output is not valid base64: %v",
			ErrRemoteOutput, err)
	}
	return data, digest(data), nil
}

// cleanBase64 validates the output of the read command.
//
// Two conditions, and both are needed. base64 -w0 never wraps, so a second
// line is always shell noise from a profile file. Checking the pattern alone
// would let that noise through, because a line based match would find the
// base64 line and call the output valid.
func cleanBase64(output string) (string, error) {
	const advice = "check the profile files of the ssh account"

	trimmed := strings.TrimSpace(output)
	if strings.ContainsAny(trimmed, "\n\r") {
		return "", fmt.Errorf("%w: the output spans several lines, %s",
			ErrRemoteOutput, advice)
	}
	if !base64Line.MatchString(trimmed) {
		return "", fmt.Errorf("%w: the output is not base64, %s",
			ErrRemoteOutput, advice)
	}
	return trimmed, nil
}

// digest returns the SHA-256 of a file, which is how the panel tells whether
// the remote copy still matches what it last read.
func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// WriteHostEntries replaces the host entries file.
func (t *SSHTransport) WriteHostEntries(ctx context.Context, data []byte,
	expectSHA256 string) error {

	t.mu.Lock()
	defer t.mu.Unlock()

	// Read again immediately before writing. The panel read this file over the
	// network, possibly minutes ago, and another operator may have changed it
	// since.
	_, current, err := t.readLocked(ctx)
	if err != nil {
		return err
	}
	if expectSHA256 != "" && current != expectSHA256 {
		return fmt.Errorf("%w: expected %s, found %s",
			ErrConflict, expectSHA256[:12], current[:12])
	}
	return t.writeLocked(ctx, data)
}

// writeLocked replaces the file in two steps.
//
// The content goes to a temporary file next to the target, its digest is
// checked, and only then is it moved into place. Joining the two with && would
// not be enough: a shell pipeline reports the status of tee, and tee is
// perfectly happy writing a stream that was cut short. A connection lost
// halfway through would leave a short file that tee called a success, and the
// move would then truncate the real one.
//
// A failed check leaves the temporary file behind. It has a fixed name in the
// same directory and the next write overwrites it, so nothing accumulates.
func (t *SSHTransport) writeLocked(ctx context.Context, data []byte) error {
	transfer := fmt.Sprintf("%s -d | sudo %s %s > /dev/null; %s %s",
		t.cfg.Base64Path, t.cfg.TeePath, t.cfg.tempPath(),
		t.cfg.Sha256Path, t.cfg.tempPath())

	encoded := base64.StdEncoding.EncodeToString(data)
	stdout, _, err := t.run(ctx, transfer, strings.NewReader(encoded))
	if err != nil {
		return err
	}

	written, err := parseDigest(stdout)
	if err != nil {
		return err
	}
	if written != digest(data) {
		return fmt.Errorf(
			"%w: the transfer was incomplete, the target file was left untouched",
			ErrRemoteOutput)
	}

	// Same directory as the target, so the move is atomic. Either the old file
	// or the new one is in place, never a half written one.
	move := fmt.Sprintf("sudo %s %s %s",
		t.cfg.MvPath, t.cfg.tempPath(), t.cfg.HostEntriesPath)

	if _, _, err := t.run(ctx, move, nil); err != nil {
		return err
	}
	return nil
}

// parseDigest reads the first field of sha256sum output, which is the hex
// digest followed by the file name.
func parseDigest(output string) (string, error) {
	fields := strings.Fields(strings.TrimSpace(output))
	if len(fields) == 0 {
		return "", fmt.Errorf("%w: the digest command produced no output", ErrRemoteOutput)
	}

	sum := fields[0]
	if len(sum) != 64 || !hexDigest.MatchString(sum) {
		return "", fmt.Errorf("%w: %q is not a sha256 digest", ErrRemoteOutput, sum)
	}
	return sum, nil
}

// Reload asks the resolver to re-read its configuration.
func (t *SSHTransport) Reload(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	stdout, stderr, err := t.run(ctx, t.cfg.ReloadCmd, nil)
	if err != nil {
		// The reference project reports success whatever the command did. A
		// reload that failed silently means the panel shows records the
		// resolver is not serving.
		return strings.TrimSpace(stdout + stderr), err
	}
	return strings.TrimSpace(stdout + stderr), nil
}

// ServiceStatus reports whether the resolver is running.
//
// A non zero exit is the answer rather than a failure here. systemctl
// is-active exits 3 for an inactive unit, and that is information, not a
// broken connection.
func (t *SSHTransport) ServiceStatus(ctx context.Context) (bool, string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	stdout, stderr, err := t.run(ctx, t.cfg.StatusCmd, nil)
	detail := strings.TrimSpace(stdout)
	if detail == "" {
		detail = strings.TrimSpace(stderr)
	}

	if err != nil {
		if _, ok := errors.AsType[*CommandError](err); ok {
			return false, detail, nil
		}
		return false, detail, err
	}
	return true, detail, nil
}

// Probe walks every step the panel depends on and reports the first failure.
//
// The write step is the reason this exists. A sudoers rule that names a
// different path fails there, while the operator is adding the server, rather
// than during the first record change.
func (t *SSHTransport) Probe(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if _, _, err := t.connect(); err != nil {
		return &ProbeError{Step: StepConnect, Err: err}
	}

	data, sum, err := t.readLocked(ctx)
	if err != nil {
		return &ProbeError{Step: StepRead, Err: err}
	}

	// Write the file back byte for byte. The whole path is exercised and the
	// content does not change.
	if err := t.writeLocked(ctx, data); err != nil {
		return &ProbeError{Step: StepWrite, Err: err}
	}

	// Read once more and compare. A write that changed the file would mean the
	// transfer path corrupts content, which is worth knowing now.
	_, after, err := t.readLocked(ctx)
	if err != nil {
		return &ProbeError{Step: StepWrite, Err: err}
	}
	if after != sum {
		return &ProbeError{Step: StepWrite, Err: fmt.Errorf(
			"the file changed during a write that should have preserved it")}
	}

	if _, _, err := t.run(ctx, t.cfg.StatusCmd, nil); err != nil {
		if _, ok := errors.AsType[*CommandError](err); !ok {
			return &ProbeError{Step: StepStatus, Err: err}
		}
		// A non zero exit means the resolver is not running, which the probe
		// reports as reachable. The step is about whether the command runs.
	}
	return nil
}

// Close releases the connection.
func (t *SSHTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.client == nil {
		return nil
	}
	err := t.client.Close()
	t.client = nil
	if err != nil {
		return fmt.Errorf("cannot close the connection to %s: %w", t.cfg.Host, err)
	}
	return nil
}
