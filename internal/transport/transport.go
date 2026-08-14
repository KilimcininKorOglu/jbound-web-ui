// Package transport reaches the managed DNS servers.
//
// Version one speaks SSH. An agent transport is planned, so everything above
// this package works against the interface rather than against SSH, and the
// layer that manages records never learns how the bytes travel.
package transport

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Transport is one managed server.
type Transport interface {
	// ReadHostEntries returns the host entries file and its SHA-256 digest.
	ReadHostEntries(ctx context.Context) (data []byte, sha256 string, err error)

	// WriteHostEntries replaces the host entries file.
	//
	// expectSHA256 is the digest the caller last saw. The write is refused
	// when the remote file no longer matches it, because the read and the
	// write now span a network and another operator may have written in
	// between.
	WriteHostEntries(ctx context.Context, data []byte, expectSHA256 string) error

	// Reload asks the resolver to re-read its configuration.
	Reload(ctx context.Context) (output string, err error)

	// ServiceStatus reports whether the resolver is running.
	ServiceStatus(ctx context.Context) (active bool, detail string, err error)

	// Probe walks the whole path the panel depends on and reports the first
	// step that fails.
	Probe(ctx context.Context) error

	// Close releases the connection.
	Close() error
}

// Failure classes. The interface layer turns each into its own message,
// because the operator action differs: a refused key needs a key, an unknown
// host key needs approval, and a conflict needs a fresh read.
var (
	ErrUnreachable     = errors.New("server is unreachable")
	ErrHostKeyUnknown  = errors.New("host key is not approved yet")
	ErrHostKeyMismatch = errors.New("host key does not match the approved one")
	ErrAuth            = errors.New("ssh authentication failed")
	ErrConflict        = errors.New("the remote file changed since it was read")
	ErrCommandFailed   = errors.New("remote command failed")
	ErrRemoteOutput    = errors.New("remote shell produced unexpected output")
)

// Failure codes. A stored failure keeps the class and drops the text, because
// the text names the remote command, its paths and its stderr.
const (
	CodeUnreachable     = "unreachable"
	CodeHostKeyUnknown  = "host_key_unknown"
	CodeHostKeyMismatch = "host_key_mismatch"
	CodeAuth            = "auth"
	CodeConflict        = "conflict"
	CodeCommandFailed   = "command_failed"
	CodeRemoteOutput    = "remote_output"
	CodeTimeout         = "timeout"
	CodeCancelled       = "cancelled"
	CodeUnknown         = "unknown"
)

// FailureCode names the class of a transport failure.
//
// The order matters. A probe wraps a command failure, so the more specific
// class has to be tried before the one it is wrapped in.
func FailureCode(err error) string {
	switch {
	// The deadline of the whole operation, which the panel sets and the
	// operator configures. It reads as unreachable otherwise, and that would
	// send them looking at the network instead of at the limit.
	case errors.Is(err, context.DeadlineExceeded):
		return CodeTimeout
	case errors.Is(err, context.Canceled):
		return CodeCancelled
	case errors.Is(err, ErrHostKeyMismatch):
		return CodeHostKeyMismatch
	case errors.Is(err, ErrHostKeyUnknown):
		return CodeHostKeyUnknown
	case errors.Is(err, ErrAuth):
		return CodeAuth
	case errors.Is(err, ErrConflict):
		return CodeConflict
	case errors.Is(err, ErrRemoteOutput):
		return CodeRemoteOutput
	case errors.Is(err, ErrCommandFailed):
		return CodeCommandFailed
	case errors.Is(err, ErrUnreachable):
		return CodeUnreachable
	default:
		return CodeUnknown
	}
}

// ProbeStep names one stage of the connection test.
type ProbeStep string

// The probe runs these in order. Each one depends on the one before it, so the
// first failure is the one worth reporting.
const (
	StepConnect ProbeStep = "connect"
	StepRead    ProbeStep = "read"
	StepWrite   ProbeStep = "write"
	StepStatus  ProbeStep = "status"
)

// ProbeError says which step of the connection test failed.
//
// The write step matters most. A missing or mismatched sudoers rule shows up
// there, when the operator is adding the server, rather than later when the
// first record change is refused.
type ProbeError struct {
	Step ProbeStep
	Err  error
}

func (e *ProbeError) Error() string {
	return fmt.Sprintf("connection test failed at the %s step: %v", e.Step, e.Err)
}

func (e *ProbeError) Unwrap() error { return e.Err }

// HostKeyError carries the fingerprints of a rejected host key.
//
// The observed fingerprint is what the operator has to compare against the
// server, so it travels with the error rather than only reaching the log.
type HostKeyError struct {
	Observed string
	Expected string
	Err      error
}

func (e *HostKeyError) Error() string {
	if e.Expected == "" {
		return fmt.Sprintf("%v: %s", e.Err, e.Observed)
	}
	return fmt.Sprintf("%v: server offers %s, approved is %s",
		e.Err, e.Observed, e.Expected)
}

func (e *HostKeyError) Unwrap() error { return e.Err }

// CommandError carries what a failed remote command reported.
type CommandError struct {
	Command  string
	ExitCode int
	Stderr   string
}

func (e *CommandError) Error() string {
	detail := strings.TrimSpace(e.Stderr)
	if detail == "" {
		detail = "no output on stderr"
	}
	return fmt.Sprintf("%v: %s exited %d: %s",
		ErrCommandFailed, e.Command, e.ExitCode, detail)
}

func (e *CommandError) Unwrap() error { return ErrCommandFailed }

// Config describes one managed server.
//
// The tool paths are configurable because distributions disagree about them.
// Debian keeps cat in /bin, several others in /usr/bin, and a wrong path would
// surface as an unreadable file rather than as a missing tool.
type Config struct {
	ID   int64
	Name string

	Host string
	Port int
	User string

	// KeyPath is the private key on the panel host. The key itself never
	// enters the database, so a database leak does not hand over the fleet.
	KeyPath string

	// HostKey is the approved key in authorized_keys form. Empty means no
	// operator has approved a fingerprint yet.
	HostKey string

	HostEntriesPath string
	ReloadCmd       string
	StatusCmd       string

	// CheckConfCmd validates the resolver configuration. ReloadFallbackCmd and
	// RestartCmd are the second and third rungs of a reload. Each one may be
	// empty, which is a target whose sudoers rules do not name that command
	// yet, and the step is skipped rather than failed.
	CheckConfCmd      string
	ReloadFallbackCmd string
	RestartCmd        string

	Base64Path string
	TeePath    string
	MvPath     string
	Sha256Path string

	ConnectTimeout time.Duration
	CommandTimeout time.Duration
}

// shellMetacharacters are refused in every configured path and command.
//
// Remote commands do pass through a shell, so this is the boundary that keeps
// a server record from becoming a command injection. The fields are set by an
// admin, which makes this the second line of defence rather than the first.
const shellMetacharacters = ";&|`$<>()\n\r\t\"'\\*?[]{}!~"

// Validate reports every problem in one pass.
//
// A server that is misconfigured in three ways should cost the operator one
// round of corrections, not three.
func (c Config) Validate() error {
	var problems []string

	require := func(name, value string) {
		if strings.TrimSpace(value) == "" {
			problems = append(problems, name+" is empty")
		}
	}

	require("host", c.Host)
	require("user", c.User)
	require("key path", c.KeyPath)
	require("host entries path", c.HostEntriesPath)
	require("reload command", c.ReloadCmd)
	require("status command", c.StatusCmd)
	require("base64 path", c.Base64Path)
	require("tee path", c.TeePath)
	require("mv path", c.MvPath)
	require("sha256 path", c.Sha256Path)

	if c.Port < 1 || c.Port > 65535 {
		problems = append(problems, fmt.Sprintf("port %d is out of range", c.Port))
	}

	fields := map[string]string{
		"host":                    c.Host,
		"user":                    c.User,
		"host entries path":       c.HostEntriesPath,
		"reload command":          c.ReloadCmd,
		"status command":          c.StatusCmd,
		"check config command":    c.CheckConfCmd,
		"reload fallback command": c.ReloadFallbackCmd,
		"restart command":         c.RestartCmd,
		"base64 path":             c.Base64Path,
		"tee path":                c.TeePath,
		"mv path":                 c.MvPath,
		"sha256 path":             c.Sha256Path,
	}
	for name, value := range fields {
		if i := strings.IndexAny(value, shellMetacharacters); i >= 0 {
			problems = append(problems,
				fmt.Sprintf("%s contains the shell metacharacter %q", name, value[i]))
		}
	}

	// An absolute path is what the sudoers rules name. A relative one would
	// resolve against whatever directory the remote shell happens to start in.
	for name, value := range map[string]string{
		"host entries path": c.HostEntriesPath,
		"base64 path":       c.Base64Path,
		"tee path":          c.TeePath,
		"mv path":           c.MvPath,
		"sha256 path":       c.Sha256Path,
	} {
		if value != "" && !strings.HasPrefix(value, "/") {
			problems = append(problems, name+" is not absolute: "+value)
		}
	}

	if len(problems) > 0 {
		return fmt.Errorf("invalid server configuration: %s", strings.Join(problems, "; "))
	}
	return nil
}

// tempPath is where a write lands before it is moved into place.
//
// The name is fixed and sits in the target directory. Fixed, so the sudoers
// rule needs no wildcard. Same directory, so the move is atomic.
func (c Config) tempPath() string {
	slash := strings.LastIndex(c.HostEntriesPath, "/")
	dir, file := c.HostEntriesPath[:slash+1], c.HostEntriesPath[slash+1:]
	return dir + "." + file + ".tmp"
}
