package transport

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func validConfig() Config {
	return Config{
		ID:              1,
		Name:            "dns1",
		Host:            "dns1.example",
		Port:            22,
		User:            "dnsops",
		KeyPath:         "/var/lib/jbound/keys/1.key",
		HostEntriesPath: "/etc/unbound/host_entries.conf",
		ReloadCmd:       "sudo /usr/sbin/service unbound reload",
		StatusCmd:       "systemctl is-active unbound",
		Sha256Path:      "/usr/bin/sha256sum",
		Base64Path:      "/usr/bin/base64",
		TeePath:         "/usr/bin/tee",
		MvPath:          "/bin/mv",
		ConnectTimeout:  10 * time.Second,
		CommandTimeout:  30 * time.Second,
	}
}

func TestValidateAcceptsAWorkingConfiguration(t *testing.T) {
	if err := validConfig().Validate(); err != nil {
		t.Fatalf("a valid configuration was refused: %v", err)
	}
}

func TestValidateRefusesShellMetacharacters(t *testing.T) {
	// Remote commands do pass through a shell, so a metacharacter in a server
	// record is the difference between a path and a second command.
	injections := []string{
		"/etc/unbound/host_entries.conf; rm -rf /",
		"/etc/unbound/host_entries.conf && id",
		"/etc/unbound/`id`.conf",
		"/etc/unbound/$USER.conf",
		"/etc/unbound/host_entries.conf | mail me",
		"/etc/unbound/*.conf",
		"/etc/unbound/host\nentries.conf",
	}

	for _, value := range injections {
		t.Run(value, func(t *testing.T) {
			cfg := validConfig()
			cfg.HostEntriesPath = value

			err := cfg.Validate()
			if err == nil {
				t.Fatalf("Validate accepted %q", value)
			}
			if !strings.Contains(err.Error(), "host entries path") {
				t.Errorf("the error does not name the field: %v", err)
			}
		})
	}
}

func TestValidateRefusesARelativePath(t *testing.T) {
	// The sudoers rules name absolute paths. A relative one would resolve
	// against whatever directory the remote shell starts in.
	cfg := validConfig()
	cfg.TeePath = "tee"

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate accepted a relative path")
	}
	if !strings.Contains(err.Error(), "not absolute") {
		t.Errorf("the error does not name the rule: %v", err)
	}
}

func TestValidateReportsEveryProblemAtOnce(t *testing.T) {
	// Three mistakes should cost the operator one round of corrections.
	cfg := validConfig()
	cfg.Host = ""
	cfg.Port = 0
	cfg.ReloadCmd = "service unbound reload; id"

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate accepted three broken values")
	}
	for _, want := range []string{"host", "port", "reload command"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %s: %v", want, err)
		}
	}
}

func TestTempPathSitsBesideTheTarget(t *testing.T) {
	// Same directory, so the move is atomic. Fixed name, so the sudoers rule
	// needs no wildcard.
	cfg := validConfig()

	if got := cfg.tempPath(); got != "/etc/unbound/.host_entries.conf.tmp" {
		t.Errorf("tempPath = %q", got)
	}
}

func TestCleanBase64AcceptsASingleLine(t *testing.T) {
	got, err := cleanBase64("aGVsbG8gd29ybGQ=\n")
	if err != nil {
		t.Fatalf("cleanBase64 returned an error: %v", err)
	}
	if got != "aGVsbG8gd29ybGQ=" {
		t.Errorf("cleanBase64 = %q", got)
	}
}

func TestCleanBase64AcceptsEmptyOutput(t *testing.T) {
	// An empty host entries file is a normal state for a fresh server.
	if _, err := cleanBase64(""); err != nil {
		t.Fatalf("an empty file was refused: %v", err)
	}
}

func TestCleanBase64RefusesShellPollution(t *testing.T) {
	// base64 -w0 never wraps, so a second line always comes from a profile
	// file. The line based check would find the base64 line and pass, which is
	// why the whole output has to be one line.
	cases := map[string]string{
		"noise before the content": "Welcome to dns1\naGVsbG8=",
		"noise after the content":  "aGVsbG8=\nHave a nice day",
		"noise on both sides":      "motd\naGVsbG8=\nbye",
		"carriage return":          "aGVsbG8=\rmotd",
	}

	for name, output := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := cleanBase64(output)
			if err == nil {
				t.Fatalf("cleanBase64 accepted %q", output)
			}
			if !errors.Is(err, ErrRemoteOutput) {
				t.Errorf("got %v, want ErrRemoteOutput", err)
			}
			// Silently stripping the noise would hide data corruption, so the
			// error has to point at the cause.
			if !strings.Contains(err.Error(), "profile files") {
				t.Errorf("the error gives no advice: %v", err)
			}
		})
	}
}

func TestCleanBase64RefusesOutputThatIsNotBase64(t *testing.T) {
	_, err := cleanBase64("cat: /etc/unbound/host_entries.conf: No such file")
	if !errors.Is(err, ErrRemoteOutput) {
		t.Fatalf("got %v, want ErrRemoteOutput", err)
	}
}

func TestDigestMatchesTheKnownValueOfAnEmptyFile(t *testing.T) {
	const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	if got := digest(nil); got != emptySHA256 {
		t.Errorf("digest = %q", got)
	}
}

func TestProbeErrorNamesTheStep(t *testing.T) {
	err := &ProbeError{Step: StepWrite, Err: ErrCommandFailed}

	if !strings.Contains(err.Error(), "write") {
		t.Errorf("the message does not name the step: %v", err)
	}
	if !errors.Is(err, ErrCommandFailed) {
		t.Error("the cause is not reachable through errors.Is")
	}
}

func TestHostKeyErrorCarriesBothFingerprints(t *testing.T) {
	// The operator compares the observed fingerprint against the server, so it
	// has to travel with the error rather than only reach the log.
	err := &HostKeyError{
		Observed: "SHA256:aaa",
		Expected: "SHA256:bbb",
		Err:      ErrHostKeyMismatch,
	}

	message := err.Error()
	if !strings.Contains(message, "SHA256:aaa") || !strings.Contains(message, "SHA256:bbb") {
		t.Errorf("the message drops a fingerprint: %s", message)
	}
	if !errors.Is(err, ErrHostKeyMismatch) {
		t.Error("the class is not reachable through errors.Is")
	}
}

func TestHostKeyErrorForAnUnknownServerNamesOnlyTheObservedKey(t *testing.T) {
	err := &HostKeyError{Observed: "SHA256:aaa", Err: ErrHostKeyUnknown}

	if strings.Contains(err.Error(), "approved is") {
		t.Errorf("the message claims an approved key exists: %v", err)
	}
}

func TestCommandErrorCarriesTheExitCodeAndStderr(t *testing.T) {
	err := &CommandError{
		Command:  "sudo /usr/sbin/service unbound reload",
		ExitCode: 1,
		Stderr:   "unbound-checkconf: fatal error",
	}

	message := err.Error()
	for _, want := range []string{"exited 1", "fatal error", "service unbound reload"} {
		if !strings.Contains(message, want) {
			t.Errorf("the message drops %q: %s", want, message)
		}
	}
	if !errors.Is(err, ErrCommandFailed) {
		t.Error("the class is not reachable through errors.Is")
	}
}

func TestCommandErrorSaysSoWhenStderrIsEmpty(t *testing.T) {
	// An empty message would read as though nothing went wrong.
	err := &CommandError{Command: "systemctl is-active unbound", ExitCode: 3}

	if !strings.Contains(err.Error(), "no output on stderr") {
		t.Errorf("the message hides the empty stderr: %v", err)
	}
}

func TestNewSSHRefusesAnInvalidConfiguration(t *testing.T) {
	cfg := validConfig()
	cfg.Host = ""

	if _, err := NewSSH(cfg); err == nil {
		t.Fatal("NewSSH accepted a configuration with no host")
	}
}

func TestSameEndpointNoticesEveryConnectionField(t *testing.T) {
	// A changed record must replace the connection. Reusing it would send the
	// next command to the previous address.
	base := validConfig()

	changes := map[string]func(*Config){
		"host":     func(c *Config) { c.Host = "other.example" },
		"port":     func(c *Config) { c.Port = 2222 },
		"user":     func(c *Config) { c.User = "root" },
		"key path": func(c *Config) { c.KeyPath = "/other.key" },
		"host key": func(c *Config) { c.HostKey = "ssh-ed25519 AAAA" },
	}

	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			changed := base
			change(&changed)
			if sameEndpoint(base, changed) {
				t.Errorf("a change to the %s went unnoticed", name)
			}
		})
	}

	if !sameEndpoint(base, base) {
		t.Error("an unchanged record was treated as different")
	}
}

func TestEveryFailureClassCarriesItsOwnCode(t *testing.T) {
	// The stored class is what the interface layer turns into a sentence, so a
	// wrong class shows the operator the wrong next step.
	classes := map[error]string{
		ErrUnreachable:     CodeUnreachable,
		ErrHostKeyUnknown:  CodeHostKeyUnknown,
		ErrHostKeyMismatch: CodeHostKeyMismatch,
		ErrAuth:            CodeAuth,
		ErrConflict:        CodeConflict,
		ErrCommandFailed:   CodeCommandFailed,
		ErrRemoteOutput:    CodeRemoteOutput,

		// The deadline of the whole fleet operation. An SSH dial that is cut
		// short reads as unreachable otherwise, which sends the operator to
		// the network rather than to the limit they configured.
		context.DeadlineExceeded: CodeTimeout,
		context.Canceled:         CodeCancelled,
	}

	for cause, want := range classes {
		if got := FailureCode(cause); got != want {
			t.Errorf("FailureCode(%v) = %q, want %q", cause, got, want)
		}
		wrapped := fmt.Errorf("read host entries: %w", cause)
		if got := FailureCode(wrapped); got != want {
			t.Errorf("FailureCode(wrapped %v) = %q, want %q", cause, got, want)
		}
	}
}

func TestACommandFailureIsClassifiedWithoutItsText(t *testing.T) {
	// CommandError carries the remote command line and the remote stderr, and
	// this is the value that used to reach the status page verbatim.
	cause := &CommandError{
		Command:  "/usr/bin/base64 -w0 /etc/unbound/host_entries.conf",
		ExitCode: 1,
		Stderr:   "sudo: a password is required",
	}

	if got := FailureCode(cause); got != CodeCommandFailed {
		t.Errorf("FailureCode = %q, want %q", got, CodeCommandFailed)
	}
	if strings.Contains(FailureCode(cause), "base64") {
		t.Error("the code carries the remote command line")
	}
}

func TestAnUnknownFailureFallsBackToTheUnknownCode(t *testing.T) {
	if got := FailureCode(errors.New("disk on fire")); got != CodeUnknown {
		t.Errorf("FailureCode = %q, want %q", got, CodeUnknown)
	}
}
