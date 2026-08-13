package siem

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"unbound-web/internal/audit"
)

// manager returns a manager over a temporary configuration file.
func manager(t *testing.T) (*Manager, string) {
	t.Helper()

	dir := t.TempDir()
	conf := filepath.Join(dir, "60-panel.conf")
	logFile := filepath.Join(dir, "panel.log")

	m := NewManager(conf, logFile,
		[]string{"validate"}, []string{"restart"}, []string{"status"})
	m.run = func(context.Context, []string) ([]byte, error) { return nil, nil }

	return m, conf
}

func TestARuleThatReadsLikeAForwarderIsAccepted(t *testing.T) {
	for _, rule := range []string{
		"local6.*    @@siem.example.net:514",
		"local6.*  @siem.example.net",
		"local6.info    @@10.0.0.5:1514",
		"# local6.*    @@parked.example.net:514",
		"",
	} {
		if err := ValidateRules(rule); err != nil {
			t.Errorf("ValidateRules(%q) = %v", rule, err)
		}
	}
}

func TestAnythingElseIsRefused(t *testing.T) {
	// The file is read by a daemon running as root. A blacklist of dangerous
	// characters is a game the writer of the list loses.
	for _, rule := range []string{
		"*.* @@siem.example.net:514",
		"local6.* /etc/passwd",
		"local6.*    @@siem.example.net:514; rm -rf /",
		"local6.*    @@$(hostname):514",
		`local6.* ^/usr/bin/touch`,
		"module(load=\"omprog\")",
	} {
		if err := ValidateRules(rule); !errors.Is(err, ErrRule) {
			t.Errorf("ValidateRules(%q) = %v, want ErrRule", rule, err)
		}
	}
}

func TestEveryRefusedRuleIsNamedInOnePass(t *testing.T) {
	err := ValidateRules("*.* @@a.example.net\nlocal6.* @@ok.example.net\nbad line")

	if !errors.Is(err, ErrRule) {
		t.Fatalf("got %v, want ErrRule", err)
	}
	if !strings.Contains(err.Error(), "line 1") || !strings.Contains(err.Error(), "line 3") {
		t.Errorf("the message does not name both lines: %v", err)
	}
	if strings.Contains(err.Error(), "line 2") {
		t.Errorf("a valid rule was reported: %v", err)
	}
}

func TestTheSavedFileCarriesTheRulesBetweenTheMarkers(t *testing.T) {
	m, conf := manager(t)
	const rule = "local6.*    @@siem-sink:514"

	if err := m.Save(context.Background(), rule); err != nil {
		t.Fatalf("Save returned an error: %v", err)
	}

	content, err := os.ReadFile(conf)
	if err != nil {
		t.Fatalf("cannot read the file back: %v", err)
	}
	for _, want := range []string{
		"JanBoundPanelFormat", "SIEM Forwarding", rule, "& stop",
	} {
		if !strings.Contains(string(content), want) {
			t.Errorf("the file does not carry %q:\n%s", want, content)
		}
	}
}

func TestTheRulesComeBackTheWayTheyWereWritten(t *testing.T) {
	m, _ := manager(t)
	const rules = "local6.*    @@siem-sink:514\n# local6.*    @parked.example.net"

	if err := m.Save(context.Background(), rules); err != nil {
		t.Fatalf("Save returned an error: %v", err)
	}

	settings, err := m.Settings(context.Background())
	if err != nil {
		t.Fatalf("Settings returned an error: %v", err)
	}
	if settings.ForwardingRules != rules {
		t.Errorf("rules = %q", settings.ForwardingRules)
	}
	if !settings.HasActiveRules {
		t.Error("a live rule does not read as active")
	}
}

func TestOnlyCommentsReadAsNotForwarding(t *testing.T) {
	// The difference between forwarding and not forwarding is what the page
	// shows as its status badge.
	m, _ := manager(t)

	if err := m.Save(context.Background(), "# local6.*    @@parked.example.net:514"); err != nil {
		t.Fatalf("Save returned an error: %v", err)
	}

	settings, _ := m.Settings(context.Background())
	if settings.HasActiveRules {
		t.Error("a commented rule reads as active")
	}
}

func TestAMissingFileIsNotAFailure(t *testing.T) {
	// A panel that has never forwarded anything has no file yet.
	m, _ := manager(t)

	settings, err := m.Settings(context.Background())
	if err != nil {
		t.Fatalf("Settings returned an error: %v", err)
	}
	if settings.ForwardingRules != "" || settings.HasActiveRules {
		t.Errorf("got %+v", settings)
	}
}

func TestTheStatusFollowsTheStatusCommand(t *testing.T) {
	m, _ := manager(t)

	if settings, _ := m.Settings(context.Background()); settings.Status != "active" {
		t.Errorf("status = %q, want active", settings.Status)
	}

	m.run = func(context.Context, []string) ([]byte, error) {
		return nil, errors.New("exit status 1")
	}
	if settings, _ := m.Settings(context.Background()); settings.Status != "inactive" {
		t.Errorf("status = %q, want inactive", settings.Status)
	}
}

func TestARejectedConfigurationIsRolledBack(t *testing.T) {
	// A configuration the daemon will not load would leave the panel with no
	// log at all after the next restart.
	m, conf := manager(t)

	if err := m.Save(context.Background(), "local6.*    @@first.example.net:514"); err != nil {
		t.Fatalf("the first save failed: %v", err)
	}

	m.run = func(_ context.Context, argv []string) ([]byte, error) {
		if argv[0] == "validate" {
			return []byte("rsyslogd: error on line 12\n"), errors.New("exit status 1")
		}
		return nil, nil
	}

	err := m.Save(context.Background(), "local6.*    @@second.example.net:514")
	if !errors.Is(err, ErrConfig) {
		t.Fatalf("got %v, want ErrConfig", err)
	}
	if !strings.Contains(err.Error(), "error on line 12") {
		t.Errorf("the reason was lost: %v", err)
	}

	content, _ := os.ReadFile(conf)
	if !strings.Contains(string(content), "first.example.net") {
		t.Errorf("the previous configuration was not restored:\n%s", content)
	}
}

func TestAFailedRestartIsReported(t *testing.T) {
	m, _ := manager(t)
	m.run = func(_ context.Context, argv []string) ([]byte, error) {
		if argv[0] == "restart" {
			return []byte("job failed\n"), errors.New("exit status 1")
		}
		return nil, nil
	}

	err := m.Save(context.Background(), "local6.*    @@siem-sink:514")
	if err == nil || !strings.Contains(err.Error(), "job failed") {
		t.Fatalf("got %v", err)
	}
}

func TestTheRecentLinesComeBackNewestFirst(t *testing.T) {
	m, conf := manager(t)
	logFile := filepath.Join(filepath.Dir(conf), "panel.log")

	if err := os.WriteFile(logFile, []byte("first\nsecond\nthird\n"), 0o644); err != nil {
		t.Fatalf("cannot write the log file: %v", err)
	}

	lines, err := m.Recent(50)
	if err != nil {
		t.Fatalf("Recent returned an error: %v", err)
	}
	if len(lines) != 3 || lines[0] != "third" || lines[2] != "first" {
		t.Errorf("lines = %v", lines)
	}
}

func TestTheLineCountStaysWithinItsBounds(t *testing.T) {
	m, conf := manager(t)
	logFile := filepath.Join(filepath.Dir(conf), "panel.log")

	var content strings.Builder
	for i := range 300 {
		fmt.Fprintf(&content, "line %d\n", i)
	}
	if err := os.WriteFile(logFile, []byte(content.String()), 0o644); err != nil {
		t.Fatalf("cannot write the log file: %v", err)
	}

	if lines, _ := m.Recent(1); len(lines) != 10 {
		t.Errorf("a request for one line returned %d", len(lines))
	}
	if lines, _ := m.Recent(5000); len(lines) != 200 {
		t.Errorf("a request for five thousand lines returned %d", len(lines))
	}
}

func TestAMissingLogFileIsNotAFailure(t *testing.T) {
	m, _ := manager(t)

	lines, err := m.Recent(50)
	if err != nil || lines != nil {
		t.Errorf("got %v %v", lines, err)
	}
}

func TestTheTestEventsCoverMoreThanOneSeverity(t *testing.T) {
	// A single event would prove the socket works and nothing about the
	// mapping the receiver sorts on.
	client := &fakeConn{}
	forwarder, _ := harness(t, client)

	message, err := SendTestEvents(context.Background(), forwarder,
		audit.Entry{UID: 1001, Username: "dnsadmin", IPAddress: "203.0.113.5"})
	if err != nil {
		t.Fatalf("SendTestEvents returned an error: %v", err)
	}
	if message != "4 test events sent to syslog (facility local6)." {
		t.Errorf("message = %q", message)
	}

	lines := client.written()
	if len(lines) != TestEventCount {
		t.Fatalf("got %d lines, want %d", len(lines), TestEventCount)
	}

	levels := map[string]bool{}
	for _, line := range lines {
		level, _, _ := strings.Cut(line, " ")
		levels[level] = true

		if !strings.Contains(line, "SIEM Test:") {
			t.Errorf("a test event is not marked as one: %q", line)
		}
		if !strings.Contains(line, "suser=dnsadmin") {
			t.Errorf("a test event is not attributed: %q", line)
		}
	}
	if len(levels) < 2 {
		t.Errorf("every test event went out at the same severity: %v", levels)
	}
}

func TestACommandThatLeavesADaemonBehindStillReturns(t *testing.T) {
	// Restarting rsyslog leaves the new daemon holding the pipes it inherited.
	// Waiting for them to close would wait for the process the panel just
	// started, which is to say forever.
	start := time.Now()

	output, err := runCommand(context.Background(),
		[]string{"sh", "-c", "sleep 30 & echo restarted"})
	if err != nil {
		t.Fatalf("runCommand returned an error: %v", err)
	}
	if !strings.Contains(string(output), "restarted") {
		t.Errorf("output = %q", output)
	}
	if elapsed := time.Since(start); elapsed > commandTimeout {
		t.Errorf("the command took %s", elapsed)
	}
}

func TestAFailingCommandStillReportsItsExitCode(t *testing.T) {
	_, err := runCommand(context.Background(), []string{"sh", "-c", "echo broken >&2; exit 1"})
	if err == nil {
		t.Fatal("a failing command reported success")
	}
}
