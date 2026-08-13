package siem

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// ErrRule marks a forwarding rule the panel refuses to write.
var ErrRule = errors.New("invalid forwarding rule")

// ErrConfig marks a configuration rsyslog itself rejected.
var ErrConfig = errors.New("rsyslog rejected the configuration")

// rulePattern is what a forwarding rule may look like.
//
// A whitelist rather than a blacklist. The file is read by a daemon running as
// root, and listing the characters that are dangerous is a game the writer of
// the list loses.
var rulePattern = regexp.MustCompile(
	`^local6\.[A-Za-z*]+\s+@{1,2}[A-Za-z0-9._-]+(:\d{1,5})?$`)

// forwardingBlock finds the operator's rules between the two markers.
var forwardingBlock = regexp.MustCompile(`(?s)# ─── SIEM Forwarding.*?─+\n(.*?)# ─+`)

// Settings is what the SIEM page shows.
type Settings struct {
	// ForwardingRules is the block between the markers, as the operator wrote
	// it. Comments are kept, because an operator parks a rule that way.
	ForwardingRules string

	// Status is active, inactive or unknown.
	Status string

	// HasActiveRules reports whether any rule is more than a comment, which is
	// the difference between forwarding and not forwarding.
	HasActiveRules bool

	LogFile  string
	Facility string
}

// Manager owns the panel's own rsyslog configuration.
//
// It manages the panel host and never a managed DNS server. The events it
// forwards are the panel's audit trail.
type Manager struct {
	confPath string
	logPath  string

	validate []string
	restart  []string
	status   []string

	// run executes one configured command. It is a field so the manager can be
	// covered without rsyslog on the machine running the tests.
	run func(ctx context.Context, argv []string) ([]byte, error)
}

// NewManager builds the manager.
func NewManager(confPath, logPath string, validate, restart, status []string) *Manager {
	return &Manager{
		confPath: confPath,
		logPath:  logPath,
		validate: validate,
		restart:  restart,
		status:   status,
		run:      runCommand,
	}
}

// Settings reads the current configuration and the daemon status.
//
// A missing file is not a failure. It is what a panel that has never forwarded
// anything looks like.
func (m *Manager) Settings(ctx context.Context) (Settings, error) {
	settings := Settings{
		Status:   "unknown",
		LogFile:  m.logPath,
		Facility: "local6",
	}

	content, err := os.ReadFile(m.confPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Settings{}, fmt.Errorf("cannot read %s: %w", m.confPath, err)
	}
	if err == nil {
		settings.ForwardingRules = extractRules(string(content))
		settings.HasActiveRules = hasActiveRule(settings.ForwardingRules)
	}

	if _, statusErr := m.run(ctx, m.status); statusErr == nil {
		settings.Status = "active"
	} else {
		settings.Status = "inactive"
	}
	return settings, nil
}

// extractRules returns the block between the markers.
func extractRules(content string) string {
	match := forwardingBlock.FindStringSubmatch(content)
	if len(match) < 2 {
		return ""
	}
	return strings.TrimSpace(match[1])
}

// hasActiveRule reports whether any line is more than a comment.
func hasActiveRule(rules string) bool {
	for line := range strings.SplitSeq(rules, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			return true
		}
	}
	return false
}

// ValidateRules reports every rule the panel refuses, in one pass.
func ValidateRules(rules string) error {
	var problems []string

	for i, line := range strings.Split(rules, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !rulePattern.MatchString(trimmed) {
			problems = append(problems, fmt.Sprintf("line %d: %s", i+1, trimmed))
		}
	}

	if len(problems) > 0 {
		return fmt.Errorf("%w: a rule reads like "+
			"local6.*    @@siem.example.net:514; refused %s",
			ErrRule, strings.Join(problems, "; "))
	}
	return nil
}

// Save writes the forwarding rules and restarts the daemon.
//
// The previous content is restored when rsyslog rejects the new one, because a
// configuration the daemon will not load leaves the panel with no log at all
// after the next restart.
func (m *Manager) Save(ctx context.Context, rules string) error {
	if err := ValidateRules(rules); err != nil {
		return err
	}

	previous, err := os.ReadFile(m.confPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("cannot read %s: %w", m.confPath, err)
	}

	if err := m.write(render(rules, m.logPath)); err != nil {
		return err
	}

	if output, err := m.run(ctx, m.validate); err != nil {
		if restoreErr := m.write(previous); restoreErr != nil {
			return fmt.Errorf("%w: %s (the previous configuration could not be "+
				"restored either: %v)", ErrConfig, firstLine(output), restoreErr)
		}
		return fmt.Errorf("%w: %s", ErrConfig, firstLine(output))
	}

	if output, err := m.run(ctx, m.restart); err != nil {
		return fmt.Errorf("cannot restart rsyslog: %s", firstLine(output))
	}
	return nil
}

// write replaces the configuration file in place.
//
// In place rather than through a rename, because the panel runs unprivileged
// and the install grants it write access to this one file rather than to
// /etc/rsyslog.d itself. A rename needs the directory.
func (m *Manager) write(content []byte) error {
	file, err := os.OpenFile(m.confPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o640)
	if err != nil {
		return fmt.Errorf("cannot open %s: %w", m.confPath, err)
	}
	defer file.Close()

	if _, err := file.Write(content); err != nil {
		return fmt.Errorf("cannot write %s: %w", m.confPath, err)
	}
	// The daemon is about to read this file, and a restart that lands before
	// the bytes do would load half a configuration.
	if err := file.Sync(); err != nil {
		return fmt.Errorf("cannot flush %s: %w", m.confPath, err)
	}
	return nil
}

// Recent returns the last lines of the panel log, newest first.
//
// The file is read directly. Shelling out to tail would put a path the
// operator can influence on a command line for no gain.
func (m *Manager) Recent(lines int) ([]string, error) {
	lines = max(10, min(200, lines))

	content, err := os.ReadFile(m.logPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", m.logPath, err)
	}

	var kept []string
	for line := range strings.SplitSeq(string(content), "\n") {
		if strings.TrimSpace(line) != "" {
			kept = append(kept, line)
		}
	}

	if len(kept) > lines {
		kept = kept[len(kept)-lines:]
	}

	// Newest first, because that is the end an operator reads.
	for i, j := 0, len(kept)-1; i < j; i, j = i+1, j-1 {
		kept[i], kept[j] = kept[j], kept[i]
	}
	return kept, nil
}

// render builds the whole configuration file around the operator's rules.
//
// The panel owns this file. Writing only the block between the markers would
// leave the template and the log rule to drift with whatever wrote them last.
func render(rules, logPath string) []byte {
	if strings.TrimSpace(rules) == "" {
		rules = "# No forwarding rules configured."
	}

	var out bytes.Buffer
	fmt.Fprintf(&out, `# JanBound DNS Panel - Syslog Configuration
# Logs from the DNS management panel (facility local6)
#
# This file is written by the panel. Edit it through the SIEM page.

# Template: SIEM-compatible format with ISO8601 timestamp
template(name="JanBoundPanelFormat" type="string"
    string="%%timegenerated:::date-rfc3339%% %%HOSTNAME%% %%syslogtag%%%%msg%%\n"
)

# Write to dedicated log file
local6.*    %s;JanBoundPanelFormat

# ─── SIEM Forwarding ────────────────────────────────────────────────────
%s
# ─────────────────────────────────────────────────────────────────────────

# Stop processing these messages in other log files
& stop
`, logPath, strings.TrimSpace(rules))

	return out.Bytes()
}

// runCommand executes one configured command without a shell.
func runCommand(ctx context.Context, argv []string) ([]byte, error) {
	if len(argv) == 0 {
		return nil, errors.New("the command is not configured")
	}

	output, err := exec.CommandContext(ctx, argv[0], argv[1:]...).CombinedOutput()
	return output, err
}

// firstLine keeps a command's failure to one readable sentence.
func firstLine(output []byte) string {
	text := strings.TrimSpace(string(output))
	if text == "" {
		return "no output"
	}
	first, _, _ := strings.Cut(text, "\n")
	return first
}
