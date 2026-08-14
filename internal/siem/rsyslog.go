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
	"time"
)

// ErrRule marks a forwarding rule the panel refuses to write.
var ErrRule = errors.New("invalid forwarding rule")

// ErrConfig marks a configuration rsyslog itself rejected.
//
// It is about the content the operator submitted, so the panel sends the form
// back with the reason and their text still in it.
var ErrConfig = errors.New("rsyslog rejected the configuration")

// ErrWrite marks a configuration file the panel could not replace.
//
// It says nothing about what the operator typed. The file is unwritable, the
// disk is full or the mode is wrong, and every one of those is the panel host's
// own fault rather than a form to correct.
var ErrWrite = errors.New("cannot write the forwarding configuration")

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

	// Tag is the syslog ident the panel writes under. It comes from the
	// constant the forwarder uses rather than from a second spelling, because
	// the page tells the operator what to select on.
	Tag string
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

	// writeFile replaces the configuration file. It is a field for the same
	// reason run is: the failure this manager rolls back from is a write that
	// stops part way through, and a disk that fills up mid write is not
	// something a test can arrange on the machine it runs on.
	writeFile func(path string, content []byte) error
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

		writeFile: writeConfFile,
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
		Tag:      Tag,
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

	// The write replaces the file in place, so a failure part way through
	// leaves it empty or half written. What this file routes is the panel's
	// own audit trail, and the running daemon holds the old rules until it is
	// restarted, so the loss surfaces hours later and far from its cause.
	if err := m.write(render(rules, m.logPath)); err != nil {
		if restoreErr := m.write(previous); restoreErr != nil {
			return fmt.Errorf("%w: %v (the previous configuration could not be "+
				"restored either: %v)", ErrWrite, err, restoreErr)
		}
		return fmt.Errorf("%w: %v", ErrWrite, err)
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

// write replaces the configuration file.
//
// A file that did not exist before is restored as an empty one rather than
// removed, because the install grants the panel write access to this file and
// not to the directory it sits in. An empty file routes nothing, which is what
// its absence did.
func (m *Manager) write(content []byte) error {
	return m.writeFile(m.confPath, content)
}

// writeConfFile replaces the configuration file in place.
//
// In place rather than through a rename, because the panel runs unprivileged
// and the install grants it write access to this one file rather than to
// /etc/rsyslog.d itself. A rename needs the directory.
func writeConfFile(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o640)
	if err != nil {
		return fmt.Errorf("cannot open %s: %w", path, err)
	}
	defer file.Close()

	if _, err := file.Write(content); err != nil {
		return fmt.Errorf("cannot write %s: %w", path, err)
	}
	// The daemon is about to read this file, and a restart that lands before
	// the bytes do would load half a configuration.
	if err := file.Sync(); err != nil {
		return fmt.Errorf("cannot flush %s: %w", path, err)
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
	fmt.Fprintf(&out, `# JBound - Syslog Configuration
# Logs from the DNS management panel (facility local6)
#
# This file is written by the panel. Edit it through the SIEM page.

# Template: SIEM-compatible format with ISO8601 timestamp
template(name="JBoundPanelFormat" type="string"
    string="%%timegenerated:::date-rfc3339%% %%HOSTNAME%% %%syslogtag%%%%msg%%\n"
)

# Write to dedicated log file
local6.*    %s;JBoundPanelFormat

# ─── SIEM Forwarding ────────────────────────────────────────────────────
%s
# ─────────────────────────────────────────────────────────────────────────

# Stop processing these messages in other log files
& stop
`, logPath, strings.TrimSpace(rules))

	return out.Bytes()
}

// commandTimeout bounds one configured command.
//
// A daemon that never comes back would otherwise hold the request open until
// the browser gives up, with no way to tell what happened.
const commandTimeout = 30 * time.Second

// pipeDelay is how long a command's output is still collected after it exits.
//
// Restarting rsyslog leaves the new daemon holding the pipes it inherited, so
// waiting for them to close would wait for the daemon to stop. That is exactly
// the process the panel just started.
const pipeDelay = 2 * time.Second

// runCommand executes one configured command without a shell.
func runCommand(ctx context.Context, argv []string) ([]byte, error) {
	if len(argv) == 0 {
		return nil, errors.New("the command is not configured")
	}

	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()

	var output bytes.Buffer
	command := exec.CommandContext(ctx, argv[0], argv[1:]...)
	command.Stdout = &output
	command.Stderr = &output
	command.WaitDelay = pipeDelay

	err := command.Run()
	if errors.Is(err, exec.ErrWaitDelay) {
		// The command itself succeeded. Only its inherited pipes stayed open,
		// which is what a restarted daemon looks like from here.
		err = nil
	}
	return output.Bytes(), err
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
