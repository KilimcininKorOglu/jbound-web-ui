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

// ErrConfig marks rules the apply step refused.
//
// It is about the content the operator submitted, so the panel sends the form
// back with the reason and their text still in it.
var ErrConfig = errors.New("rsyslog rejected the configuration")

// ErrWrite marks a rules file the panel could not replace.
//
// It says nothing about what the operator typed. The file is unwritable, the
// disk is full or the mode is wrong, and every one of those is the panel host's
// own fault rather than a form to correct.
var ErrWrite = errors.New("cannot write the forwarding configuration")

// refusedExit is what the apply step returns when it will not turn the rules
// into configuration. Every other exit code is the host failing to apply rules
// it did not object to, which is not something the operator can correct.
const refusedExit = 2

// rulePattern is what a forwarding rule may look like.
//
// A whitelist rather than a blacklist. The file is read by a daemon running as
// root, and listing the characters that are dangerous is a game the writer of
// the list loses.
var rulePattern = regexp.MustCompile(
	`^local6\.[A-Za-z*]+\s+@{1,2}[A-Za-z0-9._-]+(:\d{1,5})?$`)

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

// Manager owns the panel's own forwarding rules.
//
// It manages the panel host and never a managed DNS server. The events it
// forwards are the panel's audit trail.
//
// What it writes is the rules file inside the panel's data directory, never
// the rsyslog configuration itself. rsyslog runs as root and its configuration
// can name a program to execute, so a panel that could write that file could
// take the machine. Turning rules into configuration is the apply command's
// job, and it refuses anything that is not a forwarding rule.
type Manager struct {
	rulesPath string
	logPath   string

	apply   []string
	restart []string
	status  []string

	// run executes one configured command. It is a field so the manager can be
	// covered without rsyslog on the machine running the tests.
	run func(ctx context.Context, argv []string) ([]byte, error)

	// writeFile replaces the rules file. It is a field for the same reason run
	// is: the failure this manager rolls back from is a write that stops part
	// way through, and a disk that fills up mid write is not something a test
	// can arrange on the machine it runs on.
	writeFile func(path string, content []byte) error
}

// NewManager builds the manager.
func NewManager(rulesPath, logPath string, apply, restart, status []string) *Manager {
	return &Manager{
		rulesPath: rulesPath,
		logPath:   logPath,
		apply:     apply,
		restart:   restart,
		status:    status,
		run:       runCommand,

		writeFile: writeRulesFile,
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

	content, err := os.ReadFile(m.rulesPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Settings{}, fmt.Errorf("cannot read %s: %w", m.rulesPath, err)
	}
	if err == nil {
		settings.ForwardingRules = strings.TrimRight(string(content), "\n")
		settings.HasActiveRules = hasActiveRule(settings.ForwardingRules)
	}

	if _, statusErr := m.run(ctx, m.status); statusErr == nil {
		settings.Status = "active"
	} else {
		settings.Status = "inactive"
	}
	return settings, nil
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

// Save writes the forwarding rules, applies them and restarts the daemon.
//
// The rules the panel wrote are put back when the apply step refuses them,
// because the page reads that file and would otherwise show rules rsyslog is
// not running.
func (m *Manager) Save(ctx context.Context, rules string) error {
	if err := ValidateRules(rules); err != nil {
		return err
	}

	previous, err := os.ReadFile(m.rulesPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("cannot read %s: %w", m.rulesPath, err)
	}

	// The write replaces the file in place, so a failure part way through
	// leaves it empty or half written. What these rules route is the panel's
	// own audit trail, and the running daemon holds the old ones until it is
	// restarted, so the loss surfaces hours later and far from its cause.
	if err := m.write(rulesFile(rules)); err != nil {
		if restoreErr := m.write(previous); restoreErr != nil {
			return fmt.Errorf("%w: %v (the previous rules could not be "+
				"restored either: %v)", ErrWrite, err, restoreErr)
		}
		return fmt.Errorf("%w: %v", ErrWrite, err)
	}

	if output, err := m.run(ctx, m.apply); err != nil {
		if restoreErr := m.write(previous); restoreErr != nil {
			return fmt.Errorf("%w: %s (the previous rules could not be "+
				"restored either: %v)", ErrConfig, firstLine(output), restoreErr)
		}
		if exitCode(err) != refusedExit {
			// The rules were not the problem. The host could not turn them
			// into configuration, which is not something the form can correct.
			return fmt.Errorf("cannot apply the forwarding rules: %s", firstLine(output))
		}
		return fmt.Errorf("%w: %s", ErrConfig, firstLine(output))
	}

	if output, err := m.run(ctx, m.restart); err != nil {
		return fmt.Errorf("cannot restart rsyslog: %s", firstLine(output))
	}
	return nil
}

// rulesFile renders what goes on disk. A file with no trailing newline is one
// the apply step reads a line short of, so an empty last rule would be lost.
func rulesFile(rules string) []byte {
	trimmed := strings.TrimRight(rules, "\n")
	if trimmed == "" {
		return nil
	}
	return []byte(trimmed + "\n")
}

// exitCode reports what a command exited with, or -1 when it never ran.
func exitCode(err error) int {
	if exit, ok := errors.AsType[*exec.ExitError](err); ok {
		return exit.ExitCode()
	}
	return -1
}

// write replaces the rules file.
func (m *Manager) write(content []byte) error {
	return m.writeFile(m.rulesPath, content)
}

// writeRulesFile replaces the rules file in place.
//
// In place rather than through a rename, because a rename would leave the mode
// to the umask of whatever started the panel. This file lives in the data
// directory and stays as restricted as the directory around it.
func writeRulesFile(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("cannot open %s: %w", path, err)
	}
	defer file.Close()

	if _, err := file.Write(content); err != nil {
		return fmt.Errorf("cannot write %s: %w", path, err)
	}
	// The apply step is about to read this file as a different process, and a
	// run that lands before the bytes do would render half a configuration.
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
