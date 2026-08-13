// Package config loads the panel configuration from the environment.
//
// Every value has a default that matches the production install. The
// development stack overrides the command values, because containers have no
// systemd.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"unbound-web/internal/server"
)

// Config holds every runtime setting of the panel.
type Config struct {
	ListenAddr string
	DataDir    string
	DBPath     string
	KeyDir     string

	AuthHelperPath    string
	PAMService        string
	AdminGroup        string
	AllowedGroup      string
	MinUID            int
	AuthMaxConcurrent int

	CookieSecure bool

	DigPath string

	RsyslogRestartCmd  Command
	RsyslogStatusCmd   Command
	RsyslogValidateCmd Command
	RsyslogConfPath    string
	SyslogLogPath      string
}

// shellMetacharacters are rejected in every configured command. Commands run
// through exec without a shell, so a metacharacter can only come from a
// misconfiguration or an injection attempt. Failing at startup surfaces both.
const shellMetacharacters = ";&|`$<>()\n\r"

// Command is a command line already split into an argv list. Splitting happens
// once at load time so no caller is tempted to hand the value to a shell.
type Command []string

// String renders the command for logs and error messages.
func (c Command) String() string { return strings.Join(c, " ") }

// Load reads the configuration from the environment and validates it.
func Load() (*Config, error) {
	var errs []string
	fail := func(format string, args ...any) {
		errs = append(errs, fmt.Sprintf(format, args...))
	}

	cfg := &Config{}

	cfg.ListenAddr = env("LISTEN_ADDR", "127.0.0.1:8080")
	cfg.DataDir = env("DATA_DIR", "/var/lib/unbound-web")
	cfg.DBPath = env("DB_PATH", filepath.Join(cfg.DataDir, "unbound.db"))
	cfg.KeyDir = filepath.Join(cfg.DataDir, server.KeySubdir)

	cfg.AuthHelperPath = env("AUTH_HELPER_PATH", "/usr/local/libexec/unbound-web-authhelper")
	cfg.PAMService = env("PAM_SERVICE", "unbound-web")
	cfg.AdminGroup = env("ADMIN_GROUP", "sudo")
	cfg.AllowedGroup = env("ALLOWED_GROUP", "")
	cfg.RsyslogConfPath = env("RSYSLOG_CONF_PATH", "/etc/rsyslog.d/60-unbound-dns-panel.conf")
	cfg.SyslogLogPath = env("SYSLOG_LOG_PATH", "/var/log/unbound-dns-panel.log")
	cfg.DigPath = env("DIG_PATH", "dig")

	var err error

	if cfg.MinUID, err = envInt("MIN_UID", 1000); err != nil {
		fail("%v", err)
	}
	if cfg.AuthMaxConcurrent, err = envInt("AUTH_MAX_CONCURRENT", 4); err != nil {
		fail("%v", err)
	}
	if cfg.CookieSecure, err = envBool("COOKIE_SECURE", true); err != nil {
		fail("%v", err)
	}

	commands := []struct {
		key    string
		def    string
		target *Command
	}{
		{"RSYSLOG_RESTART_CMD", "systemctl restart rsyslog", &cfg.RsyslogRestartCmd},
		{"RSYSLOG_STATUS_CMD", "systemctl is-active rsyslog", &cfg.RsyslogStatusCmd},
		{"RSYSLOG_VALIDATE_CMD", "rsyslogd -N1", &cfg.RsyslogValidateCmd},
	}
	for _, c := range commands {
		value, cerr := ParseCommand(env(c.key, c.def))
		if cerr != nil {
			fail("%s: %v", c.key, cerr)
			continue
		}
		*c.target = value
	}

	if cfg.MinUID < 0 {
		fail("MIN_UID must not be negative, got %d", cfg.MinUID)
	}
	if cfg.AuthMaxConcurrent < 1 {
		fail("AUTH_MAX_CONCURRENT must be at least 1, got %d", cfg.AuthMaxConcurrent)
	}

	if len(errs) > 0 {
		return nil, fmt.Errorf("invalid configuration:\n  %s", strings.Join(errs, "\n  "))
	}
	return cfg, nil
}

// ParseCommand splits a configured command into an argv list and rejects shell
// metacharacters. The result is passed to exec directly, never to a shell.
func ParseCommand(raw string) (Command, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("command is empty")
	}
	if i := strings.IndexAny(trimmed, shellMetacharacters); i >= 0 {
		return nil, fmt.Errorf("command contains the shell metacharacter %q: %s",
			trimmed[i], trimmed)
	}
	return Command(strings.Fields(trimmed)), nil
}

func env(key, def string) string {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		return value
	}
	return def
}

func envInt(key string, def int) (int, error) {
	raw, ok := os.LookupEnv(key)
	if !ok || raw == "" {
		return def, nil
	}
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer, got %q", key, raw)
	}
	return value, nil
}

func envBool(key string, def bool) (bool, error) {
	raw, ok := os.LookupEnv(key)
	if !ok || raw == "" {
		return def, nil
	}
	value, err := strconv.ParseBool(strings.TrimSpace(raw))
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean, got %q", key, raw)
	}
	return value, nil
}
