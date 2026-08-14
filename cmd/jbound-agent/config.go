package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Config is everything the agent knows.
//
// It is read from the environment, the same way the panel reads its own, so
// the two are configured with one habit rather than two. The values live in
// /etc/jbound-agent/jbound-agent.env, which the systemd unit loads.
//
// Every path and every command is here rather than in a request. That is the
// point of the agent: the panel names a step, and what a step does was decided
// on this host, by whoever installed it.
type Config struct {
	ListenAddr string
	TLSCert    string
	TLSKey     string
	TokenFile  string

	// RecordsPath is the file the panel writes through this agent, and
	// MainConfig is what has to include it. Neither is ever taken from a
	// request: an agent that wrote a file the caller named would be a way to
	// write anything on this host, which is a larger thing than everything
	// else here put together.
	RecordsPath string
	MainConfig  string

	// The steps the agent runs. An empty command is a step this host does not
	// have, and the agent says so rather than pretending it worked.
	CheckConfCmd      Command
	ReloadCmd         Command
	ReloadFallbackCmd Command
	RestartCmd        Command
	StatusCmd         Command

	// CommandTimeout bounds one step. A reload that never returns would
	// otherwise hold the request until the panel gives up, and the process
	// would stay behind.
	CommandTimeout time.Duration
}

// Command is a command line already split into an argv list.
//
// Splitting happens once, at load, so nothing further along is tempted to hand
// the value to a shell. There is no shell anywhere in this binary.
type Command []string

// String renders the command for a log line.
func (c Command) String() string { return strings.Join(c, " ") }

// Configured reports whether this step has a command at all.
func (c Command) Configured() bool { return len(c) > 0 }

// shellMetacharacters are refused in every configured command.
//
// Commands run through exec without a shell, so one of these can only come
// from a misconfiguration or from somebody trying to make this into a shell.
// Failing at startup surfaces both, on the host where it can be corrected.
const shellMetacharacters = ";&|`$<>()\n\r"

// Load reads the configuration and reports every problem in one pass.
func Load() (*Config, error) {
	var problems []string
	fail := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	cfg := &Config{
		ListenAddr:  env("LISTEN_ADDR", "0.0.0.0:8443"),
		TLSCert:     env("TLS_CERT", "/etc/jbound-agent/agent.crt"),
		TLSKey:      env("TLS_KEY", "/etc/jbound-agent/agent.key"),
		TokenFile:   env("TOKEN_FILE", "/etc/jbound-agent/token"),
		RecordsPath: env("RECORDS_PATH", "/etc/unbound/local_records.conf"),
		MainConfig:  env("MAIN_CONFIG_PATH", "/etc/unbound/unbound.conf"),
	}

	seconds, err := envInt("COMMAND_TIMEOUT_SECONDS", 60)
	if err != nil {
		fail("%v", err)
	}
	if seconds < 1 {
		fail("COMMAND_TIMEOUT_SECONDS must be at least 1, got %d", seconds)
	}
	cfg.CommandTimeout = time.Duration(seconds) * time.Second

	// The two paths are absolute or the agent does not start. A relative one
	// would resolve against whatever directory systemd happened to give it.
	for name, path := range map[string]string{
		"RECORDS_PATH":     cfg.RecordsPath,
		"MAIN_CONFIG_PATH": cfg.MainConfig,
		"TOKEN_FILE":       cfg.TokenFile,
		"TLS_CERT":         cfg.TLSCert,
		"TLS_KEY":          cfg.TLSKey,
	} {
		if !filepath.IsAbs(path) {
			fail("%s must be an absolute path, got %q", name, path)
		}
	}

	// Every step may be empty. A host whose resolver has no control socket has
	// no reload command, and the panel's ladder moves on to the next rung.
	commands := []struct {
		key    string
		def    string
		target *Command
	}{
		{"CHECK_CONF_CMD", "/usr/sbin/unbound-checkconf " + cfg.MainConfig, &cfg.CheckConfCmd},
		{"RELOAD_CMD", "/usr/sbin/unbound-control reload_keep_cache", &cfg.ReloadCmd},
		{"RELOAD_FALLBACK_CMD", "/usr/sbin/service unbound reload", &cfg.ReloadFallbackCmd},
		{"RESTART_CMD", "/usr/sbin/service unbound restart", &cfg.RestartCmd},
		{"STATUS_CMD", "systemctl is-active unbound", &cfg.StatusCmd},
	}
	for _, c := range commands {
		raw := env(c.key, c.def)
		if strings.TrimSpace(raw) == "" {
			continue
		}
		value, cerr := ParseCommand(raw)
		if cerr != nil {
			fail("%s: %v", c.key, cerr)
			continue
		}
		*c.target = value
	}

	if len(problems) > 0 {
		return nil, fmt.Errorf("invalid configuration:\n  %s", strings.Join(problems, "\n  "))
	}
	return cfg, nil
}

// ParseCommand splits a configured command into an argv list.
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
