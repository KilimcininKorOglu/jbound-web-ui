// Package config loads the panel configuration from the environment.
//
// Every value has a default that matches the production install. The
// development stack overrides the command values, because containers have no
// systemd.
package config

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"jbound/internal/logging"
	"jbound/internal/server"
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

	// LogLevel is how much the panel writes. It is read once at startup, and
	// SIGUSR1 switches to debug and back while the panel runs, so an incident
	// needs no restart.
	LogLevel slog.Level

	DigPath string

	// SIEMRulesPath is where the release that forwarded through rsyslog kept the
	// rules an operator wrote. The panel sends its trail itself now and writes
	// nothing here, but it still reads the file once at startup to carry an
	// existing collector over.
	SIEMRulesPath string
}

// Load reads the configuration from the environment and validates it.
func Load() (*Config, error) {
	var errs []string
	fail := func(format string, args ...any) {
		errs = append(errs, fmt.Sprintf(format, args...))
	}

	cfg := &Config{}

	cfg.ListenAddr = env("LISTEN_ADDR", "127.0.0.1:8080")
	cfg.DataDir = env("DATA_DIR", "/var/lib/jbound")
	cfg.DBPath = env("DB_PATH", filepath.Join(cfg.DataDir, "jbound.db"))
	cfg.KeyDir = filepath.Join(cfg.DataDir, server.KeySubdir)

	cfg.AuthHelperPath = env("AUTH_HELPER_PATH", "/usr/local/libexec/jbound-authhelper")
	cfg.PAMService = env("PAM_SERVICE", "jbound")
	cfg.AdminGroup = env("ADMIN_GROUP", "sudo")
	cfg.AllowedGroup = env("ALLOWED_GROUP", "")
	cfg.SIEMRulesPath = filepath.Join(cfg.DataDir, "siem-rules.conf")
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
	if cfg.LogLevel, err = logging.ParseLevel(env("LOG_LEVEL", "info")); err != nil {
		fail("%v", err)
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
