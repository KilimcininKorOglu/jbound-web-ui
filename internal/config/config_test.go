package config

import (
	"log/slog"
	"strings"
	"testing"
)

// settableKeys is every variable Load reads. Load treats an empty value as
// unset, so blanking them all is how a test asks for the pure defaults.
var settableKeys = []string{
	"LISTEN_ADDR", "DATA_DIR", "DB_PATH",
	"AUTH_HELPER_PATH", "PAM_SERVICE", "ADMIN_GROUP", "ALLOWED_GROUP",
	"MIN_UID", "AUTH_MAX_CONCURRENT",
	"COOKIE_SECURE", "DIG_PATH", "LOG_LEVEL",
}

// clearEnvironment removes every configured value for the duration of a test.
//
// Without it the result would depend on the shell that started the test, and
// the development container sets most of these.
func clearEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range settableKeys {
		t.Setenv(key, "")
	}
}

func TestLoadUsesProductionDefaults(t *testing.T) {
	clearEnvironment(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned an error: %v", err)
	}

	if cfg.ListenAddr != "127.0.0.1:8080" {
		t.Errorf("ListenAddr = %q, want 127.0.0.1:8080", cfg.ListenAddr)
	}
	if cfg.DigPath != "dig" {
		t.Errorf("DigPath = %q, want dig", cfg.DigPath)
	}
	if cfg.MinUID != 1000 {
		t.Errorf("MinUID = %d, want 1000", cfg.MinUID)
	}
	if cfg.AdminGroup != "sudo" {
		t.Errorf("AdminGroup = %q, want sudo", cfg.AdminGroup)
	}
	if !cfg.CookieSecure {
		t.Error("CookieSecure = false, want true by default")
	}
	if cfg.LogLevel != slog.LevelInfo {
		t.Errorf("LogLevel = %v, want info", cfg.LogLevel)
	}
	if cfg.SIEMRulesPath != cfg.DataDir+"/siem-rules.conf" {
		t.Errorf("SIEMRulesPath = %q, want it under DataDir", cfg.SIEMRulesPath)
	}
	if cfg.DBPath != cfg.DataDir+"/jbound.db" {
		t.Errorf("DBPath = %q, want it under DataDir", cfg.DBPath)
	}
	if cfg.KeyDir != cfg.DataDir+"/keys" {
		t.Errorf("KeyDir = %q, want it under DataDir", cfg.KeyDir)
	}
}

func TestLoadRejectsBadValues(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"non numeric MIN_UID", map[string]string{"MIN_UID": "abc"}, "MIN_UID"},
		{"negative MIN_UID", map[string]string{"MIN_UID": "-1"}, "MIN_UID"},
		{"zero concurrency", map[string]string{"AUTH_MAX_CONCURRENT": "0"}, "AUTH_MAX_CONCURRENT"},
		{"bad boolean", map[string]string{"COOKIE_SECURE": "yes please"}, "COOKIE_SECURE"},
		// A typo here would otherwise leave the panel logging at a level
		// nobody chose, which is only noticed when the output is needed.
		{"unknown log level", map[string]string{"LOG_LEVEL": "verbose"}, "log level"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearEnvironment(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			_, err := Load()
			if err == nil {
				t.Fatalf("Load accepted %v", tc.env)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %s", err, tc.want)
			}
		})
	}
}

// A single Load call must report every problem it finds, so an operator fixes
// the environment in one pass instead of one variable per restart.
func TestLoadReportsEveryProblemAtOnce(t *testing.T) {
	clearEnvironment(t)
	t.Setenv("MIN_UID", "abc")
	t.Setenv("AUTH_MAX_CONCURRENT", "nope")
	t.Setenv("COOKIE_SECURE", "yes please")

	_, err := Load()
	if err == nil {
		t.Fatal("Load accepted three broken values")
	}
	for _, want := range []string{"MIN_UID", "AUTH_MAX_CONCURRENT", "COOKIE_SECURE"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %s:\n%v", want, err)
		}
	}
}
