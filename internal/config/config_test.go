package config

import (
	"log/slog"
	"strings"
	"testing"
)

func TestParseCommandSplitsIntoArgv(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"single word", "rsyslogd", []string{"rsyslogd"}},
		{"with flags", "rsyslogd -N1", []string{"rsyslogd", "-N1"}},
		{"sudo prefix", "sudo /usr/bin/systemctl restart rsyslog",
			[]string{"sudo", "/usr/bin/systemctl", "restart", "rsyslog"}},
		{"collapses runs of spaces", "systemctl   is-active    rsyslog",
			[]string{"systemctl", "is-active", "rsyslog"}},
		{"trims the edges", "  systemctl is-active rsyslog  ",
			[]string{"systemctl", "is-active", "rsyslog"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseCommand(tc.in)
			if err != nil {
				t.Fatalf("ParseCommand(%q) returned an error: %v", tc.in, err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("ParseCommand(%q) = %v, want %v", tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("ParseCommand(%q) = %v, want %v", tc.in, got, tc.want)
				}
			}
		})
	}
}

// Commands are handed to exec, never to a shell. A metacharacter therefore
// signals a misconfiguration or an injection attempt, and the panel must
// refuse to start rather than run it.
func TestParseCommandRejectsShellMetacharacters(t *testing.T) {
	cases := []string{
		"systemctl restart rsyslog; rm -rf /",
		"systemctl restart rsyslog && id",
		"cat /etc/shadow | mail me",
		"echo `id`",
		"echo $HOME",
		"cat < /etc/passwd",
		"echo hi > /tmp/x",
		"systemctl restart rsyslog\nid",
	}

	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			if _, err := ParseCommand(in); err == nil {
				t.Fatalf("ParseCommand(%q) accepted a shell metacharacter", in)
			}
		})
	}
}

func TestParseCommandRejectsEmpty(t *testing.T) {
	for _, in := range []string{"", "   ", "\t"} {
		if _, err := ParseCommand(in); err == nil {
			t.Fatalf("ParseCommand(%q) accepted an empty command", in)
		}
	}
}

// settableKeys is every variable Load reads. Load treats an empty value as
// unset, so blanking them all is how a test asks for the pure defaults.
var settableKeys = []string{
	"LISTEN_ADDR", "DATA_DIR", "DB_PATH",
	"AUTH_HELPER_PATH", "PAM_SERVICE", "ADMIN_GROUP", "ALLOWED_GROUP",
	"MIN_UID", "AUTH_MAX_CONCURRENT",
	"COOKIE_SECURE", "DIG_PATH", "LOG_LEVEL",
	"RSYSLOG_RESTART_CMD", "RSYSLOG_STATUS_CMD", "RSYSLOG_VALIDATE_CMD",
	"RSYSLOG_CONF_PATH", "SYSLOG_LOG_PATH",
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
	// The defaults decide production behaviour when nothing is configured, so
	// they are asserted rather than assumed.
	if got := cfg.RsyslogRestartCmd.String(); got != "systemctl restart rsyslog" {
		t.Errorf("RsyslogRestartCmd = %q, want systemctl restart rsyslog", got)
	}
	if cfg.DBPath != cfg.DataDir+"/unbound.db" {
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
		{"injected command", map[string]string{"RSYSLOG_RESTART_CMD": "systemctl restart rsyslog; id"},
			"RSYSLOG_RESTART_CMD"},
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
	t.Setenv("RSYSLOG_STATUS_CMD", "id; whoami")

	_, err := Load()
	if err == nil {
		t.Fatal("Load accepted three broken values")
	}
	for _, want := range []string{"MIN_UID", "AUTH_MAX_CONCURRENT", "RSYSLOG_STATUS_CMD"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %s:\n%v", want, err)
		}
	}
}
