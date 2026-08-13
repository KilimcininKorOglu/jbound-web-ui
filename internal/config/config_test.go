package config

import (
	"strings"
	"testing"
	"time"
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

func TestLoadUsesProductionDefaults(t *testing.T) {
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned an error: %v", err)
	}

	if cfg.ListenAddr != "127.0.0.1:8080" {
		t.Errorf("ListenAddr = %q, want 127.0.0.1:8080", cfg.ListenAddr)
	}
	if cfg.SessionTimeout != 30*time.Minute {
		t.Errorf("SessionTimeout = %s, want 30m", cfg.SessionTimeout)
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
	// The defaults must match the reference project so production behaviour
	// does not drift when nothing is configured.
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
		{"bad duration", map[string]string{"SESSION_TIMEOUT": "half an hour"}, "SESSION_TIMEOUT"},
		{"zero duration", map[string]string{"SSH_CONNECT_TIMEOUT": "0s"}, "SSH_CONNECT_TIMEOUT"},
		{"bad boolean", map[string]string{"COOKIE_SECURE": "yes please"}, "COOKIE_SECURE"},
		{"injected command", map[string]string{"RSYSLOG_RESTART_CMD": "systemctl restart rsyslog; id"},
			"RSYSLOG_RESTART_CMD"},
		{"stale window not longer than refresh",
			map[string]string{"CACHE_REFRESH_INTERVAL": "10m", "CACHE_STALE_AFTER": "5m"},
			"CACHE_STALE_AFTER"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
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
	t.Setenv("MIN_UID", "abc")
	t.Setenv("SESSION_TIMEOUT", "nope")
	t.Setenv("RSYSLOG_STATUS_CMD", "id; whoami")

	_, err := Load()
	if err == nil {
		t.Fatal("Load accepted three broken values")
	}
	for _, want := range []string{"MIN_UID", "SESSION_TIMEOUT", "RSYSLOG_STATUS_CMD"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %s:\n%v", want, err)
		}
	}
}
