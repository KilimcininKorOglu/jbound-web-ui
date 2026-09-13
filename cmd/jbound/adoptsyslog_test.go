package main

import (
	"context"
	"maps"
	"os"
	"path/filepath"
	"testing"

	"jbound/internal/config"
	"jbound/internal/settings"
	"jbound/internal/siem"
)

// memorySettings stands in for the settings table. The migration under test
// only needs the Load and Save the service already talks to, so no database
// has to open for it.
type memorySettings struct{ rows map[string]string }

func (s *memorySettings) Load(_ context.Context) (map[string]string, error) {
	return maps.Clone(s.rows), nil
}

func (s *memorySettings) Save(_ context.Context, values map[string]string) error {
	s.rows = maps.Clone(values)
	return nil
}

func freshSettings(t *testing.T) *settings.Service {
	t.Helper()
	return settings.NewService(&memorySettings{rows: map[string]string{}})
}

func rulesFile(t *testing.T, content string) *config.Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "siem-rules.conf")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("cannot write the rules file: %v", err)
	}
	return &config.Config{SIEMRulesPath: path}
}

func TestACarriedRsyslogRuleFillsTheReceiverSettings(t *testing.T) {
	// The rule text is the only place the old release wrote the collector
	// down, so the carried settings have to match it in protocol, host and
	// port, including the syslog default when no port was named.
	cases := map[string]struct {
		rules    string
		protocol string
		host     string
		port     string
	}{
		"tcp with an explicit port": {
			rules:    "# a comment\n@@collector.example.net:601\n",
			protocol: "tcp", host: "collector.example.net", port: "601",
		},
		"udp without a port": {
			rules:    "@collector.example.net\n",
			protocol: "udp", host: "collector.example.net", port: "514",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			options := freshSettings(t)
			if options.String(settings.SIEMProtocol) != siem.ProtocolOff {
				t.Fatalf("the default protocol is %q, not off",
					options.String(settings.SIEMProtocol))
			}

			if err := adoptRsyslogRule(t.Context(), rulesFile(t, tc.rules), options); err != nil {
				t.Fatalf("adoptRsyslogRule returned an error: %v", err)
			}

			if got := options.String(settings.SIEMProtocol); got != tc.protocol {
				t.Errorf("protocol is %q, want %q", got, tc.protocol)
			}
			if got := options.String(settings.SIEMReceiverHost); got != tc.host {
				t.Errorf("host is %q, want %q", got, tc.host)
			}
			if got := options.String(settings.SIEMReceiverPort); got != tc.port {
				t.Errorf("port is %q, want %q", got, tc.port)
			}
		})
	}
}

func TestAMissingRulesFileLeavesTheReceiverOff(t *testing.T) {
	// A fresh install has no rules to carry, and that is not a failure: the
	// migration has to run and find nothing to do.
	options := freshSettings(t)
	cfg := &config.Config{SIEMRulesPath: filepath.Join(t.TempDir(), "absent.conf")}

	if err := adoptRsyslogRule(t.Context(), cfg, options); err != nil {
		t.Fatalf("adoptRsyslogRule returned an error: %v", err)
	}
	if got := options.String(settings.SIEMProtocol); got != siem.ProtocolOff {
		t.Errorf("protocol is %q, want off", got)
	}
}

func TestARulesFileWithoutAUsableRuleLeavesTheReceiverOff(t *testing.T) {
	// "mail.example.net" is an active line, but it names no receiver the
	// panel can speak to. The operator is warned, not overridden.
	options := freshSettings(t)

	if err := adoptRsyslogRule(t.Context(), rulesFile(t, "mail.example.net\n"), options); err != nil {
		t.Fatalf("adoptRsyslogRule returned an error: %v", err)
	}
	if got := options.String(settings.SIEMProtocol); got != siem.ProtocolOff {
		t.Errorf("protocol is %q, want off", got)
	}
}

func TestAChosenReceiverIsNeverOverwrittenByARsyslogRule(t *testing.T) {
	// The migration runs once, while the operator has made no choice. Saving
	// through the service first puts the function past that window, and the
	// rule in the file must then leave the settings alone.
	options := freshSettings(t)
	if err := options.Save(t.Context(), map[string]string{
		settings.SIEMProtocol:     "udp",
		settings.SIEMReceiverHost: "chosen.example.net",
	}); err != nil {
		t.Fatalf("cannot configure the receiver: %v", err)
	}

	if err := adoptRsyslogRule(t.Context(),
		rulesFile(t, "@@rule.example.net:601\n"), options); err != nil {
		t.Fatalf("adoptRsyslogRule returned an error: %v", err)
	}
	if got := options.String(settings.SIEMReceiverHost); got != "chosen.example.net" {
		t.Errorf("the rule overwrote the operator's choice: host is %q", got)
	}
}
