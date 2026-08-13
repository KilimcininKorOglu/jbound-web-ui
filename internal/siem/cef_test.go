package siem

import (
	"log/syslog"
	"strings"
	"testing"

	"unbound-web/internal/audit"
)

func entry(action string) audit.Entry {
	return audit.Entry{
		UID:       1001,
		Username:  "dnsadmin",
		Action:    action,
		Details:   "Added A record: www.example.net -> 192.0.2.10",
		IPAddress: "203.0.113.5",
	}
}

func TestEveryActionKeepsItsSeverityAndName(t *testing.T) {
	cases := []struct {
		action   string
		name     string
		severity int
		priority syslog.Priority
	}{
		{audit.ActionLogin, "User Login", 1, syslog.LOG_INFO},
		{audit.ActionLogout, "User Logout", 1, syslog.LOG_INFO},
		{audit.ActionLoginFailed, "Login Failed", 5, syslog.LOG_WARNING},
		{audit.ActionDNSAdd, "DNS Record Added", 3, syslog.LOG_NOTICE},
		{audit.ActionDNSEdit, "DNS Record Modified", 3, syslog.LOG_NOTICE},
		{audit.ActionDNSDelete, "DNS Record Deleted", 5, syslog.LOG_WARNING},
		{audit.ActionDNSRestart, "DNS Service Reloaded", 4, syslog.LOG_NOTICE},
		{audit.ActionDNSQuery, "DNS Query Executed", 1, syslog.LOG_INFO},
		{audit.ActionServerCreate, "DNS Server Registered", 4, syslog.LOG_NOTICE},
		{audit.ActionServerUpdate, "DNS Server Modified", 4, syslog.LOG_NOTICE},
		{audit.ActionServerDelete, "DNS Server Removed", 6, syslog.LOG_WARNING},
		{audit.ActionServerTrust, "SSH Host Key Trusted", 5, syslog.LOG_WARNING},
		{audit.ActionDiffRepair, "Record Drift Repaired", 3, syslog.LOG_NOTICE},
	}

	for _, want := range cases {
		t.Run(want.action, func(t *testing.T) {
			got := Classify(want.action)
			if got.Name != want.name || got.Severity != want.severity || got.Priority != want.priority {
				t.Errorf("got %+v, want %+v", got, want)
			}
		})
	}
}

func TestAnUnknownActionKeepsTheDefaults(t *testing.T) {
	// A new action must still reach the receiver rather than being dropped for
	// having no entry.
	got := Classify("something_new")

	if got.Name != "something_new" || got.Severity != 3 || got.Priority != syslog.LOG_INFO {
		t.Errorf("got %+v", got)
	}
}

func TestTheLineCarriesTheHeaderAndEveryField(t *testing.T) {
	line := Format(entry(audit.ActionDNSAdd), "panel.example.net")

	const wantHeader = "CEF:0|JanBound|JanBoundDNSPanel|1.0|dns_add|DNS Record Added|3|"
	if !strings.HasPrefix(line, wantHeader) {
		t.Fatalf("line = %q", line)
	}
	for _, want := range []string{
		"src=203.0.113.5",
		"suser=dnsadmin",
		"suid=1001",
		"msg=Added A record: www.example.net -> 192.0.2.10",
		"dhost=panel.example.net",
		"dvchost=panel.example.net",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("the line does not carry %q:\n%s", want, line)
		}
	}
}

func TestTheTargetServerTravelsAsTheDestinationHost(t *testing.T) {
	// One field says what was changed, the other says from where. A record
	// change on three servers produces three lines that differ in dhost alone.
	record := entry(audit.ActionDNSAdd)
	record.ServerName = "dns2"

	line := Format(record, "panel.example.net")
	if !strings.Contains(line, "dhost=dns2") {
		t.Errorf("the line does not name the target:\n%s", line)
	}
	if !strings.Contains(line, "dvchost=panel.example.net") {
		t.Errorf("the line does not name the panel:\n%s", line)
	}
}

func TestAnEqualsSignInAValueIsEscaped(t *testing.T) {
	// An unescaped one would end the field early and the rest of the message
	// would arrive as a field of its own.
	record := entry(audit.ActionDNSAdd)
	record.Details = `Added TXT record: v=spf1 -all`

	line := Format(record, "panel.example.net")
	if !strings.Contains(line, `msg=Added TXT record: v\=spf1 -all`) {
		t.Errorf("the equals sign was not escaped:\n%s", line)
	}
}

func TestABackslashIsEscaped(t *testing.T) {
	record := entry(audit.ActionDNSAdd)
	record.Details = `path C:\temp`

	line := Format(record, "panel.example.net")
	if !strings.Contains(line, `msg=path C:\\temp`) {
		t.Errorf("the backslash was not escaped:\n%s", line)
	}
}

func TestANewlineNeverSplitsTheEvent(t *testing.T) {
	// A second line would reach the receiver as a malformed record rather than
	// as part of this one.
	record := entry(audit.ActionDNSRestart)
	record.Details = "Unbound service reloaded.\nOutput: ok\r\n"

	line := Format(record, "panel.example.net")
	if strings.ContainsAny(line, "\n\r") {
		t.Errorf("the line holds a break:\n%q", line)
	}
	if !strings.Contains(line, "Unbound service reloaded. Output: ok") {
		t.Errorf("the message was mangled:\n%s", line)
	}
}

func TestAControlCharacterIsDropped(t *testing.T) {
	record := entry(audit.ActionLogin)
	record.Username = "dns\x00admin\x07"

	line := Format(record, "panel.example.net")
	if strings.Contains(line, "\x00") || strings.Contains(line, "\x07") {
		t.Errorf("the line holds a control character:\n%q", line)
	}
	if !strings.Contains(line, "suser=dnsadmin") {
		t.Errorf("the user name was mangled:\n%s", line)
	}
}

func TestAPipeInTheHeaderIsEscaped(t *testing.T) {
	// The header is separated by pipes, so one inside a field would shift every
	// field after it.
	record := entry("odd|action")

	line := Format(record, "panel.example.net")
	if !strings.Contains(line, `|odd\|action|odd\|action|3|`) {
		t.Errorf("the pipe was not escaped:\n%s", line)
	}
}
