// Package siem forwards audit entries to a security information and event
// management system.
//
// The panel writes CEF over syslog. The database stays the primary record,
// because the panel must still answer "who added this record" when the SIEM is
// unreachable.
package siem

import (
	"fmt"
	"log/syslog"
	"strings"

	"jbound/internal/audit"
)

// The CEF header identifies the product to the receiver. The version is the
// CEF format version and never the panel version.
const (
	cefVersion = "CEF:0"
	vendor     = "JBound"
	product    = "JBoundDNSPanel"
	release    = "1.0"
)

// Class is how one action is reported.
type Class struct {
	// Name is the human readable event name the receiver shows.
	Name string

	// Severity is the CEF scale, 0 to 10.
	Severity int

	// Priority is the syslog severity the line is sent with.
	Priority syslog.Priority
}

// classes maps an action onto how it is reported.
//
// An action that is not listed keeps the defaults: the action as its own event
// name, severity 3 and informational priority.
var classes = map[string]Class{
	audit.ActionLogin:       {"User Login", 1, syslog.LOG_INFO},
	audit.ActionLogout:      {"User Logout", 1, syslog.LOG_INFO},
	audit.ActionLoginFailed: {"Login Failed", 5, syslog.LOG_WARNING},

	audit.ActionDNSAdd:     {"DNS Record Added", 3, syslog.LOG_NOTICE},
	audit.ActionDNSEdit:    {"DNS Record Modified", 3, syslog.LOG_NOTICE},
	audit.ActionDNSDelete:  {"DNS Record Deleted", 5, syslog.LOG_WARNING},
	audit.ActionDNSRestart: {"DNS Service Reloaded", 4, syslog.LOG_NOTICE},
	audit.ActionDNSQuery:   {"DNS Query Executed", 1, syslog.LOG_INFO},

	audit.ActionServerCreate: {"DNS Server Registered", 4, syslog.LOG_NOTICE},
	audit.ActionServerUpdate: {"DNS Server Modified", 4, syslog.LOG_NOTICE},
	audit.ActionServerDelete: {"DNS Server Removed", 6, syslog.LOG_WARNING},
	audit.ActionServerTrust:  {"SSH Host Key Trusted", 5, syslog.LOG_WARNING},

	audit.ActionDiffRepair: {"Record Drift Repaired", 3, syslog.LOG_NOTICE},

	// The panel wrote to the main resolver configuration of a managed server.
	// A receiver that watches for changes outside the managed file wants to
	// see this one.
	audit.ActionConfigInclude: {"Resolver Configuration Repaired", 5, syslog.LOG_WARNING},

	// An import reaches into the trail itself. A receiver that suddenly sees
	// rows older than the panel needs to be told why, and a warning is what
	// makes somebody look.
	audit.ActionAuditImport: {"Audit Trail Imported", 5, syslog.LOG_WARNING},
}

// Classify reports how an action is sent.
func Classify(action string) Class {
	if class, ok := classes[action]; ok {
		return class
	}
	return Class{Name: action, Severity: 3, Priority: syslog.LOG_INFO}
}

// Format renders one audit entry as a CEF line.
//
// dhost carries the DNS server the action was aimed at, and dvchost the panel
// host. Both are needed: one says what was changed, the other says from where.
// An action that targets no server reports the panel host in both.
func Format(entry audit.Entry, panelHost string) string {
	class := Classify(entry.Action)

	target := entry.ServerName
	if target == "" {
		target = panelHost
	}

	return fmt.Sprintf(
		"%s|%s|%s|%s|%s|%s|%d|src=%s suser=%s suid=%d msg=%s dhost=%s dvchost=%s",
		cefVersion, vendor, product, release,
		escapeHeader(entry.Action), escapeHeader(class.Name), class.Severity,
		escapeValue(entry.IPAddress), escapeValue(entry.Username), entry.UID,
		escapeValue(entry.Details), escapeValue(target), escapeValue(panelHost))
}

// FormatRow renders one stored audit row as the CEF line it is sent as.
//
// It exists so the sender and the page that shows what was sent read the same
// row the same way. Two renderings would drift, and the page would then be a
// picture of something the receiver never got.
func FormatRow(row audit.Row, panelHost string) string {
	return Format(audit.Entry{
		UID:        row.UID,
		Username:   row.Username,
		ServerID:   row.ServerID,
		Action:     row.Action,
		Details:    row.Details,
		IPAddress:  row.IPAddress,
		ServerName: row.ServerName,
	}, panelHost)
}

// escapeHeader escapes the pipe and the backslash, which are what separate the
// header fields.
func escapeHeader(value string) string {
	return strings.NewReplacer(`\`, `\\`, "|", `\|`).Replace(clean(value))
}

// escapeValue escapes the equals sign and the backslash, which are what
// separate one extension field from the next.
func escapeValue(value string) string {
	return strings.NewReplacer(`\`, `\\`, "=", `\=`).Replace(clean(value))
}

// clean removes what would end the line early.
//
// A newline inside a value would split one event into two, and the second half
// would arrive at the receiver as a malformed record rather than as part of
// this one.
func clean(value string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value)
}
