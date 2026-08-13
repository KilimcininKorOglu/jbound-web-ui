package siem

import (
	"context"
	"fmt"

	"unbound-web/internal/audit"
)

// testEvents are what Send Test Logs produces.
//
// Four events rather than one, and four different actions, because they have
// to arrive at the receiver with different severities for the operator to see
// that the mapping works end to end.
var testEvents = []struct {
	action  string
	details string
}{
	{audit.ActionLogin, "SIEM Test: User login event"},
	{audit.ActionDNSAdd, "SIEM Test: DNS record added - test.example.com A 192.168.1.1"},
	{audit.ActionDNSDelete, "SIEM Test: DNS record deleted - test.example.com"},
	{audit.ActionLoginFailed, "SIEM Test: Failed login attempt from 10.0.0.1"},
}

// TestEventCount is how many events one test run sends.
var TestEventCount = len(testEvents)

// SendTestEvents writes the test events through the forwarder.
//
// They go out as ordinary events, so what arrives at the receiver is exactly
// what a real one looks like. They are marked in the message rather than in
// the format, because a special format would prove nothing about the real one.
func SendTestEvents(ctx context.Context, forwarder audit.Forwarder, actor audit.Entry) (string, error) {
	for _, event := range testEvents {
		entry := audit.Entry{
			UID:       actor.UID,
			Username:  actor.Username,
			Action:    event.action,
			Details:   event.details,
			IPAddress: actor.IPAddress,
		}
		entry.Defaults()

		if err := forwarder.Forward(entry); err != nil {
			return "", fmt.Errorf("cannot send the test events: %w", err)
		}
	}

	return fmt.Sprintf("%d test events sent to syslog (facility local6).",
		TestEventCount), nil
}
