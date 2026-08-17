package siem

import (
	"fmt"
	"time"

	"jbound/internal/audit"
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

// SendTestEvents writes the test events straight to the receiver.
//
// They go out as ordinary events, so what arrives is exactly what a real one
// looks like. They are marked in the message rather than in the format, because
// a special format would prove nothing about the real one.
//
// They are not audit rows and they never become any. That is why they bypass the
// queue: an operator checking a receiver must not be writing to the trail every
// time they press the button.
func SendTestEvents(sender *Sender, panelHost string, actor audit.Entry) (string, error) {

	if !sender.Configured() {
		return "", ErrNoReceiver
	}

	for _, event := range testEvents {
		entry := audit.Entry{
			UID:       actor.UID,
			Username:  actor.Username,
			Action:    event.action,
			Details:   event.details,
			IPAddress: actor.IPAddress,
		}
		entry.Defaults()

		if err := sender.Send(entry.Action, Format(entry, panelHost), time.Now()); err != nil {
			return "", fmt.Errorf("cannot send the test events: %w", err)
		}
	}

	return fmt.Sprintf("%d test events sent to the receiver.", TestEventCount), nil
}
