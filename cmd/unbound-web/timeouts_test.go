package main

import (
	"testing"

	"unbound-web/internal/settings"
)

func TestTheWriteTimeoutOutlastsTheLongestFleetOperation(t *testing.T) {
	// The write timeout of net/http cancels nothing and writes no status, so a
	// fleet operation that reaches it loses the per-server report. The panel
	// bounds those handlers itself, and this holds the two limits in the order
	// that keeps the report reachable.
	definition, ok := settings.Lookup(settings.FleetOperationTimeout)
	if !ok {
		t.Fatalf("%s is not a setting", settings.FleetOperationTimeout)
	}

	if httpWriteTimeout <= definition.Max {
		t.Errorf("write timeout %s does not outlast the longest fleet operation %s",
			httpWriteTimeout, definition.Max)
	}
}
