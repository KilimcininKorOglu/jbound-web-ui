// Package store holds the SQL statements of the panel.
//
// Domain types live in the packages that own the behaviour. This package only
// reads and writes them, so business rules stay testable without a database.
package store

import (
	"fmt"
	"time"
)

// timeLayout matches what SQLite's strftime produces in the schema. Every
// column stores UTC, so the layout carries no zone.
const timeLayout = "2006-01-02 15:04:05"

// formatTime renders a timestamp for storage. The value is converted to UTC
// first, because a local time in the same column would silently reorder rows.
func formatTime(t time.Time) string {
	return t.UTC().Format(timeLayout)
}

// parseTime reads a stored timestamp back as UTC.
func parseTime(value string) (time.Time, error) {
	t, err := time.Parse(timeLayout, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("cannot parse the timestamp %q: %w", value, err)
	}
	return t.UTC(), nil
}
