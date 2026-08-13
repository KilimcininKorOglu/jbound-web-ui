package settings

import (
	"strings"
	"time"
)

// Human writes a duration the way an operator types it.
//
// Go prints 24h as 24h0m0s, which is three units for a value that has one. The
// panel prints bounds, stored values and refusals through this, so a reader is
// not asked to match 24h against 24h0m0s.
func Human(d time.Duration) string {
	text := d.String()
	if strings.HasSuffix(text, "m0s") {
		text = strings.TrimSuffix(text, "0s")
	}
	if strings.HasSuffix(text, "h0m") {
		text = strings.TrimSuffix(text, "0m")
	}
	return text
}
