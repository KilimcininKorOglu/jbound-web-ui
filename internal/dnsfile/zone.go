package dnsfile

import (
	"fmt"
	"regexp"
	"strings"
)

// localZone matches a zone declaration and captures the name it covers.
var localZone = regexp.MustCompile(`^local-zone:\s*"([^"]+)"`)

// ParentZone is the zone a record belongs to.
//
// It is the name with its first label removed, which is what the resolver
// treats as the record's zone. A name with one label has no parent to declare
// and returns empty.
func ParentZone(fqdn string) string {
	name := strings.TrimSuffix(strings.TrimSpace(fqdn), ".")

	_, parent, found := strings.Cut(name, ".")
	if !found || parent == "" {
		return ""
	}
	return parent
}

// EnsureZone declares the parent zone of a record as transparent.
//
// Unbound generates a transparent zone for a name it has local data for and no
// zone covering, so most files work without this line. The case it does not
// cover is a parent zone the operator has already declared: under a static or
// a redirect zone the record is written, the panel reports it written, and the
// resolver answers something else.
//
// A zone line that is already there is left alone whatever its type. An
// operator who chose static chose it, and turning that into transparent is a
// decision about the whole zone rather than about the record being added.
func EnsureZone(content []byte, fqdn string) []byte {
	zone := ParentZone(fqdn)
	if zone == "" {
		return content
	}

	lines := split(content)
	if declaresZone(lines, zone) {
		return content
	}
	// The type sits outside the quotes, which is the form Unbound documents.
	return join(append(lines, fmt.Sprintf("local-zone: %q transparent", zone+".")))
}

// declaresZone reports whether the file already covers a zone.
//
// The quotes are allowed to hold the type as well, because Unbound accepts
// both forms and the file is edited by hand on the target.
func declaresZone(lines []string, zone string) bool {
	for _, line := range lines {
		match := localZone.FindStringSubmatch(strings.TrimSpace(line))
		if match == nil {
			continue
		}
		name := fields.Split(strings.TrimSpace(match[1]), -1)[0]
		if strings.TrimSuffix(name, ".") == zone {
			return true
		}
	}
	return false
}
