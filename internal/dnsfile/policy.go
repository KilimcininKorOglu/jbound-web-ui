package dnsfile

import (
	"fmt"
	"strings"
)

// The behaviours the panel can give a name.
//
// Neither is a record. In Unbound a name that answers NXDOMAIN or REFUSED is a
// zone with a behaviour rather than a name with data, so these are written as
// local-zone lines. They are carried in Record all the same, because the cache,
// the diff, the mirror and the listing all speak that type and a second model
// beside it would have to be taught to every one of them.
const (
	TypeNXDOMAIN = "NXDOMAIN"
	TypeREFUSED  = "REFUSED"
)

// zoneTypes maps what the panel offers onto what Unbound reads.
//
// The always_ forms are the ones that hold whatever else the file says about
// the name. Plain refuse and nxdomain still answer from local data underneath
// them, which would make a block that does not block.
var zoneTypes = map[string]string{
	TypeNXDOMAIN: "always_nxdomain",
	TypeREFUSED:  "always_refuse",
}

// IsPolicy reports whether a type names a behaviour rather than data.
func IsPolicy(recordType string) bool {
	_, ok := zoneTypes[recordType]
	return ok
}

// zoneTypeFor is what the file holds for a behaviour.
func zoneTypeFor(recordType string) string {
	return zoneTypes[recordType]
}

// policyFor reads a zone type back into the type the panel offers.
//
// A zone type the panel does not manage returns empty, and the line it came
// from stays invisible. A transparent zone is plumbing the panel writes itself,
// and a static or redirect zone is a decision an operator made by hand; showing
// either as a record would invite deleting it from a listing.
func policyFor(zoneType string) string {
	for recordType, zone := range zoneTypes {
		if zone == zoneType {
			return recordType
		}
	}
	return ""
}

// covers reports whether a zone answers for a name.
//
// A zone covers itself and everything beneath it, which is how Unbound reads a
// local-zone line. Matching only the exact name would let a record under a
// blocked zone look legal while the resolver answers nothing for it.
func covers(zone, name string) bool {
	zone = normaliseName(zone)
	name = normaliseName(name)

	if zone == name {
		return true
	}
	return strings.HasSuffix(name, "."+zone)
}

// normaliseName drops the trailing dot and the case, so a name written either
// way in the file compares equal.
func normaliseName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

// CheckConsistency reports a record the resolver would never answer.
//
// A blocked zone holds every name beneath it, so a record written under one
// reaches the file, passes the configuration check, survives the reload and
// then answers nothing. The panel would report it written and the listing would
// go on showing it, which is the failure this rule exists to prevent.
//
// It runs over the content a change produced rather than over the change, so
// every path that builds a file reaches it: an addition, a batch, an edit, a
// repair and a mirror.
func CheckConsistency(content []byte) error {
	records := Parse(content)

	var blocks []Record
	for _, record := range records {
		if IsPolicy(record.Type) {
			blocks = append(blocks, record)
		}
	}
	if len(blocks) == 0 {
		return nil
	}

	for _, record := range records {
		if IsPolicy(record.Type) {
			continue
		}
		for _, block := range blocks {
			if covers(block.FQDN, record.FQDN) {
				return fmt.Errorf(
					"%w: %s is blocked with %s, so the %s record for %s would never be answered; remove the block first",
					ErrInvalid, block.FQDN, block.Type, record.Type, record.FQDN)
			}
		}
	}
	return nil
}

// parseZone reads one local-zone line into a record.
//
// The type is accepted inside the quotes as well as outside them, because
// Unbound reads both and the file is edited by hand on the target. A line whose
// type the panel does not manage is not a record and returns false.
func parseZone(line string, number int) (Record, bool) {
	match := localZone.FindStringSubmatch(line)
	if match == nil {
		return Record{}, false
	}

	parts := fields.Split(strings.TrimSpace(match[1]), -1)
	zoneType := ""

	switch {
	case len(parts) > 1:
		// The quotes hold both, which is the form "example.net. static" takes.
		zoneType = parts[1]
	default:
		rest := strings.TrimSpace(line[strings.Index(line, match[1])+len(match[1]):])
		rest = strings.TrimPrefix(rest, `"`)
		if outside := fields.Split(strings.TrimSpace(rest), -1); len(outside) > 0 {
			zoneType = outside[0]
		}
	}

	recordType := policyFor(strings.ToLower(zoneType))
	if recordType == "" {
		return Record{}, false
	}

	return Record{
		Line: number,
		FQDN: strings.TrimSuffix(parts[0], "."),
		Type: recordType,
		Raw:  line,
	}, true
}

// declaresName reports whether the file already opens a zone for exactly this
// name, whatever its type.
//
// Two zone lines for one name leave which of them wins to the resolver, so a
// second one is refused rather than written beside the first.
func declaresName(lines []string, name string) bool {
	target := normaliseName(name)

	for _, line := range lines {
		match := localZone.FindStringSubmatch(strings.TrimSpace(line))
		if match == nil {
			continue
		}
		zone := fields.Split(strings.TrimSpace(match[1]), -1)[0]
		if normaliseName(zone) == target {
			return true
		}
	}
	return false
}
