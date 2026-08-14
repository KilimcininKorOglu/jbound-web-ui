// Package dnsfile reads and writes the Unbound host entries file.
//
// Everything here is a pure function over a byte slice. The file arrives from
// a managed server over SSH and leaves the same way, so knowing nothing about
// files or networks keeps the rules testable against fixed content.
package dnsfile

import (
	"regexp"
	"strconv"
	"strings"
)

// Record is one local-data line of the host entries file.
type Record struct {
	// Line is the one based position in the file the record was read from.
	Line int

	FQDN string
	Type string

	// Value is the address for A and AAAA, the target for CNAME and MX, and
	// the text for TXT.
	Value string

	// Priority carries the MX preference and stays zero for every other type.
	Priority int

	// Raw is the trimmed line as it stands in the file, which is what an edit
	// and a delete match against.
	Raw string
}

// localData matches a host entries line and captures what the quotes hold.
var localData = regexp.MustCompile(`^local-data:\s*"([^"]+)"`)

// fields splits the quoted part on any run of whitespace.
var fields = regexp.MustCompile(`\s+`)

// Parse reads every record of a host entries file.
//
// A line that does not fit is skipped rather than reported. The file is edited
// by hand on the target as well, and refusing to show the records because one
// line is malformed would leave the operator with nothing to work from.
func Parse(content []byte) []Record {
	var records []Record

	for number, raw := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(raw)

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// A ptr record is the reverse of a record the panel manages, so it is
		// left where it is.
		if strings.HasPrefix(line, "local-data-ptr:") {
			continue
		}

		match := localData.FindStringSubmatch(line)
		if match == nil {
			continue
		}

		parts := fields.Split(strings.TrimSpace(match[1]), -1)
		if len(parts) < 3 {
			continue
		}

		record := Record{
			Line: number + 1,
			FQDN: strings.TrimSuffix(parts[0], "."),
			Type: parts[1],
			Raw:  line,
		}

		if record.Type == TypeMX && len(parts) >= 4 {
			// The preference sits between the type and the target, so the
			// value is one field further along. A preference that is not a
			// number reads as zero rather than dropping the line, so the
			// operator still sees what the file holds.
			if priority, err := strconv.Atoi(parts[2]); err == nil {
				record.Priority = priority
			}
			record.Value = strings.Join(parts[3:], " ")
		} else {
			// Everything after the type, not just the next field. A TXT value
			// is regularly several words, and an SPF policy cut after its
			// first one is a policy that refuses the sender's own mail.
			record.Value = strings.Join(parts[2:], " ")
		}

		records = append(records, record)
	}
	return records
}
