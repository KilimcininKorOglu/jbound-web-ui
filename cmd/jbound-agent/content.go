package main

import (
	"fmt"
	"strings"
)

// The directives the records file may carry.
//
// Everything here describes an answer for a name. Nothing here changes how the
// resolver runs, which is the whole reason the list exists.
var allowedDirectives = []string{
	"local-data:",
	"local-data-ptr:",
	"local-zone:",
}

// maxNamedDirective bounds what a refusal quotes back.
const maxNamedDirective = 40

// validateContent refuses anything but records.
//
// The file is included inside a server clause, so a directive written into it
// is a directive in the resolver's own configuration. Unbound reads that
// configuration as root before it drops to its own account, and the Debian
// build carries the python module, so a single line here is a way to run code
// as root on the host.
//
// The agent therefore refuses to write what it was sent unless every line is a
// record. That turns the token from a credential that can rewrite the resolver
// into one that can write DNS records, which is all the panel ever asks of it.
//
// The SSH path has no equivalent check and needs none: the credential there is
// a key with sudoers rules on tee and mv, which is root on that host by
// construction. The agent exists to be narrower than that, and a write it does
// not read is not narrower at all.
func validateContent(data []byte) error {
	for number, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)

		switch {
		case trimmed == "":
			continue
		case strings.HasPrefix(trimmed, "#"):
			continue
		case trimmed == clauseHeader:
			continue
		}

		if allowedDirective(trimmed) {
			continue
		}

		// The line number and the directive, never the whole line. What was
		// sent is not something to copy into a log or a panel message, and the
		// directive alone is what the operator has to remove.
		return fmt.Errorf("line %d is not a record: %s", number+1, namedDirective(trimmed))
	}
	return nil
}

func allowedDirective(line string) bool {
	for _, directive := range allowedDirectives {
		if strings.HasPrefix(line, directive) {
			return true
		}
	}
	return false
}

// namedDirective is the part of a refused line worth repeating.
func namedDirective(line string) string {
	name, _, found := strings.Cut(line, ":")
	if !found {
		name = line
	}
	name = strings.TrimSpace(name)
	if len(name) > maxNamedDirective {
		name = name[:maxNamedDirective]
	}
	return name
}
