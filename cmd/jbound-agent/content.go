package main

import (
	"fmt"
	"slices"
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

		// One directive per line, and that one allowed. Unbound's lexer does not
		// treat a newline as a separator, so `local-data: "..." module-config:
		// "..."` on one physical line is two options; matching only the prefix
		// would take the record and the smuggled directive with it.
		tokens := directiveTokens(trimmed)
		if len(tokens) == 1 && allowedDirective(tokens[0]) {
			continue
		}

		// The line number and the directive, never the whole line. What was
		// sent is not something to copy into a log or a panel message, and the
		// directive alone is what the operator has to remove.
		return fmt.Errorf("line %d is not a record: %s", number+1, offendingName(trimmed, tokens))
	}
	return nil
}

// allowedDirective reports whether one directive keyword, including its colon,
// is one a records file may carry.
func allowedDirective(directive string) bool {
	return slices.Contains(allowedDirectives, directive)
}

// directiveTokens returns the config directives on one line, in order, each a
// keyword ending in a colon that sits outside any quoted string. A record line
// carries exactly one; a second one is a directive smuggled in after the value.
func directiveTokens(line string) []string {
	var tokens []string
	inQuote := false
	start := -1
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '"':
			inQuote = !inQuote
			start = -1
		case inQuote:
			// Inside a value; nothing here is a top level directive.
		case isDirectiveChar(c):
			if start < 0 {
				start = i
			}
		case c == ':' && start >= 0:
			tokens = append(tokens, line[start:i+1])
			start = -1
		default:
			start = -1
		}
	}
	return tokens
}

// isDirectiveChar reports whether c can appear in a directive keyword.
func isDirectiveChar(c byte) bool {
	return c >= 'a' && c <= 'z' ||
		c >= 'A' && c <= 'Z' ||
		c >= '0' && c <= '9' ||
		c == '-' || c == '_'
}

// offendingName picks the directive worth naming in a refusal: the first one
// that is not allowed, or the surplus directive when a line carries more than
// one, or the leading word when the line carries none.
func offendingName(line string, tokens []string) string {
	for _, token := range tokens {
		if !allowedDirective(token) {
			return strings.TrimSuffix(token, ":")
		}
	}
	if len(tokens) > 1 {
		return strings.TrimSuffix(tokens[1], ":")
	}
	return namedDirective(line)
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
