package dnsfile

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The record types the panel manages. Anything else in the file is left alone.
const (
	TypeA     = "A"
	TypeAAAA  = "AAAA"
	TypeMX    = "MX"
	TypeCNAME = "CNAME"
	TypeTXT   = "TXT"
)

// Types lists the managed record types in the order the form offers them.
var Types = []string{TypeA, TypeAAAA, TypeMX, TypeCNAME, TypeTXT}

// DefaultMXPriority is what an MX record gets when nobody chose a preference.
const DefaultMXPriority = 10

// ErrInvalid marks a rejected record, which a handler answers with 422 rather
// than 500.
var ErrInvalid = errors.New("invalid record")

// namePattern is what a name may hold, for both the record and its value.
//
// It is deliberately permissive: the file is also edited by hand on the
// target, and a stricter rule here would refuse records the resolver accepts.
var namePattern = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,253}$`)

// ValidateFQDN reports whether a name can be written to the file.
func ValidateFQDN(fqdn string) error {
	if !namePattern.MatchString(fqdn) {
		return fmt.Errorf("%w: the name may hold letters, digits, dot, dash and underscore", ErrInvalid)
	}
	return nil
}

// ValidateIPOrHostname reports whether a value can be written to the file.
//
// An address is accepted as it stands. Anything else has to read as a name,
// which is what a CNAME or an MX target is.
func ValidateIPOrHostname(value string) error {
	if _, err := netip.ParseAddr(value); err == nil {
		return nil
	}
	if !namePattern.MatchString(value) {
		return fmt.Errorf("%w: the value is neither an address nor a name", ErrInvalid)
	}
	return nil
}

// validateAddress reports whether a value is an address of the family its type
// declares.
//
// Unbound refuses to load a line whose family contradicts the type, and the
// whole file arrives through one include, so a single mixed line stops the
// resolver from reading any of it.
func validateAddress(recordType, value string) error {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return fmt.Errorf("%w: an %s record needs an address", ErrInvalid, recordType)
	}
	if addr.Zone() != "" {
		return fmt.Errorf("%w: the address may not carry an interface zone", ErrInvalid)
	}

	switch recordType {
	case TypeA:
		if !addr.Is4() {
			return fmt.Errorf("%w: an A record needs an IPv4 address", ErrInvalid)
		}
	case TypeAAAA:
		// A v4-mapped address reads as IPv6 here and as four dotted numbers in
		// the file, which is not what an AAAA record holds.
		if !addr.Is6() || addr.Is4In6() {
			return fmt.Errorf("%w: an AAAA record needs an IPv6 address", ErrInvalid)
		}
	}
	return nil
}

// ValidateRecordType reports whether the panel manages a type.
func ValidateRecordType(recordType string) error {
	if !slices.Contains(Types, recordType) {
		return fmt.Errorf("%w: the type must be one of %s", ErrInvalid, strings.Join(Types, ", "))
	}
	return nil
}

// Validate reports every problem of a record in one pass.
//
// A value holding a quote or whitespace would produce a line the parser reads
// back differently, so the record would survive the write and then vanish from
// the view.
func (r Record) Validate() error {
	return r.validate(true)
}

// ValidateForRemoval reports whether a record can be taken out of a file.
//
// The address family is not checked here. A line whose family contradicts its
// type is exactly the line an operator has to remove, and this path writes the
// value nowhere: it only names which line to drop.
func (r Record) ValidateForRemoval() error {
	return r.validate(false)
}

func (r Record) validate(family bool) error {
	var problems []string

	if err := ValidateFQDN(r.FQDN); err != nil {
		problems = append(problems, message(err))
	}
	if err := ValidateRecordType(r.Type); err != nil {
		problems = append(problems, message(err))
	}

	switch {
	case r.Type == TypeTXT:
		if err := validateText(r.Value); err != nil {
			problems = append(problems, message(err))
		}
	case family && (r.Type == TypeA || r.Type == TypeAAAA):
		if err := validateAddress(r.Type, r.Value); err != nil {
			problems = append(problems, message(err))
		}
	default:
		if err := ValidateIPOrHostname(r.Value); err != nil {
			problems = append(problems, message(err))
		}
	}

	if r.Type == TypeMX && (r.Priority < 0 || r.Priority > 65535) {
		problems = append(problems, "the preference must be between 0 and 65535")
	}

	if len(problems) > 0 {
		return fmt.Errorf("%w: %s", ErrInvalid, strings.Join(problems, "; "))
	}
	return nil
}

// validateText covers the one type whose value is free text.
//
// The file format quotes the whole record, so a quote inside the text would
// end the record early and the rest would become something else entirely.
//
// The rule is that the value written to the file has to be the value that was
// checked. The line is rendered with %q, which escapes a quote, a backslash,
// every non printable rune and every byte that is not valid UTF-8. Each of
// those would land in the file as a backslash the value never had, parse back
// as a different string, and then be refused by this very function, leaving a
// record only a hand edit on the target could remove.
func validateText(value string) error {
	notPrintable := func(r rune) bool { return !unicode.IsPrint(r) }

	switch {
	case value == "":
		return fmt.Errorf("%w: the text is empty", ErrInvalid)
	case len(value) > 255:
		return fmt.Errorf("%w: the text is longer than 255 characters", ErrInvalid)
	case strings.ContainsAny(value, "\"\\\n\r"):
		// A backslash is written back escaped, so the record would not read
		// the same way twice.
		return fmt.Errorf("%w: the text may not hold a quote, a backslash or a line break", ErrInvalid)
	case strings.ContainsAny(value, " \t"):
		// A space would split into several fields and the parser would read
		// only the first one back.
		return fmt.Errorf("%w: the text may not hold whitespace", ErrInvalid)
	case !utf8.ValidString(value):
		return fmt.Errorf("%w: the text is not valid UTF-8", ErrInvalid)
	case strings.ContainsFunc(value, notPrintable):
		return fmt.Errorf("%w: the text may only hold printable characters", ErrInvalid)
	}
	return nil
}

// message strips the wrapper so several problems read as one sentence.
func message(err error) string {
	return strings.TrimPrefix(err.Error(), ErrInvalid.Error()+": ")
}
