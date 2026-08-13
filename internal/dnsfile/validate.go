package dnsfile

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

// The record types the panel manages. Anything else in the file is left alone.
//
// Source: core/functions.php::322.
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
//
// Source: core/functions.php::330.
const DefaultMXPriority = 10

// ErrInvalid marks a rejected record, which a handler answers with 422 rather
// than 500.
var ErrInvalid = errors.New("invalid record")

// namePattern is what a name may hold, for both the record and its value.
//
// Source: core/functions.php::308 and 317. It is deliberately permissive: the
// file is also edited by hand on the target, and a stricter rule here would
// refuse records the resolver itself accepts.
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

// ValidateRecordType reports whether the panel manages a type.
func ValidateRecordType(recordType string) error {
	if !slices.Contains(Types, recordType) {
		return fmt.Errorf("%w: the type must be one of %s", ErrInvalid, strings.Join(Types, ", "))
	}
	return nil
}

// Validate reports every problem of a record in one pass.
//
// The quote and the whitespace checks have no counterpart in the reference
// project. A value holding either would produce a line the parser reads back
// differently, so the record would survive the write and vanish from the view.
func (r Record) Validate() error {
	var problems []string

	if err := ValidateFQDN(r.FQDN); err != nil {
		problems = append(problems, message(err))
	}
	if err := ValidateRecordType(r.Type); err != nil {
		problems = append(problems, message(err))
	}

	switch r.Type {
	case TypeTXT:
		if err := validateText(r.Value); err != nil {
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
func validateText(value string) error {
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
	}
	return nil
}

// message strips the wrapper so several problems read as one sentence.
func message(err error) string {
	return strings.TrimPrefix(err.Error(), ErrInvalid.Error()+": ")
}
