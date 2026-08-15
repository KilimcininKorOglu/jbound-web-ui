package dnsfile

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// ErrNotFound marks an edit or a delete whose line is not in the file.
//
// It is its own class because it usually means the file changed on the target
// since the panel last read it, which is something the operator has to know
// rather than a fault of the request.
var ErrNotFound = errors.New("the record is not in the file")

// ErrDuplicate marks an addition that is already in the file.
var ErrDuplicate = errors.New("the record is already in the file")

// BuildLine renders one record the way the file holds it.
//
// The trailing dot makes the name absolute, which is what Unbound expects.
func (r Record) BuildLine() string {
	fqdn := strings.TrimSuffix(r.FQDN, ".") + "."

	if IsPolicy(r.Type) {
		// A behaviour opens a zone rather than carrying data, and the type sits
		// outside the quotes, which is the form Unbound documents and the one
		// EnsureZone already writes.
		return fmt.Sprintf("local-zone: %q %s", fqdn, zoneTypeFor(r.Type))
	}

	if r.Type == TypeMX {
		// The preference is written as it stands. Zero is a legal preference,
		// and it is the one the most preferred mail exchanger of a zone
		// usually carries, so substituting a default here would make that
		// record the one the panel cannot manage.
		return fmt.Sprintf("local-data: %q",
			fmt.Sprintf("%s %s %d %s", fqdn, r.Type, r.Priority, r.Value))
	}
	return fmt.Sprintf("local-data: %q", fmt.Sprintf("%s %s %s", fqdn, r.Type, r.Value))
}

// matches reports whether one line of the file holds this record.
//
// The line is read back through the parser rather than compared against
// BuildLine. The file is edited by hand on the target as well, and the parser
// accepts two forms BuildLine renders differently: a name without the trailing
// dot, and any run of whitespace between the fields. Rebuilding the line would
// hide exactly those records from an edit and a delete, while the panel goes
// on listing them.
func (r Record) matches(line string) bool {
	parsed := Parse([]byte(line))
	if len(parsed) != 1 {
		return false
	}
	other := parsed[0]

	if strings.TrimSuffix(r.FQDN, ".") != other.FQDN ||
		r.Type != other.Type || r.Value != other.Value {
		return false
	}
	if r.Type == TypeMX {
		return r.Priority == other.Priority
	}
	return true
}

// Add appends a record to the file.
//
// The content is joined through a line split rather than appended to. A file
// whose last line has no newline would otherwise swallow the new record.
func Add(content []byte, record Record) ([]byte, error) {
	if err := record.Validate(); err != nil {
		return nil, err
	}

	line := record.BuildLine()
	lines := split(content)

	if contains(lines, record) {
		return nil, fmt.Errorf("%w: %s", ErrDuplicate, line)
	}
	// One name, one zone line. A second one for the same name leaves which of
	// the two the resolver honours to the resolver, and the panel would show
	// both while only one of them decides the answer.
	if IsPolicy(record.Type) && declaresName(lines, record.FQDN) {
		return nil, fmt.Errorf("%w: the file already opens a zone for %s",
			ErrDuplicate, record.FQDN)
	}
	return join(append(lines, line)), nil
}

// Edit replaces one record with another.
//
// Every matching line is replaced. A file that holds the same record twice is
// a mistake somebody made by hand, and leaving one of the two behind would
// look like the edit did not work.
func Edit(content []byte, old, updated Record) ([]byte, error) {
	if err := old.ValidateForRemoval(); err != nil {
		return nil, err
	}
	if err := updated.Validate(); err != nil {
		return nil, err
	}

	newLine := updated.BuildLine()

	lines := split(content)
	replaced := 0
	for i, line := range lines {
		if old.matches(line) {
			lines[i] = newLine
			replaced++
		}
	}
	if replaced == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, old.BuildLine())
	}
	return join(lines), nil
}

// Delete removes every line that holds a record.
//
// The comparison is against the trimmed line, so indentation on the target
// does not hide a record from the panel.
func Delete(content []byte, record Record) ([]byte, error) {
	if err := record.ValidateForRemoval(); err != nil {
		return nil, err
	}

	lines := split(content)

	kept := make([]string, 0, len(lines))
	removed := 0
	for _, line := range lines {
		if record.matches(line) {
			removed++
			continue
		}
		kept = append(kept, line)
	}
	if removed == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, record.BuildLine())
	}
	return join(kept), nil
}

// ClauseHeader opens the Unbound clause the records belong to.
const ClauseHeader = "server:"

// EnsureHeader puts the clause header at the top of the file.
//
// A local-data line is only legal inside a server clause, so without a header
// of its own the file can only be included from inside one. That makes the
// position of the include line in the main configuration something the panel
// would have to reason about on every target. With the header the file stands
// on its own and the include can go anywhere, which is what lets the panel
// repair a missing one by appending a single line.
//
// Unbound allows a server clause to be opened more than once, so the header is
// safe even where the include already sits inside one.
func EnsureHeader(content []byte) []byte {
	lines := split(content)
	for _, line := range lines {
		if strings.TrimSpace(line) == ClauseHeader {
			return content
		}
	}
	return join(append([]string{ClauseHeader}, lines...))
}

// split breaks the file into lines and drops the empty tail a trailing newline
// leaves behind, so the tail is decided in one place instead of by whoever
// wrote the file last.
func split(content []byte) []string {
	if len(content) == 0 {
		return nil
	}

	text := strings.ReplaceAll(string(content), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// join writes the lines back with a trailing newline, which is what every
// other tool that reads this file expects.
func join(lines []string) []byte {
	if len(lines) == 0 {
		return nil
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

// contains reports whether the file already holds a record.
//
// It matches the way an edit and a delete do, so a record that is in the file
// in another form is refused as the duplicate it is rather than written twice.
func contains(lines []string, record Record) bool {
	return slices.ContainsFunc(lines, record.matches)
}
