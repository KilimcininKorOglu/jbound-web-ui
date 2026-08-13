package dnsfile

import (
	"errors"
	"fmt"
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
// Source: core/functions.php::325-332. The trailing dot makes the name
// absolute, which is what Unbound expects.
func (r Record) BuildLine() string {
	fqdn := strings.TrimSuffix(r.FQDN, ".") + "."

	if r.Type == TypeMX {
		priority := r.Priority
		if priority == 0 {
			priority = DefaultMXPriority
		}
		return fmt.Sprintf("local-data: %q", fmt.Sprintf("%s %s %d %s", fqdn, r.Type, priority, r.Value))
	}
	return fmt.Sprintf("local-data: %q", fmt.Sprintf("%s %s %s", fqdn, r.Type, r.Value))
}

// Add appends a record to the file.
//
// Unlike the reference project, the content is joined through a line split
// rather than a raw append. A file whose last line has no newline would
// otherwise swallow the new record into it.
func Add(content []byte, record Record) ([]byte, error) {
	if err := record.Validate(); err != nil {
		return nil, err
	}

	line := record.BuildLine()
	lines := split(content)

	if contains(lines, line) {
		return nil, fmt.Errorf("%w: %s", ErrDuplicate, line)
	}
	return join(append(lines, line)), nil
}

// Edit replaces one record with another.
//
// Every matching line is replaced, which is what the reference project does.
// A file that holds the same record twice is a mistake somebody made by hand,
// and leaving one of the two behind would look like the edit did not work.
func Edit(content []byte, old, updated Record) ([]byte, error) {
	if err := old.Validate(); err != nil {
		return nil, err
	}
	if err := updated.Validate(); err != nil {
		return nil, err
	}

	oldLine := old.BuildLine()
	newLine := updated.BuildLine()

	lines := split(content)
	replaced := 0
	for i, line := range lines {
		if strings.TrimSpace(line) == oldLine {
			lines[i] = newLine
			replaced++
		}
	}
	if replaced == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, oldLine)
	}
	return join(lines), nil
}

// Delete removes every line that holds a record.
//
// Source: core/functions.php::391-404. The comparison is against the trimmed
// line, so indentation on the target does not hide a record from the panel.
func Delete(content []byte, record Record) ([]byte, error) {
	if err := record.Validate(); err != nil {
		return nil, err
	}

	target := record.BuildLine()
	lines := split(content)

	kept := make([]string, 0, len(lines))
	removed := 0
	for _, line := range lines {
		if strings.TrimSpace(line) == target {
			removed++
			continue
		}
		kept = append(kept, line)
	}
	if removed == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, target)
	}
	return join(kept), nil
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

// contains reports whether a line is already in the file.
func contains(lines []string, target string) bool {
	for _, line := range lines {
		if strings.TrimSpace(line) == target {
			return true
		}
	}
	return false
}
