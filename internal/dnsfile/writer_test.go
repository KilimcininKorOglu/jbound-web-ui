package dnsfile_test

import (
	"errors"
	"strings"
	"testing"

	"unbound-web/internal/dnsfile"
)

func record(fqdn, recordType, value string) dnsfile.Record {
	return dnsfile.Record{FQDN: fqdn, Type: recordType, Value: value}
}

func TestBuildLineRendersEveryType(t *testing.T) {
	cases := map[string]struct {
		record dnsfile.Record
		want   string
	}{
		"address": {
			record: record("www.example.net", "A", "192.0.2.10"),
			want:   `local-data: "www.example.net. A 192.0.2.10"`,
		},
		"ipv6": {
			record: record("ipv6.example.net", "AAAA", "2001:db8::1"),
			want:   `local-data: "ipv6.example.net. AAAA 2001:db8::1"`,
		},
		"alias": {
			record: record("alias.example.net", "CNAME", "www.example.net"),
			want:   `local-data: "alias.example.net. CNAME www.example.net"`,
		},
		"text": {
			record: record("txt.example.net", "TXT", "hello-world"),
			want:   `local-data: "txt.example.net. TXT hello-world"`,
		},
		"mail with a preference": {
			record: dnsfile.Record{FQDN: "mail.example.net", Type: "MX",
				Value: "mx1.example.net", Priority: 20},
			want: `local-data: "mail.example.net. MX 20 mx1.example.net"`,
		},
		"mail without a preference": {
			record: record("mail.example.net", "MX", "mx1.example.net"),
			want:   `local-data: "mail.example.net. MX 10 mx1.example.net"`,
		},
		"name that already ends in a dot": {
			record: record("www.example.net.", "A", "192.0.2.10"),
			want:   `local-data: "www.example.net. A 192.0.2.10"`,
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			if got := test.record.BuildLine(); got != test.want {
				t.Errorf("got  %s\nwant %s", got, test.want)
			}
		})
	}
}

func TestEveryBuiltLineParsesBackToTheSameRecord(t *testing.T) {
	// The panel writes a line and reads it back on the next refresh. A record
	// that does not survive that trip would look like somebody changed the
	// file by hand.
	originals := []dnsfile.Record{
		record("www.example.net", "A", "192.0.2.10"),
		record("ipv6.example.net", "AAAA", "2001:db8::1"),
		record("alias.example.net", "CNAME", "www.example.net"),
		record("txt.example.net", "TXT", "hello-world"),
		{FQDN: "mail.example.net", Type: "MX", Value: "mx1.example.net", Priority: 20},
	}

	for _, original := range originals {
		t.Run(original.Type, func(t *testing.T) {
			parsed := dnsfile.Parse([]byte(original.BuildLine()))
			if len(parsed) != 1 {
				t.Fatalf("the line parses to %d records", len(parsed))
			}
			got := parsed[0]
			if got.FQDN != original.FQDN || got.Type != original.Type ||
				got.Value != original.Value || got.Priority != original.Priority {
				t.Errorf("got %+v, want %+v", got, original)
			}
		})
	}
}

func TestAddAppendsTheRecord(t *testing.T) {
	content := []byte("# managed by the panel\nlocal-data: \"www.example.net. A 192.0.2.10\"\n")

	updated, err := dnsfile.Add(content, record("new.example.net", "A", "192.0.2.20"))
	if err != nil {
		t.Fatalf("Add returned an error: %v", err)
	}

	lines := strings.Split(strings.TrimSuffix(string(updated), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3:\n%s", len(lines), updated)
	}
	if lines[2] != `local-data: "new.example.net. A 192.0.2.20"` {
		t.Errorf("the record was not appended: %q", lines[2])
	}
	if lines[0] != "# managed by the panel" {
		t.Error("the comment did not survive")
	}
}

func TestAddKeepsTheLastLineIntactWhenTheFileHasNoTrailingNewline(t *testing.T) {
	// A raw append would join the new record onto the last line and both
	// records would disappear from the view at once.
	content := []byte(`local-data: "www.example.net. A 192.0.2.10"`)

	updated, err := dnsfile.Add(content, record("new.example.net", "A", "192.0.2.20"))
	if err != nil {
		t.Fatalf("Add returned an error: %v", err)
	}

	if got := len(dnsfile.Parse(updated)); got != 2 {
		t.Fatalf("the file parses to %d records, want 2:\n%s", got, updated)
	}
	if !strings.HasSuffix(string(updated), "\n") {
		t.Error("the file does not end with a newline")
	}
}

func TestAddWritesTheFirstRecordOfAnEmptyFile(t *testing.T) {
	updated, err := dnsfile.Add(nil, record("first.example.net", "A", "192.0.2.10"))
	if err != nil {
		t.Fatalf("Add returned an error: %v", err)
	}

	if string(updated) != "local-data: \"first.example.net. A 192.0.2.10\"\n" {
		t.Errorf("got %q", updated)
	}
}

func TestAddRefusesARecordThatIsAlreadyThere(t *testing.T) {
	// Two identical lines resolve the same way, so the duplicate would be
	// invisible in the resolver and confusing in the panel.
	content := []byte("local-data: \"www.example.net. A 192.0.2.10\"\n")

	_, err := dnsfile.Add(content, record("www.example.net", "A", "192.0.2.10"))
	if !errors.Is(err, dnsfile.ErrDuplicate) {
		t.Fatalf("got %v, want ErrDuplicate", err)
	}
}

func TestAddRefusesAnInvalidRecord(t *testing.T) {
	_, err := dnsfile.Add(nil, record("no spaces allowed", "A", "192.0.2.10"))
	if !errors.Is(err, dnsfile.ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid", err)
	}
}

func TestEditReplacesTheRecordAndLeavesTheRestAlone(t *testing.T) {
	content := []byte(`# managed by the panel
local-data: "www.example.net. A 192.0.2.10"
local-data: "other.example.net. A 192.0.2.11"
`)

	updated, err := dnsfile.Edit(content,
		record("www.example.net", "A", "192.0.2.10"),
		record("www.example.net", "A", "192.0.2.99"))
	if err != nil {
		t.Fatalf("Edit returned an error: %v", err)
	}

	text := string(updated)
	if !strings.Contains(text, `local-data: "www.example.net. A 192.0.2.99"`) {
		t.Error("the new record is not in the file")
	}
	if strings.Contains(text, "192.0.2.10") {
		t.Error("the old record survived")
	}
	if !strings.Contains(text, "other.example.net") || !strings.Contains(text, "# managed by the panel") {
		t.Error("the edit touched a line it had no business touching")
	}
}

func TestEditReplacesEveryCopyOfTheRecord(t *testing.T) {
	// A file holding the same record twice is a mistake somebody made by hand.
	// Leaving one copy behind would look like the edit did not work.
	content := []byte(`local-data: "www.example.net. A 192.0.2.10"
local-data: "www.example.net. A 192.0.2.10"
`)

	updated, err := dnsfile.Edit(content,
		record("www.example.net", "A", "192.0.2.10"),
		record("www.example.net", "A", "192.0.2.99"))
	if err != nil {
		t.Fatalf("Edit returned an error: %v", err)
	}

	if strings.Contains(string(updated), "192.0.2.10") {
		t.Errorf("a copy of the old record survived:\n%s", updated)
	}
}

func TestEditMatchesAnIndentedLine(t *testing.T) {
	content := []byte("    local-data: \"www.example.net. A 192.0.2.10\"\n")

	updated, err := dnsfile.Edit(content,
		record("www.example.net", "A", "192.0.2.10"),
		record("www.example.net", "A", "192.0.2.99"))
	if err != nil {
		t.Fatalf("Edit returned an error: %v", err)
	}
	if strings.Contains(string(updated), "192.0.2.10") {
		t.Error("the indented record was not matched")
	}
}

func TestEditLeavesACommentedOutRecordAlone(t *testing.T) {
	// Somebody commented that line out on purpose. Editing it would bring the
	// record back to life without anybody asking for it.
	content := []byte(`# local-data: "www.example.net. A 192.0.2.10"
local-data: "other.example.net. A 192.0.2.11"
`)

	_, err := dnsfile.Edit(content,
		record("www.example.net", "A", "192.0.2.10"),
		record("www.example.net", "A", "192.0.2.99"))
	if !errors.Is(err, dnsfile.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestEditReportsARecordThatIsNotThere(t *testing.T) {
	// It usually means the file changed on the target since the panel read it.
	content := []byte("local-data: \"other.example.net. A 192.0.2.11\"\n")

	_, err := dnsfile.Edit(content,
		record("www.example.net", "A", "192.0.2.10"),
		record("www.example.net", "A", "192.0.2.99"))
	if !errors.Is(err, dnsfile.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestEditRefusesAnInvalidReplacement(t *testing.T) {
	content := []byte("local-data: \"www.example.net. A 192.0.2.10\"\n")

	_, err := dnsfile.Edit(content,
		record("www.example.net", "A", "192.0.2.10"),
		record("www.example.net", "SRV", "192.0.2.99"))
	if !errors.Is(err, dnsfile.ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid", err)
	}
}

func TestDeleteRemovesTheRecord(t *testing.T) {
	content := []byte(`# managed by the panel
local-data: "www.example.net. A 192.0.2.10"
local-data: "other.example.net. A 192.0.2.11"
`)

	updated, err := dnsfile.Delete(content, record("www.example.net", "A", "192.0.2.10"))
	if err != nil {
		t.Fatalf("Delete returned an error: %v", err)
	}

	if strings.Contains(string(updated), "www.example.net") {
		t.Error("the record survived")
	}
	if !strings.Contains(string(updated), "other.example.net") {
		t.Error("the delete took a record with it")
	}
	if !strings.HasSuffix(string(updated), "\n") {
		t.Error("the file does not end with a newline")
	}
}

func TestDeleteRemovesEveryCopyOfTheRecord(t *testing.T) {
	content := []byte(`local-data: "www.example.net. A 192.0.2.10"
    local-data: "www.example.net. A 192.0.2.10"
`)

	updated, err := dnsfile.Delete(content, record("www.example.net", "A", "192.0.2.10"))
	if err != nil {
		t.Fatalf("Delete returned an error: %v", err)
	}
	if len(dnsfile.Parse(updated)) != 0 {
		t.Errorf("a copy survived:\n%s", updated)
	}
}

func TestDeleteEmptiesAFileThatHeldOneRecord(t *testing.T) {
	content := []byte("local-data: \"www.example.net. A 192.0.2.10\"\n")

	updated, err := dnsfile.Delete(content, record("www.example.net", "A", "192.0.2.10"))
	if err != nil {
		t.Fatalf("Delete returned an error: %v", err)
	}
	if len(updated) != 0 {
		t.Errorf("got %q, want an empty file", updated)
	}
}

func TestDeleteReportsARecordThatIsNotThere(t *testing.T) {
	content := []byte("local-data: \"other.example.net. A 192.0.2.11\"\n")

	_, err := dnsfile.Delete(content, record("www.example.net", "A", "192.0.2.10"))
	if !errors.Is(err, dnsfile.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestWritingNeverTouchesTheCallersContent(t *testing.T) {
	// The same file is written to several servers in one operation, so a
	// function that edited the slice in place would corrupt the next write.
	original := []byte("local-data: \"www.example.net. A 192.0.2.10\"\n")
	before := string(original)

	if _, err := dnsfile.Add(original, record("new.example.net", "A", "192.0.2.20")); err != nil {
		t.Fatalf("Add returned an error: %v", err)
	}
	if _, err := dnsfile.Edit(original,
		record("www.example.net", "A", "192.0.2.10"),
		record("www.example.net", "A", "192.0.2.99")); err != nil {
		t.Fatalf("Edit returned an error: %v", err)
	}
	if _, err := dnsfile.Delete(original, record("www.example.net", "A", "192.0.2.10")); err != nil {
		t.Fatalf("Delete returned an error: %v", err)
	}

	if string(original) != before {
		t.Errorf("the content changed under the caller:\n%s", original)
	}
}
