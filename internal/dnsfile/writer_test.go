package dnsfile_test

import (
	"errors"
	"strings"
	"testing"

	"jbound/internal/dnsfile"
)

// mxRecord is one mail exchanger with the preference it was given.
func mxRecord(fqdn, value string, preference int) dnsfile.Record {
	return dnsfile.Record{
		FQDN: fqdn, Type: dnsfile.TypeMX, Value: value, Priority: preference}
}

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
		"mail with the preference it was given": {
			record: mxRecord("mail.example.net", "mx1.example.net", 20),
			want:   `local-data: "mail.example.net. MX 20 mx1.example.net"`,
		},
		// Zero is a legal preference, and it is the one the most preferred
		// exchanger of a zone usually carries. It used to be written as ten.
		"mail with the zero preference": {
			record: mxRecord("mail.example.net", "mx1.example.net", 0),
			want:   `local-data: "mail.example.net. MX 0 mx1.example.net"`,
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

func TestAddRefusesAValueOfTheWrongAddressFamily(t *testing.T) {
	// Unbound cannot load the line, and the file reaches it through one
	// include, so the whole configuration would stop parsing.
	_, err := dnsfile.Add(nil, record("host.example.net", "A", "2001:db8::1"))
	if !errors.Is(err, dnsfile.ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid", err)
	}
}

func TestDeleteRemovesALineOfTheWrongAddressFamily(t *testing.T) {
	// An earlier version of the panel could have written this line, and the
	// panel has to be the way it comes off again.
	content := []byte(`local-data: "host.example.net. A 2001:db8::1"
local-data: "other.example.net. A 192.0.2.11"
`)

	updated, err := dnsfile.Delete(content, record("host.example.net", "A", "2001:db8::1"))
	if err != nil {
		t.Fatalf("Delete returned an error: %v", err)
	}

	if strings.Contains(string(updated), "host.example.net") {
		t.Error("the record survived")
	}
	if !strings.Contains(string(updated), "other.example.net") {
		t.Error("the delete took a record with it")
	}
}

func TestEditReplacesALineOfTheWrongAddressFamily(t *testing.T) {
	content := []byte(`local-data: "host.example.net. A 2001:db8::1"` + "\n")

	updated, err := dnsfile.Edit(content,
		record("host.example.net", "A", "2001:db8::1"),
		record("host.example.net", "A", "192.0.2.10"))
	if err != nil {
		t.Fatalf("Edit returned an error: %v", err)
	}

	if !strings.Contains(string(updated), `"host.example.net. A 192.0.2.10"`) {
		t.Errorf("the correction was not written: %s", updated)
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

// The file is edited by hand on the target, which the package says in several
// places. A record written there in a form the panel does not render was
// listed by the panel and then refused every edit and every delete, with a
// message that sent the operator looking for a conflict on the server.
func TestARecordWrittenByHandCanBeEditedAndDeleted(t *testing.T) {
	forms := map[string]string{
		"no trailing dot": `local-data: "byhand.example.local A 10.0.0.5"`,
		"extra spaces":    `local-data: "byhand.example.local.   A    10.0.0.5"`,
		"a tab":           "local-data: \"byhand.example.local.\tA\t10.0.0.5\"",
		"indented":        `    local-data: "byhand.example.local. A 10.0.0.5"`,
	}
	record := dnsfile.Record{FQDN: "byhand.example.local", Type: dnsfile.TypeA, Value: "10.0.0.5"}

	for name, line := range forms {
		t.Run(name, func(t *testing.T) {
			content := []byte("# managed by the panel\n" + line + "\n")

			updated, err := dnsfile.Edit(content, record,
				dnsfile.Record{FQDN: "byhand.example.local", Type: dnsfile.TypeA, Value: "10.0.0.6"})
			if err != nil {
				t.Fatalf("dnsfile.Edit returned an error: %v", err)
			}
			if !strings.Contains(string(updated), "10.0.0.6") ||
				strings.Contains(string(updated), "10.0.0.5") {
				t.Errorf("the edit did not replace the line:\n%s", updated)
			}

			left, err := dnsfile.Delete(content, record)
			if err != nil {
				t.Fatalf("dnsfile.Delete returned an error: %v", err)
			}
			if strings.Contains(string(left), "byhand.example.local") {
				t.Errorf("the delete left the line behind:\n%s", left)
			}
		})
	}
}

// The same record in another form is the same record, so adding it again is a
// duplicate rather than a second line the resolver has to choose between.
func TestARecordAlreadyInTheFileInAnotherFormIsADuplicate(t *testing.T) {
	content := []byte(`local-data: "byhand.example.local A 10.0.0.5"` + "\n")

	_, err := dnsfile.Add(content, dnsfile.Record{
		FQDN: "byhand.example.local", Type: dnsfile.TypeA, Value: "10.0.0.5"})
	if !errors.Is(err, dnsfile.ErrDuplicate) {
		t.Errorf("dnsfile.Add returned %v, want a duplicate", err)
	}
}

// A record that is genuinely absent still has to be reported as absent, or the
// looser match would turn a stale panel into a silent no-op.
func TestARecordThatIsNotInTheFileIsStillRefused(t *testing.T) {
	content := []byte(`local-data: "other.example.local. A 10.0.0.5"` + "\n")
	missing := dnsfile.Record{FQDN: "byhand.example.local", Type: dnsfile.TypeA, Value: "10.0.0.5"}

	if _, err := dnsfile.Delete(content, missing); !errors.Is(err, dnsfile.ErrNotFound) {
		t.Errorf("dnsfile.Delete returned %v, want not found", err)
	}
	// A different value at the same name is a different record.
	if _, err := dnsfile.Delete(content, dnsfile.Record{
		FQDN: "other.example.local", Type: dnsfile.TypeA, Value: "10.0.0.9",
	}); !errors.Is(err, dnsfile.ErrNotFound) {
		t.Errorf("dnsfile.Delete removed a record with another value: %v", err)
	}
	// So is a different type.
	if _, err := dnsfile.Delete(content, dnsfile.Record{
		FQDN: "other.example.local", Type: dnsfile.TypeAAAA, Value: "10.0.0.5",
	}); !errors.Is(err, dnsfile.ErrNotFound) {
		t.Errorf("dnsfile.Delete removed a record of another type: %v", err)
	}
}

// The preference is part of what the record is, so it decides the match.
func TestAnMXRecordIsMatchedByItsPreference(t *testing.T) {
	content := []byte(`local-data: "example.local MX 10 mx1.example.local"` + "\n")

	if _, err := dnsfile.Delete(content, mxRecord("example.local", "mx1.example.local", 10)); err != nil {
		t.Errorf("dnsfile.Delete returned an error: %v", err)
	}
	if _, err := dnsfile.Delete(content,
		mxRecord("example.local", "mx1.example.local", 20)); !errors.Is(err, dnsfile.ErrNotFound) {
		t.Errorf("dnsfile.Delete removed a record with another preference: %v", err)
	}
}

// The exchanger a zone prefers most is the one written with preference zero,
// and it used to be the one record the panel could neither write nor remove.
func TestTheZeroPreferenceIsARecordOfItsOwn(t *testing.T) {
	content := []byte(`local-data: "example.local. MX 0 mx1.example.local"` + "\n")

	if _, err := dnsfile.Delete(content,
		mxRecord("example.local", "mx1.example.local", 10)); !errors.Is(err, dnsfile.ErrNotFound) {
		t.Errorf("dnsfile.Delete removed the zero preference for a ten: %v", err)
	}

	left, err := dnsfile.Delete(content, mxRecord("example.local", "mx1.example.local", 0))
	if err != nil {
		t.Fatalf("dnsfile.Delete returned an error: %v", err)
	}
	if strings.Contains(string(left), "mx1.example.local") {
		t.Errorf("the record is still there:\n%s", left)
	}
}

// The value written to the file has to be the value that was checked. The line
// is rendered with %q, so anything that renders escaped would land in the file
// as a backslash the value never had, parse back as a different string, and
// then be refused by the validator, leaving a record only a hand edit on the
// target could remove.
func TestATextValueTheWriterWouldEscapeIsRefused(t *testing.T) {
	refused := map[string]string{
		"a vertical tab":     "v=spf1\vall",
		"a null byte":        "v=spf1\x00all",
		"a bell":             "alert\a",
		"an escape":          "\x1b[31mred",
		"a delete":           "text\x7f",
		"invalid utf-8":      "text\xff",
		"a zero width space": "text\u200b",
	}

	for name, value := range refused {
		t.Run(name, func(t *testing.T) {
			record := dnsfile.Record{
				FQDN: "spf.example.local", Type: dnsfile.TypeTXT, Value: value}

			if err := record.Validate(); !errors.Is(err, dnsfile.ErrInvalid) {
				t.Fatalf("Validate returned %v, want a refusal", err)
			}
			if _, err := dnsfile.Add(nil, record); !errors.Is(err, dnsfile.ErrInvalid) {
				t.Errorf("Add returned %v, want a refusal", err)
			}
		})
	}
}

// Everything the validator accepts has to survive the round trip, which is the
// property the refusals above exist to protect.
func TestAnAcceptedTextValueReadsBackUnchanged(t *testing.T) {
	accepted := []string{
		"v=spf1",
		"v=spf1-include:_spf.example.net-all",
		"google-site-verification=abc123",
		"héllo-wörld",
		"日本語",
	}

	for _, value := range accepted {
		t.Run(value, func(t *testing.T) {
			record := dnsfile.Record{
				FQDN: "spf.example.local", Type: dnsfile.TypeTXT, Value: value}
			if err := record.Validate(); err != nil {
				t.Fatalf("Validate refused %q: %v", value, err)
			}

			parsed := dnsfile.Parse([]byte(record.BuildLine()))
			if len(parsed) != 1 {
				t.Fatalf("the line parsed into %d records", len(parsed))
			}
			if parsed[0].Value != value {
				t.Errorf("read back %q, want %q", parsed[0].Value, value)
			}
			// And what came back is still a record the panel can remove.
			if err := parsed[0].ValidateForRemoval(); err != nil {
				t.Errorf("the record it wrote is one it refuses: %v", err)
			}
		})
	}
}
