package dnsfile_test

import (
	"os"
	"path/filepath"
	"testing"

	"unbound-web/internal/dnsfile"
)

// golden is a host entries file holding every shape the parser has to survive.
const golden = `# Unbound host entries, managed by the panel
# comment lines are left alone

local-data: "www.example.net. A 192.0.2.10"
local-data: "ipv6.example.net. AAAA 2001:db8::1"
local-data: "mail.example.net. MX 20 mx1.example.net"
local-data: "alias.example.net. CNAME www.example.net"
local-data: "txt.example.net. TXT hello-world"

# a reverse record the panel does not manage
local-data-ptr: "192.0.2.10 www.example.net."

    local-data: "indented.example.net. A 192.0.2.11"
local-data:"tight.example.net. A 192.0.2.12"

# malformed lines the parser has to skip rather than choke on
local-data: "onlytwo.example.net. A"
local-data: missing quotes here
something-else: "www.example.net. A 192.0.2.99"
local-data: "trailing.example.net. A 192.0.2.13"`

func TestParseReadsEveryShapeOfLine(t *testing.T) {
	records := dnsfile.Parse([]byte(golden))

	want := []dnsfile.Record{
		{Line: 4, FQDN: "www.example.net", Type: "A", Value: "192.0.2.10"},
		{Line: 5, FQDN: "ipv6.example.net", Type: "AAAA", Value: "2001:db8::1"},
		{Line: 6, FQDN: "mail.example.net", Type: "MX", Value: "mx1.example.net", Priority: 20},
		{Line: 7, FQDN: "alias.example.net", Type: "CNAME", Value: "www.example.net"},
		{Line: 8, FQDN: "txt.example.net", Type: "TXT", Value: "hello-world"},
		{Line: 13, FQDN: "indented.example.net", Type: "A", Value: "192.0.2.11"},
		{Line: 14, FQDN: "tight.example.net", Type: "A", Value: "192.0.2.12"},
		{Line: 20, FQDN: "trailing.example.net", Type: "A", Value: "192.0.2.13"},
	}

	if len(records) != len(want) {
		t.Fatalf("got %d records, want %d:\n%+v", len(records), len(want), records)
	}
	for i, expected := range want {
		got := records[i]
		if got.Line != expected.Line || got.FQDN != expected.FQDN || got.Type != expected.Type ||
			got.Value != expected.Value || got.Priority != expected.Priority {
			t.Errorf("record %d = %+v, want %+v", i, got, expected)
		}
		if got.Raw == "" {
			t.Errorf("record %d carries no raw line", i)
		}
	}
}

func TestParseKeepsTheRawLineForEditingAndDeleting(t *testing.T) {
	// An edit and a delete match against what the file holds, so the raw line
	// has to survive the round trip with its indentation trimmed off.
	records := dnsfile.Parse([]byte(`    local-data: "www.example.net. A 192.0.2.10"`))

	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	if records[0].Raw != `local-data: "www.example.net. A 192.0.2.10"` {
		t.Errorf("raw = %q", records[0].Raw)
	}
}

func TestParseReturnsNothingForAnEmptyFile(t *testing.T) {
	for name, content := range map[string]string{
		"empty":    "",
		"newlines": "\n\n\n",
		"comments": "# nothing here\n# and here\n",
	} {
		t.Run(name, func(t *testing.T) {
			if records := dnsfile.Parse([]byte(content)); len(records) != 0 {
				t.Errorf("got %+v, want nothing", records)
			}
		})
	}
}

func TestParseCountsLinesTheWayAnEditorDoes(t *testing.T) {
	// The line number is shown next to the record, so it has to point at the
	// same line the operator sees when they open the file on the target.
	records := dnsfile.Parse([]byte("\n\n\nlocal-data: \"www.example.net. A 192.0.2.10\"\n"))

	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	if records[0].Line != 4 {
		t.Errorf("line = %d, want 4", records[0].Line)
	}
}

func TestParseHandlesWindowsLineEndings(t *testing.T) {
	// The file is edited by hand on the target as well, and one editor there
	// is enough to leave carriage returns behind.
	records := dnsfile.Parse([]byte("local-data: \"www.example.net. A 192.0.2.10\"\r\n"))

	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	if records[0].Value != "192.0.2.10" {
		t.Errorf("value = %q, want the carriage return trimmed", records[0].Value)
	}
}

func TestParseReadsAnMXWithoutAPreference(t *testing.T) {
	// Three fields mean the third one is the value, whatever the type says.
	records := dnsfile.Parse([]byte(`local-data: "mail.example.net. MX mx1.example.net"`))

	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	if records[0].Value != "mx1.example.net" || records[0].Priority != 0 {
		t.Errorf("got %+v", records[0])
	}
}

func TestParseReadsAnMXWhosePreferenceIsNotANumber(t *testing.T) {
	// The operator still has to see what the file holds, so the line survives
	// with a zero preference instead of disappearing.
	records := dnsfile.Parse([]byte(`local-data: "mail.example.net. MX high mx1.example.net"`))

	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	if records[0].Value != "mx1.example.net" || records[0].Priority != 0 {
		t.Errorf("got %+v", records[0])
	}
}

func TestParseMatchesTheSeededTargetFile(t *testing.T) {
	// The development targets are seeded from this file, so a change to it
	// that the parser cannot read would break every integration test.
	seeds, err := filepath.Glob(filepath.Join("..", "..", "docker", "seed", "*.conf"))
	if err != nil || len(seeds) == 0 {
		t.Fatalf("the seed files are not where they belong: %v", err)
	}

	for _, path := range seeds {
		t.Run(filepath.Base(path), func(t *testing.T) {
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("cannot read the seed file: %v", err)
			}

			records := dnsfile.Parse(content)
			if len(records) == 0 {
				t.Fatal("the seed file parses to nothing")
			}
			for _, record := range records {
				if err := record.Validate(); err != nil {
					t.Errorf("the seeded record %q is refused by the panel: %v", record.Raw, err)
				}
				if record.BuildLine() != record.Raw {
					t.Errorf("the seeded record does not round trip:\n  file:  %s\n  panel: %s",
						record.Raw, record.BuildLine())
				}
			}
		})
	}
}

func TestAValueKeepsEveryFieldAfterTheType(t *testing.T) {
	// A multi-word value is normal in this file. An SPF policy cut after its
	// first field is a policy that refuses the sender's own mail, and the
	// truncated record is what the diff compares and what a repair writes.
	const content = `local-data: "example.net. TXT v=spf1 include:_spf.example.net ~all"
local-data: "mail.example.net. MX 10 mx1.example.net"
local-data: "www.example.net. A 192.0.2.10"
`

	records := dnsfile.Parse([]byte(content))
	if len(records) != 3 {
		t.Fatalf("got %d records, want 3", len(records))
	}

	if want := "v=spf1 include:_spf.example.net ~all"; records[0].Value != want {
		t.Errorf("TXT value = %q, want %q", records[0].Value, want)
	}
	if records[1].Value != "mx1.example.net" || records[1].Priority != 10 {
		t.Errorf("MX = %q / %d", records[1].Value, records[1].Priority)
	}
	if records[2].Value != "192.0.2.10" {
		t.Errorf("A value = %q", records[2].Value)
	}
}

func TestAMultiWordMXTargetKeepsEveryFieldToo(t *testing.T) {
	// The preference sits between the type and the value, so the join has to
	// start one field further along.
	records := dnsfile.Parse([]byte(`local-data: "example.net. MX 20 a b c"` + "\n"))
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	if records[0].Value != "a b c" || records[0].Priority != 20 {
		t.Errorf("got %q / %d", records[0].Value, records[0].Priority)
	}
}
