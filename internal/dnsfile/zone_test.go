package dnsfile_test

import (
	"strings"
	"testing"

	"jbound/internal/dnsfile"
)

func TestTheParentZoneIsTheNameWithoutItsFirstLabel(t *testing.T) {
	for name, want := range map[string]string{
		"www.example.local":   "example.local",
		"a.b.example.local":   "b.example.local",
		"www.example.local.":  "example.local",
		"example.local":       "local",
		"local":               "",
		"":                    "",
		" www.example.local ": "example.local",
	} {
		t.Run(name, func(t *testing.T) {
			if got := dnsfile.ParentZone(name); got != want {
				t.Errorf("ParentZone(%q) = %q, want %q", name, got, want)
			}
		})
	}
}

func TestAddingARecordDeclaresItsParentZone(t *testing.T) {
	// Unbound generates a transparent zone for local data it has no zone for,
	// so the line changes nothing in an ordinary file. It changes everything
	// under a parent the operator declared static: there the record is written
	// and the resolver answers something else.
	content := dnsfile.EnsureZone(nil, "www.example.local")

	if want := `local-zone: "example.local." transparent`; !strings.Contains(string(content), want) {
		t.Errorf("got:\n%s\nwant a line reading %s", content, want)
	}
}

func TestTheZoneIsDeclaredOnceHoweverManyRecordsItHolds(t *testing.T) {
	content := dnsfile.EnsureZone(nil, "www.example.local")
	content = dnsfile.EnsureZone(content, "ns1.example.local")

	if got := strings.Count(string(content), "local-zone:"); got != 1 {
		t.Errorf("the file carries %d zone lines, want 1:\n%s", got, content)
	}
}

func TestADeclaredZoneIsLeftAloneWhateverItsType(t *testing.T) {
	// An operator who wrote static wrote it. Rewriting the zone of a record
	// being added is a decision about every other name under it.
	for name, existing := range map[string]string{
		"type outside the quotes": `local-zone: "example.local." static` + "\n",
		"type inside the quotes":  `local-zone: "example.local. redirect"` + "\n",
		"no trailing dot":         `local-zone: "example.local" static` + "\n",
		"indented":                `    local-zone: "example.local." static` + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			content := dnsfile.EnsureZone([]byte(existing), "www.example.local")

			if string(content) != existing {
				t.Errorf("the file changed:\n%s", content)
			}
		})
	}
}

func TestAZoneOfAnotherNameDoesNotCountAsDeclared(t *testing.T) {
	const existing = `local-zone: "other.local." transparent` + "\n"

	content := dnsfile.EnsureZone([]byte(existing), "www.example.local")
	if !strings.Contains(string(content), `"example.local."`) {
		t.Errorf("the zone of the record was not declared:\n%s", content)
	}
}

func TestANameWithOneLabelDeclaresNoZone(t *testing.T) {
	// There is no parent to declare, and writing a zone for the root would
	// cover every name the resolver answers.
	if content := dnsfile.EnsureZone(nil, "local"); len(content) != 0 {
		t.Errorf("got:\n%s\nwant nothing", content)
	}
}

func TestAZoneLineIsNotAReadableRecord(t *testing.T) {
	// The listing is built from local-data lines. A zone line that showed up
	// as a record would offer the operator an edit button on it.
	content := dnsfile.EnsureZone(nil, "www.example.local")

	if records := dnsfile.Parse(content); len(records) != 0 {
		t.Errorf("got %+v, want no records", records)
	}
}
