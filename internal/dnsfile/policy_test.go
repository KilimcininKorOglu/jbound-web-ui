package dnsfile_test

import (
	"errors"
	"strings"
	"testing"

	"jbound/internal/dnsfile"
)

func TestABlockedNameIsWrittenAsAZone(t *testing.T) {
	// NXDOMAIN is not a value a record can hold. Unbound answers it for a zone
	// rather than for a name with data, so the panel has to write another kind
	// of line entirely.
	record := dnsfile.Record{FQDN: "ads.example.local", Type: dnsfile.TypeNXDOMAIN}

	if want := `local-zone: "ads.example.local." always_nxdomain`; record.BuildLine() != want {
		t.Errorf("BuildLine() = %q, want %q", record.BuildLine(), want)
	}

	refused := dnsfile.Record{FQDN: "ads.example.local", Type: dnsfile.TypeREFUSED}
	if want := `local-zone: "ads.example.local." always_refuse`; refused.BuildLine() != want {
		t.Errorf("BuildLine() = %q, want %q", refused.BuildLine(), want)
	}
}

func TestOnlyTheManagedZoneTypesAreRead(t *testing.T) {
	// A transparent zone is plumbing the panel writes itself, and a static one
	// is a decision an operator made by hand. Listing either as a record would
	// invite deleting it from a table.
	content := []byte(`server:
local-zone: "example.local." transparent
local-zone: "held.example.local." static
local-zone: "ads.example.local." always_nxdomain
local-zone: "spam.example.local." always_refuse
local-data: "www.example.local. A 10.0.0.20"
`)

	records := dnsfile.Parse(content)
	if len(records) != 3 {
		t.Fatalf("read %d records, want 3:\n%+v", len(records), records)
	}

	types := map[string]string{}
	for _, record := range records {
		types[record.FQDN] = record.Type
	}
	if types["ads.example.local"] != dnsfile.TypeNXDOMAIN {
		t.Errorf("the blocked name reads as %q", types["ads.example.local"])
	}
	if types["spam.example.local"] != dnsfile.TypeREFUSED {
		t.Errorf("the refused name reads as %q", types["spam.example.local"])
	}
	if _, ok := types["example.local"]; ok {
		t.Errorf("the transparent zone reached the listing")
	}
	if _, ok := types["held.example.local"]; ok {
		t.Errorf("the static zone reached the listing")
	}
}

func TestAZoneLineIsReadWithTheTypeInsideTheQuotesToo(t *testing.T) {
	// Unbound accepts both forms and the file is edited by hand on the target,
	// so a block written the other way has to be visible rather than silently
	// duplicated by the next one the panel writes.
	records := dnsfile.Parse([]byte(`local-zone: "ads.example.local. always_nxdomain"` + "\n"))

	if len(records) != 1 {
		t.Fatalf("read %d records, want 1", len(records))
	}
	if records[0].Type != dnsfile.TypeNXDOMAIN || records[0].FQDN != "ads.example.local" {
		t.Errorf("read %+v", records[0])
	}
}

func TestABlockedNameCarriesNoValue(t *testing.T) {
	// The form hides the field, so a value here came from somewhere else. It
	// would reach nothing in the file, and accepting it would let whoever sent
	// it believe an address is being served.
	record := dnsfile.Record{
		FQDN: "ads.example.local", Type: dnsfile.TypeNXDOMAIN, Value: "10.0.0.1"}

	err := record.Validate()
	if !errors.Is(err, dnsfile.ErrInvalid) {
		t.Fatalf("error = %v, want a refusal", err)
	}
	if !strings.Contains(err.Error(), "no value") {
		t.Errorf("the message does not say why: %v", err)
	}
}

func TestOneNameOpensOneZone(t *testing.T) {
	// Two zone lines for one name leave which of them wins to the resolver,
	// and the panel would list both while only one decides the answer.
	content := []byte(`local-zone: "ads.example.local." always_nxdomain` + "\n")

	_, err := dnsfile.Add(content, dnsfile.Record{
		FQDN: "ads.example.local", Type: dnsfile.TypeREFUSED})

	if !errors.Is(err, dnsfile.ErrDuplicate) {
		t.Fatalf("error = %v, want a duplicate", err)
	}
}

func TestBlockingANameDeclaresNoOtherZone(t *testing.T) {
	// The line is already a zone declaration. A transparent parent beside it
	// would be a second decision about names the operator did not name.
	content, err := dnsfile.Add(nil, dnsfile.Record{
		FQDN: "ads.example.local", Type: dnsfile.TypeNXDOMAIN})
	if err != nil {
		t.Fatalf("cannot block the name: %v", err)
	}

	if strings.Contains(string(content), "transparent") {
		t.Errorf("a transparent zone was written beside the block:\n%s", content)
	}
}

func TestARecordUnderABlockedNameIsRefused(t *testing.T) {
	// The record would reach the file, pass the configuration check, survive
	// the reload and answer nothing. The panel would report it written and the
	// listing would go on showing it.
	content := []byte(`server:
local-zone: "ads.example.local." always_nxdomain
local-data: "www.ads.example.local. A 10.0.0.20"
`)

	err := dnsfile.CheckConsistency(content)
	if !errors.Is(err, dnsfile.ErrInvalid) {
		t.Fatalf("error = %v, want a refusal", err)
	}
	for _, want := range []string{"ads.example.local", "www.ads.example.local", "NXDOMAIN"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the message does not name %s: %v", want, err)
		}
	}
}

func TestABlockCoversTheNameItselfAsWell(t *testing.T) {
	content := []byte(`local-zone: "ads.example.local." always_refuse
local-data: "ads.example.local. A 10.0.0.20"
`)

	if err := dnsfile.CheckConsistency(content); !errors.Is(err, dnsfile.ErrInvalid) {
		t.Fatalf("error = %v, want a refusal", err)
	}
}

func TestAFileWithNoBlockIsLeftAlone(t *testing.T) {
	// The rule may not refuse the ordinary file, which is every file the panel
	// has written until now.
	content := []byte(`server:
local-zone: "example.local." transparent
local-data: "www.example.local. A 10.0.0.20"
local-data: "mail.example.local. MX 10 mx1.example.local."
`)

	if err := dnsfile.CheckConsistency(content); err != nil {
		t.Errorf("the file was refused: %v", err)
	}
}

func TestASiblingOfABlockedNameStillResolves(t *testing.T) {
	// A block covers itself and what is beneath it, not what sits beside it.
	content := []byte(`local-zone: "ads.example.local." always_nxdomain
local-data: "adsl.example.local. A 10.0.0.20"
local-data: "www.example.local. A 10.0.0.21"
`)

	if err := dnsfile.CheckConsistency(content); err != nil {
		t.Errorf("a name beside the block was refused: %v", err)
	}
}

func TestABlockIsRemovedLikeAnyOtherLine(t *testing.T) {
	content := []byte(`server:
local-zone: "ads.example.local." always_nxdomain
local-data: "www.example.local. A 10.0.0.20"
`)

	updated, err := dnsfile.Delete(content, dnsfile.Record{
		FQDN: "ads.example.local", Type: dnsfile.TypeNXDOMAIN})
	if err != nil {
		t.Fatalf("cannot remove the block: %v", err)
	}

	if strings.Contains(string(updated), "always_nxdomain") {
		t.Errorf("the block is still there:\n%s", updated)
	}
	if !strings.Contains(string(updated), "www.example.local") {
		t.Errorf("the record went with it:\n%s", updated)
	}
}
