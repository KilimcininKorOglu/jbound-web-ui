package dnsfile_test

import (
	"errors"
	"strings"
	"testing"

	"unbound-web/internal/dnsfile"
)

func TestValidateFQDNAcceptsWhatTheFileHolds(t *testing.T) {
	valid := []string{
		"www.example.net",
		"a",
		"host_name.example.net",
		"my-host.example.net",
		"1.2.3.4.in-addr.arpa",
		strings.Repeat("a", 253),
	}
	for _, name := range valid {
		if err := dnsfile.ValidateFQDN(name); err != nil {
			t.Errorf("%q was refused: %v", name, err)
		}
	}
}

func TestValidateFQDNRefusesWhatWouldBreakTheLine(t *testing.T) {
	invalid := map[string]string{
		"empty":       "",
		"space":       "www example.net",
		"quote":       `www".example.net`,
		"semicolon":   "www.example.net;id",
		"newline":     "www.example.net\nlocal-data: \"evil.net. A 192.0.2.1\"",
		"slash":       "www/example.net",
		"too long":    strings.Repeat("a", 254),
		"unicode":     "wwwü.example.net",
		"backslash":   `www\example.net`,
		"tab":         "www\texample.net",
		"dollar sign": "www$.example.net",
	}
	for name, value := range invalid {
		t.Run(name, func(t *testing.T) {
			if err := dnsfile.ValidateFQDN(value); !errors.Is(err, dnsfile.ErrInvalid) {
				t.Errorf("%q was accepted", value)
			}
		})
	}
}

func TestValidateIPOrHostnameAcceptsBothShapes(t *testing.T) {
	valid := []string{
		"192.0.2.10",
		"2001:db8::1",
		"::1",
		"mx1.example.net",
		"mx1.example.net.",
	}
	for _, value := range valid {
		if err := dnsfile.ValidateIPOrHostname(value); err != nil {
			t.Errorf("%q was refused: %v", value, err)
		}
	}
}

func TestValidateIPOrHostnameRefusesAnInjectedLine(t *testing.T) {
	invalid := []string{"", "192.0.2.10 evil", `192.0.2.10"`, "192.0.2.10\nlocal-data: \"x. A 1\""}
	for _, value := range invalid {
		if err := dnsfile.ValidateIPOrHostname(value); !errors.Is(err, dnsfile.ErrInvalid) {
			t.Errorf("%q was accepted", value)
		}
	}
}

func TestValidateRecordTypeCoversTheManagedTypes(t *testing.T) {
	for _, recordType := range dnsfile.Types {
		if err := dnsfile.ValidateRecordType(recordType); err != nil {
			t.Errorf("%s was refused: %v", recordType, err)
		}
	}
	for _, recordType := range []string{"", "a", "SRV", "NS", "SOA", "PTR"} {
		if err := dnsfile.ValidateRecordType(recordType); !errors.Is(err, dnsfile.ErrInvalid) {
			t.Errorf("%q was accepted", recordType)
		}
	}
}

func TestValidateReportsEveryProblemAtOnce(t *testing.T) {
	// A form that fixes one problem per submission wastes the operator's time.
	err := dnsfile.Record{FQDN: "no spaces", Type: "SRV", Value: "also bad"}.Validate()
	if !errors.Is(err, dnsfile.ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid", err)
	}

	for _, want := range []string{"name", "type", "value"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the message does not mention the %s: %v", want, err)
		}
	}
}

func TestValidateAcceptsTextThatSurvivesTheFileFormat(t *testing.T) {
	valid := []string{"hello-world", "v=spf1~all", "abc123"}
	for _, value := range valid {
		record := dnsfile.Record{FQDN: "txt.example.net", Type: "TXT", Value: value}
		if err := record.Validate(); err != nil {
			t.Errorf("%q was refused: %v", value, err)
		}
	}
}

func TestValidateRefusesTextThatWouldEndTheRecordEarly(t *testing.T) {
	// The whole record sits inside one pair of quotes, so a quote in the text
	// would close it and turn the rest of the line into something else.
	invalid := map[string]string{
		"quote":      `hello"world`,
		"backslash":  `hello\world`,
		"space":      "hello world",
		"tab":        "hello\tworld",
		"line break": "hello\nworld",
		"empty":      "",
		"too long":   strings.Repeat("a", 256),
	}
	for name, value := range invalid {
		t.Run(name, func(t *testing.T) {
			record := dnsfile.Record{FQDN: "txt.example.net", Type: "TXT", Value: value}
			if err := record.Validate(); !errors.Is(err, dnsfile.ErrInvalid) {
				t.Errorf("%q was accepted", value)
			}
		})
	}
}

func TestValidateBoundsTheMailPreference(t *testing.T) {
	for _, priority := range []int{-1, 65536} {
		record := dnsfile.Record{FQDN: "mail.example.net", Type: "MX",
			Value: "mx1.example.net", Priority: priority}
		if err := record.Validate(); !errors.Is(err, dnsfile.ErrInvalid) {
			t.Errorf("the preference %d was accepted", priority)
		}
	}

	for _, priority := range []int{0, 10, 65535} {
		record := dnsfile.Record{FQDN: "mail.example.net", Type: "MX",
			Value: "mx1.example.net", Priority: priority}
		if err := record.Validate(); err != nil {
			t.Errorf("the preference %d was refused: %v", priority, err)
		}
	}
}
