package transport

import (
	"errors"
	"strings"
	"testing"
)

func TestParseDigestReadsTheFirstField(t *testing.T) {
	const sum = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	got, err := parseDigest(sum + "  /etc/unbound/.host_entries.conf.tmp\n")
	if err != nil {
		t.Fatalf("parseDigest returned an error: %v", err)
	}
	if got != sum {
		t.Errorf("parseDigest = %q", got)
	}
}

func TestParseDigestRefusesAnythingElse(t *testing.T) {
	// The digest is what decides whether the temporary file is moved over the
	// real one. Reading a wrong value out of noise would defeat the check.
	cases := map[string]string{
		"empty output":     "",
		"an error message": "sha256sum: /etc/unbound/.tmp: No such file or directory",
		"a short digest":   "abc123  /etc/unbound/.tmp",
		"upper case hex":   strings.Repeat("A", 64) + "  /etc/unbound/.tmp",
		"not hex at all":   strings.Repeat("z", 64) + "  /etc/unbound/.tmp",
	}

	for name, output := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseDigest(output); !errors.Is(err, ErrRemoteOutput) {
				t.Fatalf("parseDigest accepted %q: %v", output, err)
			}
		})
	}
}
