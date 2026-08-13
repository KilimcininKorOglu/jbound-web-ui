package transport

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// newTestKey returns a public key to stand in for a server host key.
func newTestKey(t *testing.T) ssh.PublicKey {
	t.Helper()

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate a key: %v", err)
	}
	_ = private

	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatalf("cannot wrap the key: %v", err)
	}
	return key
}

func TestFingerprintUsesTheOpenSSHFormat(t *testing.T) {
	// The operator compares this against ssh-keyscan output, so the format has
	// to be the one OpenSSH prints.
	got := Fingerprint(newTestKey(t))

	if !strings.HasPrefix(got, "SHA256:") {
		t.Errorf("Fingerprint = %q, want a SHA256: prefix", got)
	}
}

func TestAuthorizedKeyRoundTrip(t *testing.T) {
	key := newTestKey(t)
	line := AuthorizedKey(key)

	if strings.ContainsAny(line, "\n\r") {
		t.Error("the stored line spans several lines")
	}

	parsed, err := ParseHostKey(line)
	if err != nil {
		t.Fatalf("ParseHostKey returned an error: %v", err)
	}
	if string(parsed.Marshal()) != string(key.Marshal()) {
		t.Error("the key changed on the way through storage")
	}
}

func TestParseHostKeyRefusesRubbish(t *testing.T) {
	for _, line := range []string{"", "   ", "not a key", "ssh-ed25519"} {
		if _, err := ParseHostKey(line); err == nil {
			t.Errorf("ParseHostKey accepted %q", line)
		}
	}
}

func TestHostKeyCallbackRefusesAnUnapprovedServer(t *testing.T) {
	// There is no first use exception. Approving a key is an act the operator
	// performs, not something the panel does on their behalf.
	key := newTestKey(t)
	callback := hostKeyCallback("")

	err := callback("dns1:22", &net.TCPAddr{}, key)
	if !errors.Is(err, ErrHostKeyUnknown) {
		t.Fatalf("got %v, want ErrHostKeyUnknown", err)
	}

	hostKeyErr, ok := errors.AsType[*HostKeyError](err)
	if !ok {
		t.Fatal("the error carries no fingerprint")
	}
	if hostKeyErr.Observed != Fingerprint(key) {
		t.Errorf("observed = %q, want the fingerprint of the offered key", hostKeyErr.Observed)
	}
}

func TestHostKeyCallbackAcceptsTheApprovedKey(t *testing.T) {
	key := newTestKey(t)

	if err := hostKeyCallback(AuthorizedKey(key))("dns1:22", &net.TCPAddr{}, key); err != nil {
		t.Fatalf("the approved key was refused: %v", err)
	}
}

func TestHostKeyCallbackRefusesADifferentKey(t *testing.T) {
	approved := newTestKey(t)
	offered := newTestKey(t)

	err := hostKeyCallback(AuthorizedKey(approved))("dns1:22", &net.TCPAddr{}, offered)
	if !errors.Is(err, ErrHostKeyMismatch) {
		t.Fatalf("got %v, want ErrHostKeyMismatch", err)
	}

	hostKeyErr, ok := errors.AsType[*HostKeyError](err)
	if !ok {
		t.Fatal("the error carries no fingerprints")
	}
	if hostKeyErr.Observed == hostKeyErr.Expected {
		t.Error("the two fingerprints are the same")
	}
}

func TestHostKeyCallbackReportsAnUnusableStoredKey(t *testing.T) {
	// A stored line that will not parse is a database fault. Treating it as a
	// mismatch would send the operator to check the server instead.
	err := hostKeyCallback("ssh-ed25519 this-is-not-base64")("dns1:22", &net.TCPAddr{}, newTestKey(t))

	if err == nil {
		t.Fatal("an unusable stored key was accepted")
	}
	if errors.Is(err, ErrHostKeyMismatch) {
		t.Error("a broken stored key was reported as a mismatch")
	}
	if !strings.Contains(err.Error(), "stored host key") {
		t.Errorf("the error does not point at the stored value: %v", err)
	}
}
