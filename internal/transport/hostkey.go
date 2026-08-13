package transport

import (
	"fmt"
	"net"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Fingerprint renders a host key the way OpenSSH does.
//
// The operator compares this against what ssh-keyscan or the server console
// shows, so the format has to match theirs exactly.
func Fingerprint(key ssh.PublicKey) string {
	return ssh.FingerprintSHA256(key)
}

// AuthorizedKey renders a host key as a single authorized_keys line, which is
// what the server record stores.
func AuthorizedKey(key ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

// ParseHostKey reads a stored authorized_keys line.
func ParseHostKey(line string) (ssh.PublicKey, error) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return nil, fmt.Errorf("host key line is empty")
	}

	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(trimmed))
	if err != nil {
		return nil, fmt.Errorf("cannot parse the host key: %w", err)
	}
	return key, nil
}

// hostKeyCallback compares the key a server offers against the approved one.
//
// There is no first use exception. An unapproved key stops the connection and
// reports the fingerprint, so approving one is an act the operator performs
// rather than something the panel does on their behalf.
func hostKeyCallback(approved string) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		observed := Fingerprint(key)

		if strings.TrimSpace(approved) == "" {
			return &HostKeyError{Observed: observed, Err: ErrHostKeyUnknown}
		}

		expected, err := ParseHostKey(approved)
		if err != nil {
			return fmt.Errorf("the stored host key is unusable: %w", err)
		}

		// Compare the marshalled key rather than the fingerprint. The
		// fingerprint is a digest for people to read, and the bytes are what
		// the connection is actually authenticated against.
		if string(key.Marshal()) != string(expected.Marshal()) {
			return &HostKeyError{
				Observed: observed,
				Expected: Fingerprint(expected),
				Err:      ErrHostKeyMismatch,
			}
		}
		return nil
	}
}

// ScanHostKey connects far enough to learn the host key and returns its
// fingerprint together with the line to store.
//
// The connection is deliberately abandoned once the key is known. Nothing is
// authenticated and no command runs.
func ScanHostKey(cfg Config) (fingerprint, authorizedKey string, err error) {
	var seen ssh.PublicKey

	client, dialErr := dial(cfg, func(_ string, _ net.Addr, key ssh.PublicKey) error {
		seen = key
		// Stop here. The key is what this call wanted, and going further would
		// authenticate against a server nobody has approved yet.
		return errHostKeyCaptured
	})
	if client != nil {
		client.Close()
	}

	if seen == nil {
		return "", "", dialErr
	}
	return Fingerprint(seen), AuthorizedKey(seen), nil
}
