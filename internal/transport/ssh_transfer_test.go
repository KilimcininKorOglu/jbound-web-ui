package transport

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestParseDigestReadsTheFirstField(t *testing.T) {
	const sum = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	got, err := parseDigest(sum + "  /etc/unbound/.local_records.conf.tmp\n")
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

// silentPeer accepts a connection and then says nothing, which is what a
// tarpit, a wrong port and a wedged sshd all look like from here.
func silentPeer(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			// Hold it open. Closing would let the handshake fail on its own.
			t.Cleanup(func() { conn.Close() })
		}
	}()
	return listener.Addr().String()
}

// writeTestKey writes a private key the dial can read.
func writeTestKey(t *testing.T) string {
	t.Helper()

	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate a key: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(private, "test")
	if err != nil {
		t.Fatalf("cannot marshal the key: %v", err)
	}

	path := filepath.Join(t.TempDir(), "test.key")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("cannot write the key: %v", err)
	}
	return path
}

func TestASilentPeerFailsWithinTheConnectTimeout(t *testing.T) {
	// ClientConfig.Timeout bounds the TCP connect only. Without a deadline over
	// the handshake this call never returns, and it runs while the per-server
	// mutex is held.
	address := silentPeer(t)
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatalf("cannot split %s: %v", address, err)
	}

	cfg := validConfig()
	cfg.Host = host
	cfg.Port = mustAtoi(t, port)
	cfg.KeyPath = writeTestKey(t)
	cfg.ConnectTimeout = time.Second

	done := make(chan error, 1)
	go func() {
		_, _, scanErr := ScanHostKey(cfg)
		done <- scanErr
	}()

	select {
	case scanErr := <-done:
		if scanErr == nil {
			t.Fatal("a peer that never speaks was accepted")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the handshake never gave up")
	}
}

func mustAtoi(t *testing.T, value string) int {
	t.Helper()

	number, err := strconv.Atoi(value)
	if err != nil {
		t.Fatalf("cannot read the port %q: %v", value, err)
	}
	return number
}
