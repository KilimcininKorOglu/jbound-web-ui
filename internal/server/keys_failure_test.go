package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// skipAsRoot leaves the tests below out when the file modes they rest on carry
// no weight, because root writes into a directory it has no permission for.
func skipAsRoot(t *testing.T) {
	t.Helper()

	if os.Geteuid() == 0 {
		t.Skip("root ignores the directory mode these tests rest on")
	}
}

func TestAKeyThatCannotBeWrittenIsReportedRatherThanReturned(t *testing.T) {
	// The caller stores the path it gets back in the server row. A generate
	// that reported a key pair it never managed to write would leave a row
	// pointing at nothing, and the failure would surface on the first
	// connection instead of here.
	skipAsRoot(t)

	store := newKeyStore(t)
	if err := os.Chmod(store.Dir(), 0o500); err != nil {
		t.Fatalf("cannot take away the write permission: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(store.Dir(), 0o700) })

	pair, err := store.Generate(1)
	if err == nil {
		t.Fatal("a key was reported for a directory that cannot be written")
	}
	if pair.RelPath != "" || pair.PublicKey != "" {
		t.Errorf("a failed generate still described a key: %+v", pair)
	}
	if !strings.Contains(err.Error(), "key file") {
		t.Errorf("the failure does not say what could not be written: %v", err)
	}
}

func TestAFailedRotationLeavesTheOldKeyInPlace(t *testing.T) {
	// This is the whole reason a rotation writes beside the key and renames.
	// A server whose key file was replaced by a half written one is a server
	// the panel can no longer reach at all, which is worse than the leaked key
	// the rotation was for.
	skipAsRoot(t)

	store := newKeyStore(t)
	original, err := store.Generate(1)
	if err != nil {
		t.Fatalf("cannot generate the first key: %v", err)
	}

	before, err := os.ReadFile(keyPath(store, original.RelPath))
	if err != nil {
		t.Fatalf("cannot read the key back: %v", err)
	}

	if err := os.Chmod(store.Dir(), 0o500); err != nil {
		t.Fatalf("cannot take away the write permission: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(store.Dir(), 0o700) })

	if _, err := store.Rotate(1, original.RelPath); err == nil {
		t.Fatal("a rotation into a directory that cannot be written succeeded")
	}

	if err := os.Chmod(store.Dir(), 0o700); err != nil {
		t.Fatalf("cannot restore the write permission: %v", err)
	}

	after, err := os.ReadFile(keyPath(store, original.RelPath))
	if err != nil {
		t.Fatalf("the key file is gone after a failed rotation: %v", err)
	}
	if string(after) != string(before) {
		t.Error("a failed rotation changed the key the server still uses")
	}

	// And no staging file is left for the next rotation to trip over.
	entries, err := os.ReadDir(store.Dir())
	if err != nil {
		t.Fatalf("cannot list the key directory: %v", err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".new") {
			t.Errorf("a failed rotation left %s behind", entry.Name())
		}
	}
}

func TestAnImportedKeyThatCannotBeWrittenLeavesNoFile(t *testing.T) {
	// A key file that exists but holds half of a key reads as a usable key
	// until the first connection fails on it.
	skipAsRoot(t)

	store := newKeyStore(t)
	material := generatedKeyMaterial(t, store)

	if err := os.Chmod(store.Dir(), 0o500); err != nil {
		t.Fatalf("cannot take away the write permission: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(store.Dir(), 0o700) })

	if _, err := store.Import(2, material); err == nil {
		t.Fatal("an import into a directory that cannot be written succeeded")
	}

	if err := os.Chmod(store.Dir(), 0o700); err != nil {
		t.Fatalf("cannot restore the write permission: %v", err)
	}
	if _, err := os.Stat(filepath.Join(store.Dir(), "server-2.key")); !os.IsNotExist(err) {
		t.Error("a failed import left a key file behind")
	}
}

func TestAKeyStoreRefusesADataDirectoryItCannotUse(t *testing.T) {
	// The panel stores the SSH key of every managed resolver here. Starting
	// without the directory would mean discovering that on the first server
	// somebody adds.
	skipAsRoot(t)

	base := t.TempDir()
	blocked := filepath.Join(base, "blocked")
	if err := os.Mkdir(blocked, 0o500); err != nil {
		t.Fatalf("cannot create the read-only directory: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o700) })

	if _, err := NewKeyStore(filepath.Join(blocked, "data")); err == nil {
		t.Fatal("a key store was built inside a directory it cannot write")
	}
}

// generatedKeyMaterial returns the private half of a real key, so an import
// test is refused for the reason it is about rather than for its content.
func generatedKeyMaterial(t *testing.T, store *KeyStore) string {
	t.Helper()

	pair, err := store.Generate(99)
	if err != nil {
		t.Fatalf("cannot generate a key to import: %v", err)
	}
	material, err := os.ReadFile(keyPath(store, pair.RelPath))
	if err != nil {
		t.Fatalf("cannot read the generated key: %v", err)
	}
	return string(material)
}
