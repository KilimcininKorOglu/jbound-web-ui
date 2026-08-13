package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func newKeyStore(t *testing.T) *KeyStore {
	t.Helper()

	store, err := NewKeyStore(t.TempDir())
	if err != nil {
		t.Fatalf("cannot create the key store: %v", err)
	}
	return store
}

// keyPath resolves a stored path the way the panel does, against the data
// directory rather than the key directory.
func keyPath(store *KeyStore, relPath string) string {
	return filepath.Join(store.dataDir, relPath)
}

func TestNewKeyStoreLocksDownTheDirectory(t *testing.T) {
	// A readable directory would let any local account list which servers the
	// panel reaches.
	store := newKeyStore(t)

	info, err := os.Stat(store.Dir())
	if err != nil {
		t.Fatalf("cannot stat the key directory: %v", err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("mode = %o, want 700", info.Mode().Perm())
	}
}

func TestGenerateWritesAPrivateKeyOnlyTheServiceCanRead(t *testing.T) {
	store := newKeyStore(t)

	pair, err := store.Generate(1)
	if err != nil {
		t.Fatalf("Generate returned an error: %v", err)
	}

	if pair.RelPath != filepath.Join(KeySubdir, "1.key") {
		t.Errorf("relative path = %q, want it named after the record", pair.RelPath)
	}

	info, err := os.Stat(keyPath(store, pair.RelPath))
	if err != nil {
		t.Fatalf("the key file is missing: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 600", info.Mode().Perm())
	}
}

func TestGenerateReturnsAUsablePublicKey(t *testing.T) {
	store := newKeyStore(t)

	pair, err := store.Generate(1)
	if err != nil {
		t.Fatalf("Generate returned an error: %v", err)
	}

	if !strings.HasPrefix(pair.PublicKey, "ssh-ed25519 ") {
		t.Errorf("public key = %q, want an ed25519 authorized_keys line", pair.PublicKey)
	}
	if strings.ContainsAny(pair.PublicKey, "\n\r") {
		t.Error("the public key spans several lines")
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pair.PublicKey)); err != nil {
		t.Errorf("the public key does not parse: %v", err)
	}
	if !strings.HasPrefix(pair.Fingerprint, "SHA256:") {
		t.Errorf("fingerprint = %q", pair.Fingerprint)
	}
}

func TestGeneratedKeyLoadsBackAsASigner(t *testing.T) {
	// The transport parses this file on every connection, so a key that will
	// not load is worth catching here.
	store := newKeyStore(t)

	pair, err := store.Generate(1)
	if err != nil {
		t.Fatalf("Generate returned an error: %v", err)
	}

	material, err := os.ReadFile(keyPath(store, pair.RelPath))
	if err != nil {
		t.Fatalf("cannot read the key file: %v", err)
	}
	signer, err := ssh.ParsePrivateKey(material)
	if err != nil {
		t.Fatalf("the stored key does not parse: %v", err)
	}

	stored := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	if stored != pair.PublicKey {
		t.Error("the stored key does not match the public key that was returned")
	}
}

func TestEachServerGetsItsOwnKey(t *testing.T) {
	store := newKeyStore(t)

	first, err := store.Generate(1)
	if err != nil {
		t.Fatalf("the first Generate failed: %v", err)
	}
	second, err := store.Generate(2)
	if err != nil {
		t.Fatalf("the second Generate failed: %v", err)
	}

	if first.RelPath == second.RelPath {
		t.Fatal("two servers share one key file")
	}
	if first.PublicKey == second.PublicKey {
		t.Error("two servers share one identity")
	}
	if _, err := os.Stat(keyPath(store, first.RelPath)); err != nil {
		t.Errorf("the first key did not survive: %v", err)
	}
}

func TestGenerateReplacesTheLeftoverOfADeletedServer(t *testing.T) {
	// The name comes from a row identifier the database has just issued, so an
	// existing file cannot belong to a live server. Refusing here would leave
	// the identifier unusable for good.
	store := newKeyStore(t)

	first, err := store.Generate(1)
	if err != nil {
		t.Fatalf("the first Generate failed: %v", err)
	}
	second, err := store.Generate(1)
	if err != nil {
		t.Fatalf("the second Generate failed: %v", err)
	}

	if first.PublicKey == second.PublicKey {
		t.Error("the second key is the first one")
	}

	public, _, err := store.PublicKey(second.RelPath)
	if err != nil {
		t.Fatalf("PublicKey returned an error: %v", err)
	}
	if public != second.PublicKey {
		t.Error("the file still holds the previous key")
	}
}

func TestImportAcceptsASuppliedKey(t *testing.T) {
	source := newKeyStore(t)
	pair, err := source.Generate(1)
	if err != nil {
		t.Fatalf("cannot prepare a key: %v", err)
	}
	material, err := os.ReadFile(keyPath(source, pair.RelPath))
	if err != nil {
		t.Fatalf("cannot read the prepared key: %v", err)
	}

	target := newKeyStore(t)
	imported, err := target.Import(7, string(material))
	if err != nil {
		t.Fatalf("Import returned an error: %v", err)
	}

	if imported.PublicKey != pair.PublicKey {
		t.Error("the imported key has a different public half")
	}

	info, err := os.Stat(keyPath(target, imported.RelPath))
	if err != nil {
		t.Fatalf("the imported key file is missing: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 600", info.Mode().Perm())
	}
}

func TestImportRefusesSomethingThatIsNotAKey(t *testing.T) {
	// A file that is not a key would otherwise fail on the first connection,
	// with a message that points at the server instead of at the paste.
	store := newKeyStore(t)

	_, err := store.Import(1, "this is not a key")
	if err == nil {
		t.Fatal("Import accepted a file that is not a key")
	}
	if !strings.Contains(err.Error(), ErrValidation.Error()) {
		t.Errorf("got %v, want a validation error the form can show", err)
	}
	if _, err := os.Stat(keyPath(store, KeyRelPath(1))); !os.IsNotExist(err) {
		t.Error("the rejected key was written anyway")
	}
}

func TestPublicKeyReadsBackTheStoredIdentity(t *testing.T) {
	store := newKeyStore(t)
	pair, err := store.Generate(1)
	if err != nil {
		t.Fatalf("Generate returned an error: %v", err)
	}

	public, fingerprint, err := store.PublicKey(pair.RelPath)
	if err != nil {
		t.Fatalf("PublicKey returned an error: %v", err)
	}
	if public != pair.PublicKey || fingerprint != pair.Fingerprint {
		t.Error("the read back identity differs from the generated one")
	}
}

func TestStoredPathsCannotLeaveTheKeyDirectory(t *testing.T) {
	// The path is read back out of the database. A tampered row must not be
	// able to read or delete a file somewhere else on the host.
	store := newKeyStore(t)

	outside := filepath.Join(store.dataDir, "panel.db")
	if err := os.WriteFile(outside, []byte("not a key"), 0o600); err != nil {
		t.Fatalf("cannot prepare the file: %v", err)
	}

	for _, relPath := range []string{"panel.db", "keys/../panel.db", "/etc/shadow"} {
		if _, _, err := store.PublicKey(relPath); err == nil {
			t.Errorf("PublicKey accepted %q", relPath)
		}
		if err := store.Remove(relPath); err == nil {
			t.Errorf("Remove accepted %q", relPath)
		}
	}

	if _, err := os.Stat(outside); err != nil {
		t.Errorf("the file outside the key directory was removed: %v", err)
	}
}

func TestRemoveIsQuietAboutAMissingFile(t *testing.T) {
	// The record is going away either way. Refusing to finish would leave the
	// panel pointing at a server nobody can reach.
	store := newKeyStore(t)

	if err := store.Remove(KeyRelPath(404)); err != nil {
		t.Fatalf("Remove complained about a missing file: %v", err)
	}
	if err := store.Remove(""); err != nil {
		t.Fatalf("Remove complained about an empty path: %v", err)
	}
}

func TestRemoveDeletesTheKey(t *testing.T) {
	store := newKeyStore(t)
	pair, err := store.Generate(1)
	if err != nil {
		t.Fatalf("Generate returned an error: %v", err)
	}

	if err := store.Remove(pair.RelPath); err != nil {
		t.Fatalf("Remove returned an error: %v", err)
	}
	if _, err := os.Stat(keyPath(store, pair.RelPath)); !os.IsNotExist(err) {
		t.Error("the key file survived")
	}
}
