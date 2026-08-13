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

	store, err := NewKeyStore(filepath.Join(t.TempDir(), "keys"))
	if err != nil {
		t.Fatalf("cannot create the key store: %v", err)
	}
	return store
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

	pair, err := store.Generate("dns1")
	if err != nil {
		t.Fatalf("Generate returned an error: %v", err)
	}

	info, err := os.Stat(filepath.Join(store.Dir(), pair.RelPath))
	if err != nil {
		t.Fatalf("the key file is missing: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 600", info.Mode().Perm())
	}
}

func TestGenerateReturnsAUsablePublicKey(t *testing.T) {
	store := newKeyStore(t)

	pair, err := store.Generate("dns1")
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

	pair, err := store.Generate("dns1")
	if err != nil {
		t.Fatalf("Generate returned an error: %v", err)
	}

	material, err := os.ReadFile(filepath.Join(store.Dir(), pair.RelPath))
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

func TestGenerateRefusesToOverwriteAnExistingKey(t *testing.T) {
	// A name collision must fail loudly. Overwriting would cut the panel off
	// from the server that owns the previous key.
	store := newKeyStore(t)

	if _, err := store.Generate("dns1"); err != nil {
		t.Fatalf("the first Generate failed: %v", err)
	}
	if _, err := store.Generate("dns1"); err == nil {
		t.Fatal("the second Generate overwrote the existing key")
	}
}

func TestImportAcceptsASuppliedKey(t *testing.T) {
	source := newKeyStore(t)
	pair, err := source.Generate("source")
	if err != nil {
		t.Fatalf("cannot prepare a key: %v", err)
	}
	material, err := os.ReadFile(filepath.Join(source.Dir(), pair.RelPath))
	if err != nil {
		t.Fatalf("cannot read the prepared key: %v", err)
	}

	target := newKeyStore(t)
	imported, err := target.Import("dns1", string(material))
	if err != nil {
		t.Fatalf("Import returned an error: %v", err)
	}

	if imported.PublicKey != pair.PublicKey {
		t.Error("the imported key has a different public half")
	}

	info, err := os.Stat(filepath.Join(target.Dir(), imported.RelPath))
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

	if _, err := store.Import("dns1", "this is not a key"); err == nil {
		t.Fatal("Import accepted a file that is not a key")
	}
	if _, err := os.Stat(filepath.Join(store.Dir(), "dns1.key")); !os.IsNotExist(err) {
		t.Error("the rejected key was written anyway")
	}
}

func TestPublicKeyReadsBackTheStoredIdentity(t *testing.T) {
	store := newKeyStore(t)
	pair, err := store.Generate("dns1")
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

func TestRemoveIsQuietAboutAMissingFile(t *testing.T) {
	// The record is going away either way. Refusing to finish would leave the
	// panel pointing at a server nobody can reach.
	store := newKeyStore(t)

	if err := store.Remove("gone.key"); err != nil {
		t.Fatalf("Remove complained about a missing file: %v", err)
	}
	if err := store.Remove(""); err != nil {
		t.Fatalf("Remove complained about an empty path: %v", err)
	}
}

func TestRemoveDeletesTheKey(t *testing.T) {
	store := newKeyStore(t)
	pair, err := store.Generate("dns1")
	if err != nil {
		t.Fatalf("Generate returned an error: %v", err)
	}

	if err := store.Remove(pair.RelPath); err != nil {
		t.Fatalf("Remove returned an error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(store.Dir(), pair.RelPath)); !os.IsNotExist(err) {
		t.Error("the key file survived")
	}
}
