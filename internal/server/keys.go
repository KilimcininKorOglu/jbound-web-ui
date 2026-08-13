package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

// KeySubdir is where the private keys live inside the data directory.
const KeySubdir = "keys"

// KeyPair is a generated SSH identity.
//
// Only the public half is ever returned to a caller. The private half goes
// straight to disk, so no handler can put it in a response by accident.
type KeyPair struct {
	// RelPath is where the private key lives, relative to the data directory.
	RelPath string

	// PublicKey is the authorized_keys line for the target server.
	PublicKey string

	// Fingerprint identifies the key for a person.
	Fingerprint string
}

// KeyStore writes and removes the private keys of the managed servers.
type KeyStore struct {
	// dataDir is what the stored paths are relative to, so moving the data
	// directory does not invalidate every record.
	dataDir string
	dir     string
}

// NewKeyStore prepares the key directory inside the data directory.
//
// Mode 0700 on the directory matters as much as 0600 on the files. A readable
// directory would let any local account list which servers the panel reaches.
func NewKeyStore(dataDir string) (*KeyStore, error) {
	dir := filepath.Join(dataDir, KeySubdir)

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("cannot create the key directory %s: %w", dir, err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("cannot set mode 0700 on %s: %w", dir, err)
	}
	return &KeyStore{dataDir: dataDir, dir: dir}, nil
}

// Dir reports the directory the keys live in.
func (k *KeyStore) Dir() string { return k.dir }

// Generate writes a new ed25519 key pair for one server.
//
// ed25519 rather than RSA: the keys are short, every current OpenSSH accepts
// them, and there is no key size to get wrong.
func (k *KeyStore) Generate(id int64) (KeyPair, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return KeyPair{}, fmt.Errorf("cannot generate a key pair: %w", err)
	}

	block, err := ssh.MarshalPrivateKey(private, "unbound-web server "+strconv.FormatInt(id, 10))
	if err != nil {
		return KeyPair{}, fmt.Errorf("cannot encode the private key: %w", err)
	}

	signer, err := ssh.NewPublicKey(public)
	if err != nil {
		return KeyPair{}, fmt.Errorf("cannot encode the public key: %w", err)
	}

	relPath := KeyRelPath(id)
	path := filepath.Join(k.dataDir, relPath)

	file, err := createKeyFile(path)
	if err != nil {
		return KeyPair{}, err
	}
	defer file.Close()

	if err := pem.Encode(file, block); err != nil {
		os.Remove(path)
		return KeyPair{}, fmt.Errorf("cannot write the key file %s: %w", path, err)
	}

	return KeyPair{
		RelPath:     relPath,
		PublicKey:   strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer))),
		Fingerprint: ssh.FingerprintSHA256(signer),
	}, nil
}

// Import stores a private key the operator supplied.
//
// The key is parsed first. A file that turns out not to be a usable key would
// otherwise fail later, on the first connection, with a far less obvious
// message.
func (k *KeyStore) Import(id int64, material string) (KeyPair, error) {
	signer, err := ssh.ParsePrivateKey([]byte(material))
	if err != nil {
		return KeyPair{}, fmt.Errorf("%w: the supplied key is not usable: %v", ErrValidation, err)
	}

	relPath := KeyRelPath(id)
	path := filepath.Join(k.dataDir, relPath)

	file, err := createKeyFile(path)
	if err != nil {
		return KeyPair{}, err
	}
	defer file.Close()

	if _, err := file.WriteString(material); err != nil {
		os.Remove(path)
		return KeyPair{}, fmt.Errorf("cannot write the key file %s: %w", path, err)
	}

	public := signer.PublicKey()
	return KeyPair{
		RelPath:     relPath,
		PublicKey:   strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public))),
		Fingerprint: ssh.FingerprintSHA256(public),
	}, nil
}

// createKeyFile opens the key file of one server for writing.
//
// The name comes from a row identifier the database has just issued, so it
// cannot belong to a live server. An existing file is a leftover from a
// deleted one, which is why the write truncates instead of refusing.
func createKeyFile(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("cannot create the key file %s: %w", path, err)
	}
	return file, nil
}

// PublicKey reads the public half of a stored key.
//
// The private half never leaves this package, so the interface asks for the
// public one instead of loading the file itself.
func (k *KeyStore) PublicKey(relPath string) (string, string, error) {
	path, err := k.resolve(relPath)
	if err != nil {
		return "", "", err
	}

	material, err := os.ReadFile(path)
	if err != nil {
		return "", "", fmt.Errorf("cannot read the key file: %w", err)
	}

	signer, err := ssh.ParsePrivateKey(material)
	if err != nil {
		return "", "", fmt.Errorf("the stored key is not usable: %w", err)
	}

	public := signer.PublicKey()
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public))),
		ssh.FingerprintSHA256(public), nil
}

// Remove deletes the private key of a server that is being removed.
//
// A missing file is not an error. The record is going away either way, and
// refusing to finish would leave the panel pointing at a server nobody can
// reach.
func (k *KeyStore) Remove(relPath string) error {
	if relPath == "" {
		return nil
	}

	path, err := k.resolve(relPath)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("cannot remove the key file: %w", err)
	}
	return nil
}

// resolve turns a stored path into a full one.
//
// The service is the only writer of that column, but it is read back out of the
// database, so a tampered row must not be able to read or delete a file
// somewhere else on the host.
func (k *KeyStore) resolve(relPath string) (string, error) {
	path := filepath.Join(k.dataDir, relPath)
	if filepath.Dir(path) != k.dir {
		return "", fmt.Errorf("the key path %s is outside %s", relPath, k.dir)
	}
	return path, nil
}

// KeyRelPath builds the stored path of one server key.
//
// The name is the row identifier rather than the server name, so renaming a
// server does not orphan its key.
func KeyRelPath(id int64) string {
	return filepath.Join(KeySubdir, strconv.FormatInt(id, 10)+".key")
}
