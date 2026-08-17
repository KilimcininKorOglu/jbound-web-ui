package preflight

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAnUnprivilegedProcessIsNotWarned(t *testing.T) {
	// The warning is for the operator who chose root. Raising it on every
	// start would teach them to read past it.
	if os.Geteuid() == 0 {
		t.Skip("test suite is running as root")
	}

	var written bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&written, nil)))
	defer slog.SetDefault(previous)

	WarnIfRoot("the fleet would be handed over")

	if written.Len() != 0 {
		t.Errorf("an unprivileged process was warned: %s", written.String())
	}
}

func TestDataDirCreatesBothDirectoriesWith0700(t *testing.T) {
	base := t.TempDir()
	dataDir := filepath.Join(base, "data")
	keyDir := filepath.Join(dataDir, "keys")

	if err := DataDir(dataDir, keyDir); err != nil {
		t.Fatalf("DataDir returned an error: %v", err)
	}

	for _, dir := range []string{dataDir, keyDir} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("%s was not created: %v", dir, err)
		}
		if !info.IsDir() {
			t.Fatalf("%s is not a directory", dir)
		}
		// SSH private keys live here, so the mode is part of the contract.
		if got := info.Mode().Perm(); got != 0o700 {
			t.Errorf("%s has mode %o, want 700", dir, got)
		}
	}
}

func TestDataDirTightensAnExistingLooseDirectory(t *testing.T) {
	base := t.TempDir()
	dataDir := filepath.Join(base, "data")
	keyDir := filepath.Join(dataDir, "keys")

	if err := os.MkdirAll(keyDir, 0o755); err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	if err := DataDir(dataDir, keyDir); err != nil {
		t.Fatalf("DataDir returned an error: %v", err)
	}

	info, err := os.Stat(dataDir)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Errorf("existing directory kept mode %o, want 700", got)
	}
}

func TestDataDirLeavesNoProbeBehind(t *testing.T) {
	base := t.TempDir()
	dataDir := filepath.Join(base, "data")

	if err := DataDir(dataDir, filepath.Join(dataDir, "keys")); err != nil {
		t.Fatalf("DataDir returned an error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, ".write-probe")); !os.IsNotExist(err) {
		t.Error("the write probe file was not removed")
	}
}

func TestAuthHelperRejectsAMissingBinary(t *testing.T) {
	err := AuthHelper(filepath.Join(t.TempDir(), "absent"))
	if err == nil {
		t.Fatal("AuthHelper accepted a missing binary")
	}
	if !strings.Contains(err.Error(), "not available") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAuthHelperRejectsAPlainExecutable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "helper")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	err := AuthHelper(path)
	if err == nil {
		t.Fatal("AuthHelper accepted a binary without the setuid bit")
	}
	// The message must name the required install mode, because that is the
	// single most common deployment mistake for this helper.
	if !strings.Contains(err.Error(), "4750") {
		t.Errorf("error does not mention the required mode: %v", err)
	}
}

func TestAuthHelperRejectsADirectory(t *testing.T) {
	if err := AuthHelper(t.TempDir()); err == nil {
		t.Fatal("AuthHelper accepted a directory")
	}
}
