// Package preflight holds the startup checks that must pass before the panel
// serves traffic.
//
// Each check fails loudly. A panel that starts with a broken privilege model
// or an unwritable data directory would fail later, at a point that points at
// the wrong layer.
package preflight

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// NotRoot rejects a panel process running as uid 0.
//
// The panel stores SSH keys to every managed DNS server. Running it as root
// would mean one HTTP flaw gives away the whole fleet. PAM authentication does
// not need root here, because the setuid helper carries that privilege.
func NotRoot() error {
	if os.Geteuid() == 0 {
		return fmt.Errorf(
			"the panel must not run as root, start it as the unbound-web service account")
	}
	return nil
}

// DataDir creates the data directory and its key subdirectory with 0700 and
// verifies that the current user can write there.
func DataDir(dataDir, keyDir string) error {
	for _, dir := range []string{dataDir, keyDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("cannot create %s: %w", dir, err)
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("cannot set mode 0700 on %s: %w", dir, err)
		}
	}

	probe := filepath.Join(dataDir, ".write-probe")
	if err := os.WriteFile(probe, []byte("probe"), 0o600); err != nil {
		return fmt.Errorf("data directory %s is not writable: %w", dataDir, err)
	}
	if err := os.Remove(probe); err != nil {
		return fmt.Errorf("cannot clean up the write probe in %s: %w", dataDir, err)
	}
	return nil
}

// AuthHelper verifies that the setuid PAM helper is installed correctly.
//
// The auth subsystem calls this when it is constructed, not at process start.
// Ordering it that way keeps the phases independent: the panel runs without
// the helper until authentication is wired up.
func AuthHelper(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("auth helper %s is not available: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("auth helper %s is not a regular file", path)
	}
	if info.Mode()&fs.ModeSetuid == 0 {
		return fmt.Errorf(
			"auth helper %s is missing the setuid bit, install it as 4750 root:unbound-web",
			path)
	}
	if info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("auth helper %s is not executable", path)
	}
	return nil
}
