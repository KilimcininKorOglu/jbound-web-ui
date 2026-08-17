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
	"log/slog"
	"os"
	"path/filepath"
)

// WarnIfRoot says what running as uid 0 costs, and lets the process run.
//
// The install puts the panel under its own account and nothing here needs root:
// PAM authentication goes through the setuid helper, and the rsyslog file goes
// through one sudoers rule. An operator who starts it as root anyway gets the
// sentence rather than a refusal, because which account this runs under is
// their decision to make.
//
// consequence names what root costs at this particular entry point, because
// what the panel risks and what a one shot command risks are different things.
func WarnIfRoot(consequence string) {
	if os.Geteuid() != 0 {
		return
	}
	slog.Warn("running as root", "consequence", consequence)
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
			"auth helper %s is missing the setuid bit, install it as 4750 root:jbound",
			path)
	}
	if info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("auth helper %s is not executable", path)
	}
	return nil
}
