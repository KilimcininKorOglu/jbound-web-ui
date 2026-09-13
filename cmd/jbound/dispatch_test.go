package main

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"jbound/internal/config"
)

// refusingLoader fails the test if the routing ever reads the configuration:
// the pure refusals have to decide on the arguments alone.
func refusingLoader(t *testing.T) func() (*config.Config, error) {
	return func() (*config.Config, error) {
		t.Helper()
		t.Fatal("the routing read the configuration for a pure refusal")
		return nil, nil
	}
}

func TestAnUnknownSubcommandIsAUsageRefusal(t *testing.T) {
	// The mistyped command is the operator's doing, not a startup failure:
	// it comes back as a refusal that carries the usage, so main answers it
	// with the usage text and exit code 2 instead of the failure log.
	err := dispatch([]string{"bakup"}, refusingLoader(t))
	if err == nil {
		t.Fatal("an unknown subcommand was accepted")
	}
	var driven *usageError
	if !errors.As(err, &driven) {
		t.Fatalf("the refusal is a %T, not a usage error", err)
	}
	for _, want := range []string{"jbound backup <dir>", "import-audit <file>"} {
		if !strings.Contains(driven.Error(), want) {
			t.Errorf("the usage is missing %q: %q", want, driven.Error())
		}
	}
}

func TestTheExitCodeFollowsTheKindOfRefusal(t *testing.T) {
	// systemd units and the scripts around the panel read the difference: a
	// mistyped command is usage, everything else is a malfunction.
	if got := exitCodeFor(&usageError{text: usage}); got != 2 {
		t.Errorf("a usage refusal exits %d, want 2", got)
	}
	if got := exitCodeFor(errors.New("cannot read the configuration")); got != 1 {
		t.Errorf("a startup failure exits %d, want 1", got)
	}
}

func TestABackupWithoutExactlyOneTargetIsRefused(t *testing.T) {
	// The arity check runs before the configuration is read, so the refusal
	// is pure routing and opens nothing.
	for name, args := range map[string][]string{
		"no target":   {"backup"},
		"two targets": {"backup", "one", "two"},
	} {
		t.Run(name, func(t *testing.T) {
			err := dispatch(args, refusingLoader(t))
			if err == nil {
				t.Fatal("the arity mistake was accepted")
			}
			if !strings.Contains(err.Error(), "backup needs one target directory") {
				t.Errorf("the refusal does not say what was wrong: %v", err)
			}
		})
	}
}

func TestAnImportAuditWithoutExactlyOneFileIsRefused(t *testing.T) {
	for name, args := range map[string][]string{
		"no file":   {"import-audit"},
		"two files": {"import-audit", "one", "two"},
	} {
		t.Run(name, func(t *testing.T) {
			err := dispatch(args, refusingLoader(t))
			if err == nil {
				t.Fatal("the arity mistake was accepted")
			}
			if !strings.Contains(err.Error(), "import-audit needs one file to read") {
				t.Errorf("the refusal does not say what was wrong: %v", err)
			}
		})
	}
}

func TestBackupRoutesToTheBackupCommandWithTheInjectedConfig(t *testing.T) {
	// The loader hands the runner a configuration aimed at an empty
	// temporary directory. The routed command then fails on the missing
	// database, and naming the injected path in the refusal is the proof
	// that the configuration travelled into the command.
	dir := t.TempDir()
	cfg := &config.Config{DBPath: filepath.Join(dir, "jbound.db")}
	loader := func() (*config.Config, error) { return cfg, nil }

	err := dispatch([]string{"backup", filepath.Join(dir, "copy")}, loader)
	if err == nil {
		t.Fatal("a backup against an empty data directory succeeded")
	}
	if !strings.Contains(err.Error(), cfg.DBPath) {
		t.Errorf("the failure does not name the injected database path: %v", err)
	}
}

func TestImportAuditRoutesToTheImportCommandWithTheInjectedConfig(t *testing.T) {
	// The file the operator named is opened before the database, so the
	// refusal names that path: the proof the operator's argument travelled
	// into the import command and no database was touched.
	dir := t.TempDir()
	cfg := &config.Config{DBPath: filepath.Join(dir, "jbound.db")}
	loader := func() (*config.Config, error) { return cfg, nil }

	missing := filepath.Join(dir, "audit.csv")
	err := dispatch([]string{"import-audit", missing}, loader)
	if err == nil {
		t.Fatal("an import of a missing file succeeded")
	}
	if !strings.Contains(err.Error(), missing) {
		t.Errorf("the failure does not name the file: %v", err)
	}
}

func TestAConfigurationRefusalStopsTheCommandBeforeItRuns(t *testing.T) {
	// A configuration the panel cannot read is a plain failure, not a usage
	// mistake: it travels as the loader's own error and earns exit code 1.
	sentinel := errors.New("cannot read the configuration")
	err := dispatch([]string{"backup", "somewhere"},
		func() (*config.Config, error) { return nil, sentinel })
	if !errors.Is(err, sentinel) {
		t.Errorf("the refusal came back as %v, want the loader's own error", err)
	}
}
