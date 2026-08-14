package main

import (
	"log/slog"
	"os"
	"syscall"
	"testing"
	"time"

	"unbound-web/internal/logging"
)

func TestASignalRaisesTheLogLevelAndLowersItAgain(t *testing.T) {
	// The one Debug line in the panel, the SSH connection that dropped out of
	// the pool, was unreachable in every deployment. Reaching it used to mean
	// a rebuild and a restart, and the restart takes away the pool state the
	// operator was trying to look at.
	t.Cleanup(func() { logging.SetLevel(slog.LevelInfo) })
	logging.SetLevel(slog.LevelInfo)

	signals := make(chan os.Signal, 1)
	go toggleLogLevel(t.Context(), signals, slog.LevelInfo)

	signals <- syscall.SIGUSR1
	waitForLevel(t, slog.LevelDebug)

	// The same lever turns it back off, so a panel left at debug is a choice
	// rather than an accident.
	signals <- syscall.SIGUSR1
	waitForLevel(t, slog.LevelInfo)
}

// waitForLevel waits for the level the signal asked for.
func waitForLevel(t *testing.T, want slog.Level) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if logging.Level().Level() == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("level = %v, want %v", logging.Level().Level(), want)
}
