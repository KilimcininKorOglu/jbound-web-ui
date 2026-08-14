package logging

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestAContextWithNoLoggerAnswersWithTheDefault(t *testing.T) {
	// A background loop keeps logging exactly as it did before this package
	// existed, so no caller has to ask whether it is inside a request.
	if From(context.Background()) != slog.Default() {
		t.Error("an empty context did not answer with the default logger")
	}
}

func TestTheLoggerOfAContextIsTheOneThatWasPutThere(t *testing.T) {
	var buffer bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buffer, nil)).With(Field, "abc123")

	From(NewContext(context.Background(), logger)).Info("hello")

	if !strings.Contains(buffer.String(), Field+"=abc123") {
		t.Errorf("the line does not carry the field: %s", buffer.String())
	}
}

func TestTwoRequestsGetTwoIdentifiers(t *testing.T) {
	first, second := NewID(), NewID()

	if first == second {
		t.Errorf("both requests were named %q", first)
	}
	if first == "" || first == "unknown" {
		t.Errorf("the identifier reads %q", first)
	}
}

func TestTheLevelIsReadOnEveryRecord(t *testing.T) {
	// The point of the variable is that an operator raises the level while the
	// panel runs, so the connections and the requests being diagnosed survive.
	var buffer bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buffer, &slog.HandlerOptions{Level: Level()}))

	SetLevel(slog.LevelInfo)
	t.Cleanup(func() { SetLevel(slog.LevelInfo) })

	logger.Debug("keepalive failed")
	if buffer.Len() != 0 {
		t.Errorf("a debug line was written at info: %s", buffer.String())
	}

	SetLevel(slog.LevelDebug)
	logger.Debug("keepalive failed")
	if !strings.Contains(buffer.String(), "keepalive failed") {
		t.Errorf("the line is still missing after the level was raised: %s", buffer.String())
	}
}

func TestALevelNameIsReadOrRefused(t *testing.T) {
	for name, want := range map[string]slog.Level{
		"debug": slog.LevelDebug, "info": slog.LevelInfo,
		"WARN": slog.LevelWarn, " error ": slog.LevelError,
	} {
		got, err := ParseLevel(name)
		if err != nil {
			t.Errorf("ParseLevel(%q) returned %v", name, err)
		}
		if got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", name, got, want)
		}
	}

	// A typo in the environment file is a startup failure that names itself,
	// not a panel that quietly logs at a level nobody chose.
	if _, err := ParseLevel("verbose"); err == nil {
		t.Error("an unknown level was accepted")
	}
}
