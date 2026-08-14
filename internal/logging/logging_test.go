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
