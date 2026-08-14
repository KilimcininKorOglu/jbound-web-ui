// Package logging carries a request scoped logger through the context.
//
// Every line a request produces is written by a different package, so the
// field that ties them together cannot be passed as an argument. It travels
// with the context the request already carries.
package logging

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
)

// Field is the attribute a request scoped logger carries.
//
// It is a constant rather than a string at each call site, because a second
// spelling would split the very lines this exists to join.
const Field = "request_id"

type contextKey struct{}

// NewContext returns a context that carries the logger.
func NewContext(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, contextKey{}, logger)
}

// From returns the logger of this context.
//
// A context with none answers with the default logger, so a background loop
// keeps logging exactly as it did before this package existed.
func From(ctx context.Context) *slog.Logger {
	if logger, ok := ctx.Value(contextKey{}).(*slog.Logger); ok {
		return logger
	}
	return slog.Default()
}

// NewID returns the identifier of one request.
//
// Eight bytes. This is a label rather than a secret: it names a line in a log
// an operator already has, so it needs to be unique among the requests one
// panel serves, not unguessable.
func NewID() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		// A panel that cannot read random bytes has larger problems, and
		// losing the correlation field is not worth failing a request over.
		return "unknown"
	}
	return hex.EncodeToString(buf)
}

// level is how much the panel logs, and it is changeable while it runs.
//
// A handler reads it on every record, so an operator raising the level during
// an incident keeps the connections, the cache and the requests that were
// being diagnosed. A restart would take all three away.
var level slog.LevelVar

// Level is what a handler is built with.
func Level() *slog.LevelVar { return &level }

// SetLevel changes how much the panel logs from here on.
func SetLevel(value slog.Level) { level.Set(value) }

// Levels are the names an operator writes.
var levels = map[string]slog.Level{
	"debug": slog.LevelDebug,
	"info":  slog.LevelInfo,
	"warn":  slog.LevelWarn,
	"error": slog.LevelError,
}

// ParseLevel reads one level name.
func ParseLevel(name string) (slog.Level, error) {
	value, ok := levels[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return 0, fmt.Errorf("log level must be one of debug, info, warn, error, got %q", name)
	}
	return value, nil
}
