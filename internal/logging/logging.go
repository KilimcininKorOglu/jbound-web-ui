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
	"log/slog"
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
