package settings

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"sync/atomic"
	"time"
)

// Store persists the settings an operator changed.
//
// Only the changed rows are written. A key the operator left alone keeps
// falling back to the registry default, so a default that moves in a later
// release moves for every panel that never overrode it.
type Store interface {
	Load(ctx context.Context) (map[string]string, error)
	Save(ctx context.Context, values map[string]string) error
}

// Service answers what the panel is configured to do right now.
//
// Every reader goes through an accessor, so a saved change takes effect on the
// next read rather than on the next restart. The snapshot is swapped as a
// whole, which is why a reader never sees half of an update.
type Service struct {
	store  Store
	values atomic.Pointer[Values]
}

// NewService builds the service with the registry defaults in place.
//
// The defaults are there before the first load, so a caller that reads a
// setting during startup gets the same answer the panel had before this
// package existed.
func NewService(store Store) *Service {
	service := &Service{store: store}

	defaults, _ := NewValues(nil)
	service.values.Store(defaults)
	return service
}

// Load reads the stored settings into the snapshot.
func (s *Service) Load(ctx context.Context) error {
	stored, err := s.store.Load(ctx)
	if err != nil {
		return fmt.Errorf("cannot read the settings: %w", err)
	}

	values, refused := NewValues(stored)
	for _, problem := range refused {
		// A stored value the registry no longer accepts is reported and
		// replaced by the default. Refusing to start over it would leave the
		// operator with no interface to correct it in.
		slog.Error("stored setting refused, using the default", "problem", problem)
	}

	s.values.Store(values)
	return nil
}

// Values returns the current snapshot.
func (s *Service) Values() *Values { return s.values.Load() }

// Save validates a submission, stores it and reloads the snapshot.
//
// The submission is merged over the current values first, so a form that
// carries one card of the page cannot blank the others, and the cross field
// rules see the whole picture.
func (s *Service) Save(ctx context.Context, submitted map[string]string) error {
	merged := s.Values().All()
	maps.Copy(merged, submitted)

	if err := ValidateAll(merged); err != nil {
		return err
	}
	if err := s.store.Save(ctx, merged); err != nil {
		return fmt.Errorf("cannot store the settings: %w", err)
	}
	return s.Load(ctx)
}

// Duration returns one duration setting.
func (s *Service) Duration(key string) time.Duration { return s.Values().Duration(key) }

// Int returns one integer setting.
func (s *Service) Int(key string) int { return s.Values().Int(key) }

// Bool returns one boolean setting.
func (s *Service) Bool(key string) bool { return s.Values().Bool(key) }

// String returns one setting as it is stored.
func (s *Service) String(key string) string { return s.Values().String(key) }

// DurationOf returns an accessor for one duration setting.
//
// The components of the panel take these rather than a value, which is what
// makes a saved change take effect without a restart.
func (s *Service) DurationOf(key string) func() time.Duration {
	return func() time.Duration { return s.Duration(key) }
}

// IntOf returns an accessor for one integer setting.
func (s *Service) IntOf(key string) func() int {
	return func() int { return s.Int(key) }
}

// BoolOf returns an accessor for one boolean setting.
func (s *Service) BoolOf(key string) func() bool {
	return func() bool { return s.Bool(key) }
}

// StringOf returns an accessor for one text or enum setting.
func (s *Service) StringOf(key string) func() string {
	return func() string { return s.String(key) }
}

// Fixed turns a constant into an accessor.
//
// It exists for the callers that have no settings service: the tests, and any
// component built for a single run.
func Fixed[T any](value T) func() T {
	return func() T { return value }
}
