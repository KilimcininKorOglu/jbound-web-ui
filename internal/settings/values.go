package settings

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"
)

// ErrInvalid marks a value the panel refuses to store.
var ErrInvalid = errors.New("invalid setting")

// Values is one immutable snapshot of every setting.
//
// A snapshot rather than a live map, so a request that reads two settings sees
// the same generation of both.
type Values struct {
	raw map[string]string
}

// NewValues builds a snapshot from stored rows.
//
// A key with no row falls back to the registry default, which is why an empty
// table behaves exactly like the panel did before the table existed. A stored
// value that no longer parses falls back the same way rather than taking the
// panel down, and the caller reports it.
func NewValues(stored map[string]string) (*Values, []string) {
	values := &Values{raw: make(map[string]string, len(registry))}
	var refused []string

	for _, definition := range registry {
		value, ok := stored[definition.Key]
		if !ok {
			values.raw[definition.Key] = definition.Default
			continue
		}
		if err := Validate(definition, value); err != nil {
			refused = append(refused, err.Error())
			values.raw[definition.Key] = definition.Default
			continue
		}
		values.raw[definition.Key] = value
	}
	return values, refused
}

// All returns the snapshot as the settings page reads it.
func (v *Values) All() map[string]string {
	out := make(map[string]string, len(v.raw))
	maps.Copy(out, v.raw)
	return out
}

// String returns one value as it is stored.
func (v *Values) String(key string) string { return v.raw[key] }

// Duration returns a duration setting.
//
// The value was validated before it was stored, so a parse failure here can
// only mean the key is not a duration, which is a programming error rather
// than a configuration one.
func (v *Values) Duration(key string) time.Duration {
	value, err := time.ParseDuration(v.raw[key])
	if err != nil {
		return mustDefaultDuration(key)
	}
	return value
}

// Int returns an integer setting.
func (v *Values) Int(key string) int {
	value, err := strconv.Atoi(v.raw[key])
	if err != nil {
		return mustDefaultInt(key)
	}
	return value
}

// Bool returns a boolean setting.
func (v *Values) Bool(key string) bool {
	value, err := strconv.ParseBool(v.raw[key])
	if err != nil {
		return false
	}
	return value
}

func mustDefaultDuration(key string) time.Duration {
	definition, ok := Lookup(key)
	if !ok {
		return 0
	}
	value, _ := time.ParseDuration(definition.Default)
	return value
}

func mustDefaultInt(key string) int {
	definition, ok := Lookup(key)
	if !ok {
		return 0
	}
	value, _ := strconv.Atoi(definition.Default)
	return value
}

// Validate reports whether one value fits its definition.
func Validate(definition Definition, value string) error {
	trimmed := strings.TrimSpace(value)

	switch definition.Kind {
	case KindDuration:
		parsed, err := time.ParseDuration(trimmed)
		if err != nil {
			return fmt.Errorf("%w: %s must be a duration such as 30m, got %q",
				ErrInvalid, definition.Key, value)
		}
		if parsed < definition.Min || parsed > definition.Max {
			return fmt.Errorf("%w: %s must be between %s and %s, got %s",
				ErrInvalid, definition.Key, definition.Min, definition.Max, parsed)
		}

	case KindInt:
		parsed, err := strconv.Atoi(trimmed)
		if err != nil {
			return fmt.Errorf("%w: %s must be a whole number, got %q",
				ErrInvalid, definition.Key, value)
		}
		if parsed < definition.MinInt || parsed > definition.MaxInt {
			return fmt.Errorf("%w: %s must be between %d and %d, got %d",
				ErrInvalid, definition.Key, definition.MinInt, definition.MaxInt, parsed)
		}

	case KindBool:
		if _, err := strconv.ParseBool(trimmed); err != nil {
			return fmt.Errorf("%w: %s must be true or false, got %q",
				ErrInvalid, definition.Key, value)
		}

	case KindEnum:
		if !slices.Contains(definition.Options, trimmed) {
			return fmt.Errorf("%w: %s must be one of %s, got %q",
				ErrInvalid, definition.Key, strings.Join(definition.Options, ", "), value)
		}

	default:
		return fmt.Errorf("%w: %s has the unknown kind %q",
			ErrInvalid, definition.Key, definition.Kind)
	}
	return nil
}

// ValidateAll checks a whole submission and reports every problem in one pass.
//
// One round of corrections rather than one per field, which is how the
// configuration loader reports its own errors.
func ValidateAll(submitted map[string]string) error {
	var problems []string

	for key, value := range submitted {
		definition, ok := Lookup(key)
		if !ok {
			problems = append(problems,
				fmt.Sprintf("%s is not a setting of this panel", key))
			continue
		}
		if err := Validate(definition, value); err != nil {
			problems = append(problems, strings.TrimPrefix(err.Error(), ErrInvalid.Error()+": "))
		}
	}

	// The cross field rules run on the merged view, because a submission may
	// carry one of the pair and the stored value carries the other.
	if len(problems) == 0 {
		problems = append(problems, crossRules(submitted)...)
	}

	if len(problems) > 0 {
		slices.Sort(problems)
		return fmt.Errorf("%w: %s", ErrInvalid, strings.Join(problems, "; "))
	}
	return nil
}

// crossRules holds the rules that read more than one setting.
func crossRules(merged map[string]string) []string {
	var problems []string

	refresh, refreshOK := duration(merged, CacheRefreshInterval)
	stale, staleOK := duration(merged, CacheStaleAfter)
	if refreshOK && staleOK && stale <= refresh {
		problems = append(problems, fmt.Sprintf(
			"cache stale after (%s) must be longer than the cache refresh interval (%s)",
			stale, refresh))
	}

	idle, idleOK := duration(merged, SessionIdleTimeout)
	lifetime, lifetimeOK := duration(merged, SessionLifetime)
	if idleOK && lifetimeOK && lifetime < idle {
		problems = append(problems, fmt.Sprintf(
			"session lifetime (%s) must be at least the idle timeout (%s)",
			lifetime, idle))
	}
	return problems
}

func duration(values map[string]string, key string) (time.Duration, bool) {
	raw, ok := values[key]
	if !ok {
		return 0, false
	}
	parsed, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil {
		return 0, false
	}
	return parsed, true
}
