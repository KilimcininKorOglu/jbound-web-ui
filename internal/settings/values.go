package settings

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
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

// Int64 returns an identifier setting. It answers zero when nothing is chosen.
func (v *Values) Int64(key string) int64 {
	value, err := strconv.ParseInt(strings.TrimSpace(v.raw[key]), 10, 64)
	if err != nil {
		return 0
	}
	return value
}

// Bool returns a boolean setting.
//
// A bare false here would contradict a key whose declared default is true, and
// it would do it in the quiet direction: the only boolean the panel holds turns
// the audit mirror on.
func (v *Values) Bool(key string) bool {
	value, err := strconv.ParseBool(v.raw[key])
	if err != nil {
		return mustDefaultBool(key)
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

func mustDefaultBool(key string) bool {
	definition, ok := Lookup(key)
	if !ok {
		return false
	}
	value, _ := strconv.ParseBool(definition.Default)
	return value
}

// The problem codes. A refusal carries one of these and its values rather than
// a sentence, so the panel can print it in the language of the reader while the
// log keeps its English.
const (
	CodeNotASetting      = "not_a_setting"
	CodeDuration         = "duration"
	CodeDurationRange    = "duration_range"
	CodeInt              = "int"
	CodeIntRange         = "int_range"
	CodeBool             = "bool"
	CodeEnum             = "enum"
	CodeUnknownKind      = "unknown_kind"
	CodeStaleTooShort    = "stale_too_short"
	CodeLifetimeTooShort = "lifetime_too_short"

	CodeTextEmpty      = "text_empty"
	CodeTextLength     = "text_length"
	CodeTextCharacters = "text_characters"
	CodeServerRef      = "server_ref"
	CodeUnknownServer  = "unknown_server"
)

// problemCodes is every code the package raises.
var problemCodes = []string{
	CodeNotASetting, CodeDuration, CodeDurationRange, CodeInt, CodeIntRange,
	CodeBool, CodeEnum, CodeUnknownKind, CodeStaleTooShort, CodeLifetimeTooShort,
	CodeTextEmpty, CodeTextLength, CodeTextCharacters, CodeServerRef,
	CodeUnknownServer,
}

// Codes returns every problem code.
//
// A caller that writes these out for a reader is checked against this list, so
// a code added here cannot reach a page as a key nobody translated.
func Codes() []string { return slices.Clone(problemCodes) }

// Problem is one reason the panel refuses a value.
type Problem struct {
	// Key is the setting the problem belongs to.
	Key string

	// Code says which problem it is, and Args carries its values in the order
	// the sentence needs them.
	Code string
	Args []any
}

// Error renders the problem in English, which is what a log reads.
func (p *Problem) Error() string {
	return fmt.Sprintf("%s: %s %s", ErrInvalid, p.Key, p.sentence())
}

// Unwrap lets a caller ask whether a value was refused at all.
func (p *Problem) Unwrap() error { return ErrInvalid }

func (p *Problem) sentence() string {
	switch p.Code {
	case CodeNotASetting:
		return "is not a setting of this panel"
	case CodeDuration:
		return fmt.Sprintf("must be a duration such as 30m, got %q", p.Args...)
	case CodeDurationRange, CodeIntRange:
		return fmt.Sprintf("must be between %v and %v, got %v", p.Args...)
	case CodeInt:
		return fmt.Sprintf("must be a whole number, got %q", p.Args...)
	case CodeBool:
		return fmt.Sprintf("must be true or false, got %q", p.Args...)
	case CodeEnum:
		return fmt.Sprintf("must be one of %v, got %q", p.Args...)
	case CodeUnknownKind:
		return fmt.Sprintf("has the unknown kind %q", p.Args...)
	case CodeStaleTooShort:
		return fmt.Sprintf("(%v) must be longer than the cache refresh interval (%v)", p.Args...)
	case CodeTextEmpty:
		return "cannot be empty"
	case CodeTextLength:
		return fmt.Sprintf("must be at most %v characters, got %v", p.Args...)
	case CodeTextCharacters:
		return "cannot hold a control character"
	case CodeServerRef:
		return fmt.Sprintf("must name a server, got %q", p.Args...)
	case CodeUnknownServer:
		return "must name a server that exists and is enabled"
	case CodeLifetimeTooShort:
		return fmt.Sprintf("(%v) must be at least the idle timeout (%v)", p.Args...)
	default:
		return "was refused"
	}
}

// Validate reports whether one value fits its definition.
func Validate(definition Definition, value string) error {
	trimmed := strings.TrimSpace(value)
	refuse := func(code string, args ...any) error {
		return &Problem{Key: definition.Key, Code: code, Args: args}
	}

	switch definition.Kind {
	case KindDuration:
		parsed, err := time.ParseDuration(trimmed)
		if err != nil {
			return refuse(CodeDuration, value)
		}
		if parsed < definition.Min || parsed > definition.Max {
			return refuse(CodeDurationRange, Human(definition.Min), Human(definition.Max), Human(parsed))
		}

	case KindInt:
		parsed, err := strconv.Atoi(trimmed)
		if err != nil {
			return refuse(CodeInt, value)
		}
		if parsed < definition.MinInt || parsed > definition.MaxInt {
			return refuse(CodeIntRange, definition.MinInt, definition.MaxInt, parsed)
		}

	case KindBool:
		if _, err := strconv.ParseBool(trimmed); err != nil {
			return refuse(CodeBool, value)
		}

	case KindEnum:
		if !slices.Contains(definition.Options, trimmed) {
			return refuse(CodeEnum, strings.Join(definition.Options, ", "), value)
		}

	case KindText:
		if trimmed == "" {
			return refuse(CodeTextEmpty)
		}
		if definition.MaxLen > 0 && utf8.RuneCountInString(trimmed) > definition.MaxLen {
			return refuse(CodeTextLength, definition.MaxLen, utf8.RuneCountInString(trimmed))
		}
		// A control character would travel into a page title and a log line
		// alike, where it reads as nothing and hides what follows it.
		if strings.ContainsFunc(trimmed, unicode.IsControl) {
			return refuse(CodeTextCharacters)
		}

	case KindServer:
		// Empty means no server was chosen, which is a legitimate state.
		if trimmed == "" {
			return nil
		}
		id, err := strconv.ParseInt(trimmed, 10, 64)
		if err != nil || id <= 0 {
			return refuse(CodeServerRef, value)
		}

	default:
		return refuse(CodeUnknownKind, definition.Kind)
	}
	return nil
}

// Refusal is what a submission the panel will not store comes back as.
//
// The problems are kept by key as well as in one sentence, so the form can mark
// the controls that were refused. A message that names a setting in prose still
// leaves the reader to find it among fifteen fields.
type Refusal struct {
	// Fields maps a setting key to its problems. A rule that reads two settings
	// is filed under both, because either one of them can be the correction.
	Fields map[string][]*Problem
}

// Error renders every problem as one sentence.
func (r *Refusal) Error() string {
	var sentences []string
	for _, problem := range r.Problems() {
		sentences = append(sentences,
			strings.TrimPrefix(problem.Error(), ErrInvalid.Error()+": "))
	}
	return fmt.Sprintf("%s: %s", ErrInvalid, strings.Join(sentences, "; "))
}

// Unwrap lets a caller ask whether the submission was refused at all.
func (r *Refusal) Unwrap() error { return ErrInvalid }

// Problems returns every problem once, in a stable order.
//
// A rule that reads two settings is filed under both of them and is one problem
// here, because a reader is told it once.
func (r *Refusal) Problems() []*Problem {
	var problems []*Problem
	for _, key := range slices.Sorted(maps.Keys(r.Fields)) {
		for _, problem := range r.Fields[key] {
			if !slices.Contains(problems, problem) {
				problems = append(problems, problem)
			}
		}
	}
	return problems
}

// Of returns the first problem of one setting, or nil.
func (r *Refusal) Of(key string) *Problem {
	if r == nil || len(r.Fields[key]) == 0 {
		return nil
	}
	return r.Fields[key][0]
}

func (r *Refusal) add(problem *Problem, keys ...string) {
	if r.Fields == nil {
		r.Fields = map[string][]*Problem{}
	}
	for _, key := range keys {
		r.Fields[key] = append(r.Fields[key], problem)
	}
}

// ValidateAll checks a whole submission and reports every problem in one pass.
//
// One round of corrections rather than one per field, which is how the
// configuration loader reports its own errors.
func ValidateAll(submitted map[string]string) error {
	refusal := &Refusal{}

	for key, value := range submitted {
		definition, ok := Lookup(key)
		if !ok {
			refusal.add(&Problem{Key: key, Code: CodeNotASetting, Args: []any{key}}, key)
			continue
		}

		if problem, ok := errors.AsType[*Problem](Validate(definition, value)); ok {
			refusal.add(problem, key)
		}
	}

	// The cross field rules run on the merged view, because a submission may
	// carry one of the pair and the stored value carries the other. They run
	// only on values that parsed, so a reader is not told two things at once.
	if len(refusal.Fields) == 0 {
		for _, rule := range crossRules(submitted) {
			refusal.add(rule.problem, rule.keys...)
		}
	}

	if len(refusal.Fields) == 0 {
		return nil
	}
	return refusal
}

// crossProblem is one broken rule and the settings it reads.
type crossProblem struct {
	keys    []string
	problem *Problem
}

// crossRules holds the rules that read more than one setting.
func crossRules(merged map[string]string) []crossProblem {
	var problems []crossProblem

	refresh, refreshOK := duration(merged, CacheRefreshInterval)
	stale, staleOK := duration(merged, CacheStaleAfter)
	if refreshOK && staleOK && stale <= refresh {
		problems = append(problems, crossProblem{
			keys: []string{CacheRefreshInterval, CacheStaleAfter},
			problem: &Problem{
				Key:  CacheStaleAfter,
				Code: CodeStaleTooShort,
				Args: []any{Human(stale), Human(refresh)},
			},
		})
	}

	idle, idleOK := duration(merged, SessionIdleTimeout)
	lifetime, lifetimeOK := duration(merged, SessionLifetime)
	if idleOK && lifetimeOK && lifetime < idle {
		problems = append(problems, crossProblem{
			keys: []string{SessionIdleTimeout, SessionLifetime},
			problem: &Problem{
				Key:  SessionLifetime,
				Code: CodeLifetimeTooShort,
				Args: []any{Human(lifetime), Human(idle)},
			},
		})
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
