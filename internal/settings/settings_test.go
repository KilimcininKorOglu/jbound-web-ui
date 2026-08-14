package settings

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeStore keeps the stored rows in memory.
type fakeStore struct {
	rows     map[string]string
	loadErr  error
	saveErr  error
	saveCall int
}

func newFakeStore() *fakeStore { return &fakeStore{rows: map[string]string{}} }

func (f *fakeStore) Load(context.Context) (map[string]string, error) {
	if f.loadErr != nil {
		return nil, f.loadErr
	}
	out := map[string]string{}
	maps.Copy(out, f.rows)
	return out, nil
}

func (f *fakeStore) Save(_ context.Context, values map[string]string) error {
	f.saveCall++
	if f.saveErr != nil {
		return f.saveErr
	}
	maps.Copy(f.rows, values)
	return nil
}

// An empty table has to behave exactly like the panel did before the table
// existed, which is what makes the migration safe to apply to a live install.
func TestAnEmptyTableGivesTheRegistryDefaults(t *testing.T) {
	values, refused := NewValues(nil)
	if len(refused) != 0 {
		t.Fatalf("an empty table was refused: %v", refused)
	}

	if got := values.Duration(SessionIdleTimeout); got != 30*time.Minute {
		t.Errorf("session idle timeout = %s, want 30m", got)
	}
	if got := values.Duration(SessionLifetime); got != 24*time.Hour {
		t.Errorf("session lifetime = %s, want 24h", got)
	}
	if got := values.Int(RecordsPerPage); got != 25 {
		t.Errorf("records per page = %d, want 25", got)
	}
	if !values.Bool(SIEMForwardingEnabled) {
		t.Error("SIEM forwarding is off by default, want on")
	}
	if got := values.String(DefaultLanguage); got != "en" {
		t.Errorf("default language = %q, want en", got)
	}
}

// Every definition must parse as its own kind. A default the panel refuses is
// a default that turns the first read into a fallback.
func TestEveryDefaultPassesItsOwnValidation(t *testing.T) {
	for _, definition := range Definitions() {
		if err := Validate(definition, definition.Default); err != nil {
			t.Errorf("%s: %v", definition.Key, err)
		}
	}
}

// A key with no group card would be stored and never shown, so the page and
// the registry are checked against each other rather than kept in step by hand.
func TestEveryDefinitionBelongsToAGroupThePageShows(t *testing.T) {
	known := map[string]bool{}
	for _, name := range Groups() {
		known[name] = true
	}

	for _, definition := range Definitions() {
		if !known[definition.Group] {
			t.Errorf("%s is in the group %q, which the page does not show",
				definition.Key, definition.Group)
		}
	}
}

// A stored value the registry no longer accepts must not take the panel down.
// The operator needs a running interface to correct it in.
func TestAStoredValueThatNoLongerParsesFallsBackToTheDefault(t *testing.T) {
	values, refused := NewValues(map[string]string{
		SessionIdleTimeout: "half an hour",
		RecordsPerPage:     "9000",
	})

	if len(refused) != 2 {
		t.Fatalf("%d value(s) refused, want 2: %v", len(refused), refused)
	}
	if got := values.Duration(SessionIdleTimeout); got != 30*time.Minute {
		t.Errorf("session idle timeout = %s, want the default 30m", got)
	}
	if got := values.Int(RecordsPerPage); got != 25 {
		t.Errorf("records per page = %d, want the default 25", got)
	}
}

func TestValidationRefusesWhatTheRegistryBounds(t *testing.T) {
	cases := []struct {
		name  string
		key   string
		value string
	}{
		{"duration below the minimum", SessionIdleTimeout, "10s"},
		{"duration above the maximum", SessionIdleTimeout, "48h"},
		{"duration that does not parse", CacheRefreshInterval, "soon"},
		{"count below the minimum", RecordsPerPage, "1"},
		{"count above the maximum", FleetMaxConcurrent, "512"},
		{"count that does not parse", FleetMaxConcurrent, "four"},
		{"boolean that does not parse", SIEMForwardingEnabled, "sometimes"},
		{"enum outside the options", DefaultTheme, "neon"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			definition, ok := Lookup(tc.key)
			if !ok {
				t.Fatalf("%s is not a setting", tc.key)
			}
			err := Validate(definition, tc.value)
			if err == nil {
				t.Fatalf("%s = %q was accepted", tc.key, tc.value)
			}
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("error does not wrap ErrInvalid: %v", err)
			}
			if !strings.Contains(err.Error(), tc.key) {
				t.Errorf("error does not name the setting: %v", err)
			}
		})
	}
}

// One round of corrections rather than one per field, which is how the
// configuration loader reports its own errors.
func TestValidateAllReportsEveryProblemAtOnce(t *testing.T) {
	err := ValidateAll(map[string]string{
		SessionIdleTimeout: "10s",
		RecordsPerPage:     "1",
		"invented_key":     "1",
	})
	if err == nil {
		t.Fatal("three broken values were accepted")
	}

	for _, want := range []string{SessionIdleTimeout, RecordsPerPage, "invented_key"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %s:\n%v", want, err)
		}
	}
}

// A cache marked stale before it is refreshed would show every row with a
// warning for ever, so the pair is checked against each other.
func TestTheStaleWindowMustOutlastTheRefreshInterval(t *testing.T) {
	err := ValidateAll(map[string]string{
		CacheRefreshInterval: "10m",
		CacheStaleAfter:      "5m",
	})
	if err == nil {
		t.Fatal("a stale window shorter than the refresh interval was accepted")
	}
	if !strings.Contains(err.Error(), "refresh interval") {
		t.Errorf("error does not explain the pair: %v", err)
	}
}

// A lifetime under the idle timeout would sign a user out at a moment the idle
// rule says is still live, so the pair is checked as well.
func TestTheLifetimeMustCoverTheIdleTimeout(t *testing.T) {
	err := ValidateAll(map[string]string{
		SessionIdleTimeout: "2h",
		SessionLifetime:    "1h",
	})
	if err == nil {
		t.Fatal("a lifetime shorter than the idle timeout was accepted")
	}
	if !strings.Contains(err.Error(), "idle timeout") {
		t.Errorf("error does not explain the pair: %v", err)
	}
}

// The point of the accessors: a saved change is in effect on the next read
// rather than on the next restart.
func TestASavedValueIsInEffectOnTheNextRead(t *testing.T) {
	service := NewService(newFakeStore())
	ctx := context.Background()

	idle := service.DurationOf(SessionIdleTimeout)
	if got := idle(); got != 30*time.Minute {
		t.Fatalf("idle timeout = %s, want the default 30m", got)
	}

	if err := service.Save(ctx, map[string]string{SessionIdleTimeout: "45m"}); err != nil {
		t.Fatalf("Save returned an error: %v", err)
	}
	if got := idle(); got != 45*time.Minute {
		t.Errorf("idle timeout = %s after the save, want 45m", got)
	}
}

// A submission that carries one card must not blank the others.
func TestASubmissionOfOneCardKeepsTheRest(t *testing.T) {
	store := newFakeStore()
	service := NewService(store)
	ctx := context.Background()

	if err := service.Save(ctx, map[string]string{RecordsPerPage: "50"}); err != nil {
		t.Fatalf("Save returned an error: %v", err)
	}

	if got := service.Int(RecordsPerPage); got != 50 {
		t.Errorf("records per page = %d, want 50", got)
	}
	if got := service.Duration(SessionIdleTimeout); got != 30*time.Minute {
		t.Errorf("session idle timeout = %s, want the untouched 30m", got)
	}
	if len(store.rows) != len(Definitions()) {
		t.Errorf("%d row(s) stored, want the whole set of %d",
			len(store.rows), len(Definitions()))
	}
}

// All or nothing. Half a submission would leave the panel running on a
// combination the operator never approved.
func TestARefusedSubmissionChangesNothing(t *testing.T) {
	store := newFakeStore()
	service := NewService(store)

	err := service.Save(context.Background(), map[string]string{
		RecordsPerPage:     "50",
		SessionIdleTimeout: "10s",
	})
	if err == nil {
		t.Fatal("a submission with a broken value was accepted")
	}
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("error does not wrap ErrInvalid: %v", err)
	}
	if store.saveCall != 0 {
		t.Errorf("the store was written %d time(s), want none", store.saveCall)
	}
	if got := service.Int(RecordsPerPage); got != 25 {
		t.Errorf("records per page = %d, want the unchanged 25", got)
	}
}

func TestLoadReadsWhatTheStoreHolds(t *testing.T) {
	store := newFakeStore()
	store.rows[FleetMaxConcurrent] = "8"

	service := NewService(store)
	if err := service.Load(context.Background()); err != nil {
		t.Fatalf("Load returned an error: %v", err)
	}
	if got := service.Int(FleetMaxConcurrent); got != 8 {
		t.Errorf("fleet concurrency = %d, want 8", got)
	}
}

func TestLoadReportsAStoreThatCannotBeRead(t *testing.T) {
	store := newFakeStore()
	store.loadErr = errors.New("database is locked")

	service := NewService(store)
	if err := service.Load(context.Background()); err == nil {
		t.Fatal("Load hid a store failure")
	}
}

func TestSaveReportsAStoreThatCannotBeWritten(t *testing.T) {
	store := newFakeStore()
	store.saveErr = errors.New("disk is full")

	service := NewService(store)
	err := service.Save(context.Background(), map[string]string{RecordsPerPage: "50"})
	if err == nil {
		t.Fatal("Save hid a store failure")
	}
	if errors.Is(err, ErrInvalid) {
		t.Errorf("a store failure was reported as an invalid value: %v", err)
	}
}

// The accessors are what every component reads, so each kind is exercised.
func TestTheAccessorsAnswerForEveryKind(t *testing.T) {
	service := NewService(newFakeStore())

	if got := service.DurationOf(SSHConnectTimeout)(); got != 10*time.Second {
		t.Errorf("ssh connect timeout = %s, want 10s", got)
	}
	if got := service.IntOf(FleetMaxConcurrent)(); got != 4 {
		t.Errorf("fleet concurrency = %d, want 4", got)
	}
	if !service.BoolOf(SIEMForwardingEnabled)() {
		t.Error("SIEM forwarding accessor says off, want on")
	}
	if got := service.String(DefaultTheme); got != "system" {
		t.Errorf("default theme = %q, want system", got)
	}
	if got := Fixed(7)(); got != 7 {
		t.Errorf("Fixed(7) = %d, want 7", got)
	}
}

// The three typed readers recover the same way, so a value that cannot be
// parsed reads as the default the registry declares rather than as the zero
// value of its kind. The boolean matters most: the only one the panel holds
// defaults to on, and a bare false would turn the audit mirror off quietly.
func TestAValueThatCannotBeParsedReadsAsTheRegistryDefault(t *testing.T) {
	values, _ := NewValues(nil)

	// Past the validation NewValues runs, which is where a snapshot built by
	// hand or a key added to the registry without a row would land.
	values.raw[SIEMForwardingEnabled] = ""
	values.raw[SessionIdleTimeout] = "not a duration"
	values.raw[RecordsPerPage] = "many"

	if !values.Bool(SIEMForwardingEnabled) {
		t.Error("the SIEM mirror reads as off, and the registry declares it on")
	}
	if got := values.Duration(SessionIdleTimeout); got != 30*time.Minute {
		t.Errorf("idle timeout = %s, want 30m", got)
	}
	if got := values.Int(RecordsPerPage); got != 25 {
		t.Errorf("records per page = %d, want 25", got)
	}
}

// A key nobody defined has no default to fall back to, so the typed readers
// answer with the zero value instead of panicking.
func TestAnUnknownKeyReadsAsZero(t *testing.T) {
	values, _ := NewValues(nil)

	if got := values.Duration("invented_key"); got != 0 {
		t.Errorf("duration of an unknown key = %s, want 0", got)
	}
	if got := values.Int("invented_key"); got != 0 {
		t.Errorf("int of an unknown key = %d, want 0", got)
	}
	if values.Bool("invented_key") {
		t.Error("bool of an unknown key is true, want false")
	}
}

// The bounds are the contract of the page. A value at either edge is accepted
// and a value one step past it is not.
func TestTheBoundsOfEveryIntegerSettingHold(t *testing.T) {
	for _, definition := range Definitions() {
		if definition.Kind != KindInt {
			continue
		}
		t.Run(definition.Key, func(t *testing.T) {
			for _, value := range []int{definition.MinInt, definition.MaxInt} {
				if err := Validate(definition, strconv.Itoa(value)); err != nil {
					t.Errorf("%d was refused: %v", value, err)
				}
			}
			for _, value := range []int{definition.MinInt - 1, definition.MaxInt + 1} {
				if err := Validate(definition, strconv.Itoa(value)); err == nil {
					t.Errorf("%d was accepted", value)
				}
			}
		})
	}
}

func TestTheBoundsOfEveryDurationSettingHold(t *testing.T) {
	for _, definition := range Definitions() {
		if definition.Kind != KindDuration {
			continue
		}
		t.Run(definition.Key, func(t *testing.T) {
			for _, value := range []time.Duration{definition.Min, definition.Max} {
				if err := Validate(definition, value.String()); err != nil {
					t.Errorf("%s was refused: %v", value, err)
				}
			}
			past := []time.Duration{definition.Min - time.Second, definition.Max + time.Second}
			for _, value := range past {
				if err := Validate(definition, value.String()); err == nil {
					t.Errorf("%s was accepted", value)
				}
			}
		})
	}
}

// A whitespace padded value is what a form sends when somebody pastes into it.
func TestASurroundedValueIsAccepted(t *testing.T) {
	definition, _ := Lookup(RecordsPerPage)
	if err := Validate(definition, "  50  "); err != nil {
		t.Fatalf("a padded value was refused: %v", err)
	}
}

// A definition with an unknown kind is a programming error, and the validator
// says so rather than accepting the value.
func TestAnUnknownKindIsRefused(t *testing.T) {
	err := Validate(Definition{Key: "made_up", Kind: "colour"}, "blue")
	if err == nil {
		t.Fatal("a definition with an unknown kind was accepted")
	}
	if !strings.Contains(err.Error(), "unknown kind") {
		t.Errorf("error does not name the problem: %v", err)
	}
}

func TestLookupAnswersForEveryRegisteredKey(t *testing.T) {
	for _, definition := range Definitions() {
		found, ok := Lookup(definition.Key)
		if !ok {
			t.Errorf("%s is in the registry but Lookup does not find it", definition.Key)
			continue
		}
		if found.Group != definition.Group {
			t.Errorf("%s: Lookup returned the group %q, want %q",
				definition.Key, found.Group, definition.Group)
		}
	}
	if _, ok := Lookup("invented_key"); ok {
		t.Error("Lookup answered for a key nobody defined")
	}
}

// Definitions hands out a copy, so a caller that sorts or edits it cannot
// change what the next reader sees.
func TestDefinitionsHandsOutACopy(t *testing.T) {
	first := Definitions()
	first[0].Default = "changed"

	if Definitions()[0].Default == "changed" {
		t.Error("editing the returned slice changed the registry")
	}
}

func TestAllHandsOutACopy(t *testing.T) {
	values, _ := NewValues(nil)
	all := values.All()
	all[RecordsPerPage] = "changed"

	if values.String(RecordsPerPage) == "changed" {
		t.Error("editing the returned map changed the snapshot")
	}
}

// The registry is what the panel reads its behaviour from, so a duplicated key
// would mean one of the two entries is silently ignored.
func TestNoKeyIsDefinedTwice(t *testing.T) {
	seen := map[string]bool{}
	for _, definition := range Definitions() {
		if seen[definition.Key] {
			t.Errorf("%s is defined twice", definition.Key)
		}
		seen[definition.Key] = true
	}
}

func ExampleService_DurationOf() {
	service := NewService(newFakeStore())
	idle := service.DurationOf(SessionIdleTimeout)

	fmt.Println(idle())
	// Output: 30m0s
}

func TestATextSettingIsBoundedAndPrintable(t *testing.T) {
	// The panel name travels into a page title and a log line alike, where a
	// control character reads as nothing and hides what follows it.
	definition, ok := Lookup(PanelName)
	if !ok {
		t.Fatal("the panel name is not in the registry")
	}

	cases := map[string]bool{
		"JanBound DNS Panel":    true,
		"Şirket DNS Paneli":     true,
		"":                      false,
		"   ":                   false,
		strings.Repeat("x", 61): false,
		strings.Repeat("x", 60): true,
		"broken\x00name":        false,
		"two\nlines":            false,
	}

	for value, want := range cases {
		err := Validate(definition, value)
		if (err == nil) != want {
			t.Errorf("Validate(%q) = %v, want accepted=%v", value, err, want)
		}
	}
}

func TestAServerSettingAcceptsNothingOrAnIdentifier(t *testing.T) {
	// Empty is a legitimate state: no source server has been chosen. Whether
	// the identifier names a live server is a question this package cannot ask.
	definition, ok := Lookup(SourceServerID)
	if !ok {
		t.Fatal("the source server is not in the registry")
	}

	cases := map[string]bool{
		"":     true,
		"1":    true,
		"4711": true,
		"0":    false,
		"-1":   false,
		"two":  false,
		"1.5":  false,
	}

	for value, want := range cases {
		err := Validate(definition, value)
		if (err == nil) != want {
			t.Errorf("Validate(%q) = %v, want accepted=%v", value, err, want)
		}
	}
}

func TestAnUnchosenSourceReadsAsZero(t *testing.T) {
	values := mustValues(t, map[string]string{})
	if got := values.Int64(SourceServerID); got != 0 {
		t.Errorf("Int64 = %d, want 0 while nothing is chosen", got)
	}

	values = mustValues(t, map[string]string{SourceServerID: "7"})
	if got := values.Int64(SourceServerID); got != 7 {
		t.Errorf("Int64 = %d, want 7", got)
	}
}

// mustValues builds a snapshot and fails on a value the registry refuses.
func mustValues(t *testing.T, stored map[string]string) *Values {
	t.Helper()

	values, refused := NewValues(stored)
	if len(refused) != 0 {
		t.Fatalf("the snapshot refused %v", refused)
	}
	return values
}
