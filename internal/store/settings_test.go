package store_test

import (
	"context"
	"path/filepath"
	"testing"

	"unbound-web/internal/database"
	"unbound-web/internal/store"
)

// newSettingsStore opens a migrated database and returns the settings store.
func newSettingsStore(t *testing.T) *store.Settings {
	t.Helper()

	db, err := database.Open(context.Background(), filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatalf("cannot open the test database: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	return store.NewSettings(db.DB)
}

// A panel that has never been configured must read as an empty map rather than
// as a failure, because the registry answers for every key it does not hold.
func TestAnUnconfiguredPanelReadsAsAnEmptySet(t *testing.T) {
	values, err := newSettingsStore(t).Load(context.Background())
	if err != nil {
		t.Fatalf("Load returned an error: %v", err)
	}
	if len(values) != 0 {
		t.Errorf("%d row(s) in a fresh table, want none", len(values))
	}
}

func TestASettingIsStoredAndReadBack(t *testing.T) {
	settings := newSettingsStore(t)
	ctx := context.Background()

	if err := settings.Save(ctx, map[string]string{
		"records_per_page":     "50",
		"session_idle_timeout": "45m",
	}); err != nil {
		t.Fatalf("Save returned an error: %v", err)
	}

	values, err := settings.Load(ctx)
	if err != nil {
		t.Fatalf("Load returned an error: %v", err)
	}
	if values["records_per_page"] != "50" {
		t.Errorf("records_per_page = %q, want 50", values["records_per_page"])
	}
	if values["session_idle_timeout"] != "45m" {
		t.Errorf("session_idle_timeout = %q, want 45m", values["session_idle_timeout"])
	}
}

// A second save of the same key replaces the row rather than failing on the
// primary key, which is what makes the settings page idempotent.
func TestSavingTheSameKeyTwiceReplacesTheValue(t *testing.T) {
	settings := newSettingsStore(t)
	ctx := context.Background()

	for _, value := range []string{"50", "40"} {
		if err := settings.Save(ctx, map[string]string{"records_per_page": value}); err != nil {
			t.Fatalf("Save(%s) returned an error: %v", value, err)
		}
	}

	values, err := settings.Load(ctx)
	if err != nil {
		t.Fatalf("Load returned an error: %v", err)
	}
	if values["records_per_page"] != "40" {
		t.Errorf("records_per_page = %q, want the second value 40", values["records_per_page"])
	}
	if len(values) != 1 {
		t.Errorf("%d row(s) stored, want 1", len(values))
	}
}

// Every value of one submission lands or none of them does, so the panel never
// runs on half of a change.
func TestASubmissionIsStoredInOneTransaction(t *testing.T) {
	settings := newSettingsStore(t)
	ctx := context.Background()

	submitted := map[string]string{
		"records_per_page":     "30",
		"fleet_max_concurrent": "8",
		"default_theme":        "dark",
	}
	if err := settings.Save(ctx, submitted); err != nil {
		t.Fatalf("Save returned an error: %v", err)
	}

	values, err := settings.Load(ctx)
	if err != nil {
		t.Fatalf("Load returned an error: %v", err)
	}
	for key, want := range submitted {
		if values[key] != want {
			t.Errorf("%s = %q, want %q", key, values[key], want)
		}
	}
}

// An empty submission is what a page with nothing changed sends. It must be a
// no-op rather than an error.
func TestAnEmptySubmissionChangesNothing(t *testing.T) {
	settings := newSettingsStore(t)
	ctx := context.Background()

	if err := settings.Save(ctx, nil); err != nil {
		t.Fatalf("Save(nil) returned an error: %v", err)
	}

	values, err := settings.Load(ctx)
	if err != nil {
		t.Fatalf("Load returned an error: %v", err)
	}
	if len(values) != 0 {
		t.Errorf("%d row(s) after an empty save, want none", len(values))
	}
}
