package web

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"unbound-web/internal/i18n"
)

func TestEveryPageParsesWithItsLayout(t *testing.T) {
	// A page whose layout is missing, or a layout that no page uses, would
	// otherwise only surface when someone opens that one route.
	catalogs, err := i18n.Load()
	if err != nil {
		t.Fatalf("cannot load the catalogues: %v", err)
	}

	sets, err := parseTemplates(catalogs)
	if err != nil {
		t.Fatalf("parseTemplates returned an error: %v", err)
	}

	// Every language parses every page. A text helper that is missing in one
	// catalogue would otherwise only surface when somebody switches to it.
	for _, language := range catalogs.Languages() {
		set, ok := sets[language]
		if !ok {
			t.Fatalf("%s was not parsed", language)
		}

		for name := range pageLayouts {
			tmpl, ok := set.pages[name]
			if !ok {
				t.Errorf("%s: page %s was not parsed", language, name)
				continue
			}
			if tmpl.Lookup("layout") == nil {
				t.Errorf("%s: page %s has no layout template", language, name)
			}
			if tmpl.Lookup("content") == nil {
				t.Errorf("%s: page %s defines no content template", language, name)
			}
		}
	}
}

func TestSetToastCarriesTheSeverityAndMessage(t *testing.T) {
	recorder := httptest.NewRecorder()

	SetToast(recorder, ToastSuccess, "Record added.")

	var triggers map[string]map[string]string
	if err := json.Unmarshal([]byte(recorder.Header().Get("HX-Trigger")), &triggers); err != nil {
		t.Fatalf("the trigger header is not valid JSON: %v", err)
	}
	if triggers["toast"]["severity"] != ToastSuccess {
		t.Errorf("severity = %q, want %q", triggers["toast"]["severity"], ToastSuccess)
	}
	if triggers["toast"]["message"] != "Record added." {
		t.Errorf("message = %q", triggers["toast"]["message"])
	}
}

func TestSetTriggerKeepsTheEventsThatCameBefore(t *testing.T) {
	// A handler that raises a toast and refreshes a table must not lose one of
	// the two, and each call writes the same header.
	recorder := httptest.NewRecorder()

	SetToast(recorder, ToastSuccess, "Record added.")
	SetTrigger(recorder, "records-changed", map[string]int{"serverId": 3})

	var triggers map[string]any
	if err := json.Unmarshal([]byte(recorder.Header().Get("HX-Trigger")), &triggers); err != nil {
		t.Fatalf("the trigger header is not valid JSON: %v", err)
	}
	if _, ok := triggers["toast"]; !ok {
		t.Error("the toast event was dropped")
	}
	if _, ok := triggers["records-changed"]; !ok {
		t.Error("the second event was dropped")
	}
}

// The registry states its bounds as durations, and Go prints 24h as 24h0m0s.
// The page shows them the way an operator types them.
func TestADurationBoundIsWrittenTheWayItIsTyped(t *testing.T) {
	format, ok := funcs["duration"].(func(time.Duration) string)
	if !ok {
		t.Fatal("the templates have no duration helper")
	}

	cases := map[time.Duration]string{
		time.Second:      "1s",
		30 * time.Second: "30s",
		time.Minute:      "1m",
		90 * time.Second: "1m30s",
		5 * time.Minute:  "5m",
		24 * time.Hour:   "24h",
		168 * time.Hour:  "168h",
		90 * time.Minute: "1h30m",
		2*time.Hour + 5*time.Minute + 3*time.Second: "2h5m3s",
	}

	for value, want := range cases {
		if got := format(value); got != want {
			t.Errorf("%s reads %q, want %q", value, got, want)
		}
	}
}
