package web

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

func TestEveryPageParsesWithItsLayout(t *testing.T) {
	// A page whose layout is missing, or a layout that no page uses, would
	// otherwise only surface when someone opens that one route.
	set, err := parseTemplates()
	if err != nil {
		t.Fatalf("parseTemplates returned an error: %v", err)
	}

	for name := range pageLayouts {
		tmpl, ok := set.pages[name]
		if !ok {
			t.Errorf("page %s was not parsed", name)
			continue
		}
		if tmpl.Lookup("layout") == nil {
			t.Errorf("page %s has no layout template", name)
		}
		if tmpl.Lookup("content") == nil {
			t.Errorf("page %s defines no content template", name)
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
