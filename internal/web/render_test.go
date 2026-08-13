package web

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
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
