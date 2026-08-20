package web

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// aaThreshold is the contrast ratio WCAG AA asks of body text.
const aaThreshold = 4.5

// pair is one colour a reader has to make out against another.
type pair struct {
	name string

	// front is the token the text or the control is drawn in, back the token
	// behind it. Both are read from the palette under test, so the same table
	// measures the light theme and the dark one.
	front string
	back  string
}

// textPairs is every place the panel puts one token on another and expects it
// to be read.
var textPairs = []pair{
	{"body text on the page", "--panel-text", "--panel-bg"},
	{"body text on a card", "--panel-text", "--panel-surface"},
	{"body text on a raised surface", "--panel-text", "--panel-surface-raised"},
	{"heading", "--panel-heading", "--panel-surface"},
	{"muted text on a card", "--panel-text-muted", "--panel-surface"},
	{"muted text on the page", "--panel-text-muted", "--panel-bg"},
	{"muted text on a raised surface", "--panel-text-muted", "--panel-surface-raised"},
	{"link", "--panel-accent", "--panel-surface"},
	{"link on the page", "--panel-accent", "--panel-bg"},
	{"link hover", "--panel-accent-strong", "--panel-surface"},

	// The primary button. Which of the two carries the dark side changes with
	// the theme, and the ratio is what decides it.
	{"primary button", "--panel-on-accent", "--panel-accent"},
	{"primary button hover", "--panel-on-accent", "--panel-accent-strong"},

	{"success alert", "--panel-success", "--panel-success-bg"},
	{"info alert", "--panel-info", "--panel-info-bg"},
	{"warning alert", "--panel-warning", "--panel-warning-bg"},
	{"danger alert", "--panel-danger", "--panel-danger-bg"},
	{"secondary badge", "--panel-secondary", "--panel-secondary-bg"},

	// A refusal under a control and an outlined button sit on the card rather
	// than on a tint of their own.
	{"refused field", "--panel-danger", "--panel-surface"},
	{"outlined danger button", "--panel-danger", "--panel-surface"},
	{"status word", "--panel-success", "--panel-surface"},
}

// controlPairs is every element WCAG 1.4.11 asks 3:1 of: the edge that says
// where a control is, and the ring that says which one is focused.
//
// The hairline between two blocks of content is not in the list. It separates
// rather than identifies, and nothing is lost when it goes unseen.
var controlPairs = []pair{
	{"field border on the page", "--panel-control-border", "--panel-bg"},
	{"field border on a card", "--panel-control-border", "--panel-surface"},
	{"field border on a raised surface", "--panel-control-border", "--panel-surface-raised"},
	{"focus ring on the page", "--panel-focus", "--panel-bg"},
	{"focus ring on a card", "--panel-focus", "--panel-surface"},
	{"status dot, up", "--panel-success", "--panel-surface"},
	{"status dot, unapplied", "--panel-warning", "--panel-surface"},
	{"status dot, down", "--panel-danger", "--panel-surface"},
}

// Both palettes are measured, and by the same table.
//
// A dark theme is the easier one to get wrong: an eye adapts to a low contrast
// dark page long before it can read it comfortably, so the numbers decide
// rather than the eye that chose the colours.
func TestBothPalettesAreReadable(t *testing.T) {
	palettes := map[string]string{
		"light": ":root",
		"dark":  `html[data-color-scheme="dark"]`,
	}

	for theme, selector := range palettes {
		t.Run(theme, func(t *testing.T) {
			colours := palette(t, selector)

			measure(t, colours, textPairs, aaThreshold)
			measure(t, colours, controlPairs, uiThreshold)
		})
	}
}

// measure runs one table against one palette.
func measure(t *testing.T, colours map[string]string, pairs []pair, threshold float64) {
	t.Helper()

	for _, want := range pairs {
		t.Run(want.name, func(t *testing.T) {
			front, ok := colours[want.front]
			if !ok {
				t.Fatalf("the palette declares no %s", want.front)
			}
			back, ok := colours[want.back]
			if !ok {
				t.Fatalf("the palette declares no %s", want.back)
			}

			ratio, err := contrast(front, back)
			if err != nil {
				t.Fatalf("%v", err)
			}
			if ratio < threshold {
				t.Errorf("%s reads %s on %s at %.2f:1, want at least %.1f:1",
					want.name, front, back, ratio, threshold)
			}
		})
	}
}

// The machine output block keeps its own dark field in both themes, so it is
// the one place a literal colour still has to be measured.
func TestTheLogViewerIsReadableInBothThemes(t *testing.T) {
	block := regexp.MustCompile(`(?s)\.log-viewer\s*\{([^}]*)\}`).
		FindStringSubmatch(sheet(t, "panel.css"))
	if block == nil {
		t.Fatal("panel.css declares no log viewer")
	}

	literal := regexp.MustCompile(`(?m)^\s*(background|color)\s*:\s*(#[0-9A-Fa-f]{6})`)
	found := map[string]string{}
	for _, declaration := range literal.FindAllStringSubmatch(block[1], -1) {
		found[declaration[1]] = declaration[2]
	}
	if found["background"] == "" || found["color"] == "" {
		t.Fatalf("the log viewer declares %v, want both a background and a text colour", found)
	}

	ratio, err := contrast(found["color"], found["background"])
	if err != nil {
		t.Fatalf("%v", err)
	}
	if ratio < aaThreshold {
		t.Errorf("the log viewer reads %s on %s at %.2f:1, want at least %.1f:1",
			found["color"], found["background"], ratio, aaThreshold)
	}
}

// contrast is the WCAG ratio between two colours.
func contrast(first, second string) (float64, error) {
	a, err := luminance(first)
	if err != nil {
		return 0, err
	}
	b, err := luminance(second)
	if err != nil {
		return 0, err
	}

	lighter, darker := max(a, b), min(a, b)
	return (lighter + 0.05) / (darker + 0.05), nil
}

// luminance is the relative luminance of one hex colour.
func luminance(colour string) (float64, error) {
	digits := strings.TrimPrefix(colour, "#")
	if len(digits) != 6 {
		return 0, fmt.Errorf("%s is not a six digit colour", colour)
	}

	var channels [3]float64
	for i := range channels {
		value, err := strconv.ParseUint(digits[i*2:i*2+2], 16, 8)
		if err != nil {
			return 0, fmt.Errorf("cannot read %s: %w", colour, err)
		}
		channels[i] = linear(float64(value) / 255)
	}

	return 0.2126*channels[0] + 0.7152*channels[1] + 0.0722*channels[2], nil
}

// linear removes the gamma encoding from one channel.
func linear(value float64) float64 {
	if value <= 0.03928 {
		return value / 12.92
	}
	return math.Pow((value+0.055)/1.055, 2.4)
}
