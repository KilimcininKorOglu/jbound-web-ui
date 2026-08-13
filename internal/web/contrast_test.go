package web

import (
	"fmt"
	"io/fs"
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// aaThreshold is the contrast ratio WCAG AA asks of body text.
const aaThreshold = 4.5

// colourPattern reads one declaration out of a rule body.
var colourPattern = regexp.MustCompile(`(?m)^\s*(background-color|color)\s*:\s*(#[0-9A-Fa-f]{6})`)

// TestStatusColoursAreReadable measures the panel's own status palette.
//
// The vendor stylesheet writes a pale text on a pale tint, and its success
// alert reads at 1.9:1. The override lives in brand.css, so the ratio is
// measured there rather than trusted to the eye that wrote it.
func TestStatusColoursAreReadable(t *testing.T) {
	body, err := fs.ReadFile(staticFS, "static/css/brand.css")
	if err != nil {
		t.Fatalf("cannot read brand.css: %v", err)
	}
	sheet := string(body)

	cases := []struct {
		selector string

		// behind is the background the text sits on when the rule declares
		// none of its own. White, because that is the card.
		behind string
	}{
		{selector: ".alert-success"},
		{selector: ".alert-info"},
		{selector: ".alert-warning"},
		{selector: ".alert-danger"},
		{selector: ".btn-apply"},
		{selector: ".btn-apply:disabled", behind: "#ffffff"},
		{selector: ".bg-label-primary"},
		{selector: ".bg-label-success"},
		{selector: ".bg-label-info"},
		{selector: ".bg-label-warning"},
		{selector: ".bg-label-danger"},
		{selector: ".bg-label-secondary"},
		{selector: ".text-muted", behind: "#ffffff"},
		{selector: ".form-text", behind: "#ffffff"},
	}

	for _, testCase := range cases {
		t.Run(testCase.selector, func(t *testing.T) {
			text, background, err := rule(sheet, testCase.selector)
			if err != nil {
				t.Fatalf("%v", err)
			}
			if background == "" {
				background = testCase.behind
			}
			if background == "" {
				t.Fatalf("%s declares no background to measure against", testCase.selector)
			}

			ratio, err := contrast(text, background)
			if err != nil {
				t.Fatalf("%v", err)
			}
			if ratio < aaThreshold {
				t.Errorf("%s reads %s on %s at %.2f:1, want at least %.1f:1",
					testCase.selector, text, background, ratio, aaThreshold)
			}
		})
	}
}

// rule returns the text and background colours one selector declares.
func rule(sheet, selector string) (text, background string, err error) {
	// The selector may open a group, as a button does with its own hover and
	// focus states. Only the first selector of the group is matched, because
	// the declarations behind it are shared by all of them.
	pattern, err := regexp.Compile(
		`(?m)^` + regexp.QuoteMeta(selector) + `\s*(?:,[^{}]*)?\{([^}]*)\}`)
	if err != nil {
		return "", "", fmt.Errorf("cannot match %s: %w", selector, err)
	}

	match := pattern.FindStringSubmatch(sheet)
	if match == nil {
		return "", "", fmt.Errorf("brand.css declares no %s rule", selector)
	}

	for _, declaration := range colourPattern.FindAllStringSubmatch(match[1], -1) {
		if declaration[1] == "color" {
			text = declaration[2]
		} else {
			background = declaration[2]
		}
	}
	if text == "" {
		return "", "", fmt.Errorf("%s declares no text colour", selector)
	}
	return text, background, nil
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
