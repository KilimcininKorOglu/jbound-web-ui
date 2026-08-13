package i18n

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// argumentPattern counts the placeholders of one text.
var argumentPattern = regexp.MustCompile(`%[a-zA-Z]`)

func load(t *testing.T) *Catalogs {
	t.Helper()

	catalogs, err := Load()
	if err != nil {
		t.Fatalf("Load returned an error: %v", err)
	}
	return catalogs
}

func TestThePanelCarriesTheTwoLanguagesItPromises(t *testing.T) {
	catalogs := load(t)

	for _, language := range []string{"en", "tr"} {
		if !catalogs.Has(language) {
			t.Errorf("the %s catalogue is missing", language)
		}
	}
	if got := catalogs.Catalog(Default).Language(); got != Default {
		t.Errorf("the default catalogue reports %q", got)
	}
}

// Both files carry the same keys. A translation that lags behind shows an
// English sentence rather than a key, and this is what keeps that rare.
func TestEveryLanguageCarriesTheSameKeys(t *testing.T) {
	catalogs := load(t)
	source := catalogs.Catalog(Default).Keys()

	for _, language := range catalogs.Languages() {
		if language == Default {
			continue
		}
		other := catalogs.Catalog(language).Keys()

		for _, key := range source {
			if !slices.Contains(other, key) {
				t.Errorf("%s is missing %s", language, key)
			}
		}
		for _, key := range other {
			if !slices.Contains(source, key) {
				t.Errorf("%s carries %s, which %s does not", language, key, Default)
			}
		}
	}
}

// A text with a different number of placeholders than its English original
// prints a stray %!s(MISSING) in front of the reader.
func TestEveryTranslationTakesTheSameArguments(t *testing.T) {
	catalogs := load(t)
	source := catalogs.Catalog(Default)

	for _, language := range catalogs.Languages() {
		if language == Default {
			continue
		}
		catalog := catalogs.Catalog(language)

		for _, key := range source.Keys() {
			if !catalog.Has(key) {
				continue
			}
			want := len(argumentPattern.FindAllString(source.T(key), -1))
			got := len(argumentPattern.FindAllString(catalog.T(key), -1))
			if want != got {
				t.Errorf("%s: %s takes %d argument(s), the %s text takes %d",
					language, key, got, Default, want)
			}
		}
	}
}

// A key nobody translated falls back to English, and a key nobody wrote at all
// falls back to itself. Neither is worth a blank page.
func TestAMissingKeyFallsBackRatherThanBlanking(t *testing.T) {
	catalogs := load(t)
	catalog := catalogs.Catalog("tr")

	if got := catalog.T("invented.key"); got != "invented.key" {
		t.Errorf("an unknown key reads %q, want the key itself", got)
	}

	// Reported once. The second call must not log again, which the shared map
	// is there for.
	if got := catalog.T("invented.key"); got != "invented.key" {
		t.Errorf("the second read of an unknown key reads %q", got)
	}
}

func TestAnUnknownLanguageFallsBackToTheSource(t *testing.T) {
	catalogs := load(t)

	if catalogs.Has("de") {
		t.Fatal("the panel claims a language it was not built with")
	}
	if got := catalogs.Catalog("de").Language(); got != Default {
		t.Errorf("an unknown language answers as %q, want %s", got, Default)
	}
}

func TestTheArgumentsReachTheText(t *testing.T) {
	catalogs := load(t)
	catalog := catalogs.Catalog(Default)

	got := catalog.Tf("summary.records", 10, 40, 1, 4)
	if !strings.Contains(got, "10") || !strings.Contains(got, "40") {
		t.Errorf("the counts did not reach the sentence: %q", got)
	}
}

// The texts the scripts raise travel to the browser in one attribute, so they
// have to be findable by their prefix.
func TestTheClientTextsAreNamespaced(t *testing.T) {
	catalogs := load(t)
	catalog := catalogs.Catalog(Default)

	found := 0
	for _, key := range catalog.Keys() {
		if strings.HasPrefix(key, "client.") {
			found++
		}
	}
	if found == 0 {
		t.Error("no client text is namespaced, the dialogs would fall back to keys")
	}
}

// Every language is offered in the language control, which reads its own name
// out of the catalogue.
func TestEveryLanguageNamesItself(t *testing.T) {
	catalogs := load(t)

	for _, language := range catalogs.Languages() {
		key := "layout.language." + language
		if !catalogs.Catalog(language).Has(key) {
			t.Errorf("%s does not carry %s", language, key)
		}
	}
}
