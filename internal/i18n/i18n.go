// Package i18n holds the interface texts of the panel.
//
// One flat JSON file per language, embedded in the binary. Flat rather than
// nested, because a key is looked up by its full name and a tree would only
// add a way for two files to disagree about its shape.
//
// The language of a request comes from a cookie. Nothing about the reader is
// stored on the server, so a shared account can be read in two languages at
// once without one person changing the other's page.
package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sync"
)

//go:embed locales/*.json
var localeFS embed.FS

// Default is the language a browser gets when it asks for nothing the panel
// has. It is also the fallback of every missing key.
const Default = "en"

// Catalog holds the texts of one language.
type Catalog struct {
	language string
	messages map[string]string

	// fallback answers for a key this language does not carry. English is the
	// source language, so a translation that lags behind a release shows the
	// English sentence rather than a key.
	fallback *Catalog

	// reported keeps the missing keys that were already logged. A page in a
	// loop would otherwise fill the log with the same line.
	reported sync.Map
}

// Language returns the code of this catalog.
func (c *Catalog) Language() string { return c.language }

// T returns one text.
func (c *Catalog) T(key string) string {
	if text, ok := c.messages[key]; ok {
		return text
	}
	if c.fallback != nil {
		if text, ok := c.fallback.messages[key]; ok {
			c.report(key)
			return text
		}
	}
	c.report(key)
	return key
}

// Tf returns one text with its arguments filled in.
func (c *Catalog) Tf(key string, args ...any) string {
	return fmt.Sprintf(c.T(key), args...)
}

// Has reports whether this language carries the key itself.
func (c *Catalog) Has(key string) bool {
	_, ok := c.messages[key]
	return ok
}

// Keys returns every key of this catalog.
func (c *Catalog) Keys() []string {
	return slices.Sorted(maps.Keys(c.messages))
}

// report logs a missing key once.
func (c *Catalog) report(key string) {
	if _, seen := c.reported.LoadOrStore(key, true); seen {
		return
	}
	slog.Warn("missing translation", "language", c.language, "key", key)
}

// Catalogs holds every language the panel was built with.
type Catalogs struct {
	byLanguage map[string]*Catalog
	languages  []string
}

// Load reads the embedded locales.
//
// A file that does not parse is a build problem rather than a runtime one, so
// the caller refuses to start rather than serving a panel with no words on it.
func Load() (*Catalogs, error) {
	entries, err := localeFS.ReadDir("locales")
	if err != nil {
		return nil, fmt.Errorf("cannot list the locales: %w", err)
	}

	catalogs := &Catalogs{byLanguage: map[string]*Catalog{}}

	for _, entry := range entries {
		name := entry.Name()
		language := name[:len(name)-len(".json")]

		body, err := localeFS.ReadFile("locales/" + name)
		if err != nil {
			return nil, fmt.Errorf("cannot read %s: %w", name, err)
		}

		messages := map[string]string{}
		if err := json.Unmarshal(body, &messages); err != nil {
			return nil, fmt.Errorf("cannot parse %s: %w", name, err)
		}
		if len(messages) == 0 {
			return nil, fmt.Errorf("%s carries no texts", name)
		}

		catalogs.byLanguage[language] = &Catalog{language: language, messages: messages}
		catalogs.languages = append(catalogs.languages, language)
	}

	source, ok := catalogs.byLanguage[Default]
	if !ok {
		return nil, fmt.Errorf("the %s locale is missing", Default)
	}
	for language, catalog := range catalogs.byLanguage {
		if language != Default {
			catalog.fallback = source
		}
	}

	slices.Sort(catalogs.languages)
	return catalogs, nil
}

// Languages returns the codes the panel was built with, in a stable order.
func (c *Catalogs) Languages() []string {
	return slices.Clone(c.languages)
}

// Has reports whether the panel carries this language.
func (c *Catalogs) Has(language string) bool {
	_, ok := c.byLanguage[language]
	return ok
}

// Catalog returns one language, falling back to the source language.
func (c *Catalogs) Catalog(language string) *Catalog {
	if catalog, ok := c.byLanguage[language]; ok {
		return catalog
	}
	return c.byLanguage[Default]
}
