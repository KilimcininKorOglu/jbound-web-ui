package web

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"jbound/internal/i18n"
	"jbound/internal/settings"
)

// LanguageCookieName carries the chosen language. It holds a display choice
// and nothing else, so nothing about the reader is stored on the server.
const LanguageCookieName = "jbound_lang"

// clientStringPrefix marks the texts the scripts raise. They travel to the
// browser in one attribute, so the whole catalogue does not have to.
const clientStringPrefix = "client."

// language returns the language of the current request.
//
// The cookie wins, the panel default answers when there is none, and a code
// the panel was not built with is ignored. The browser's Accept-Language
// header is not read: the panel has a configured default, and a header the
// reader never set would override it.
func (a *App) language(r *http.Request) string {
	fallback := a.Settings.String(settings.DefaultLanguage)
	if !a.Catalogs.Has(fallback) {
		fallback = i18n.Default
	}

	cookie, err := r.Cookie(LanguageCookieName)
	if err != nil || cookie.Value == "" {
		return fallback
	}
	if !a.Catalogs.Has(cookie.Value) {
		return fallback
	}
	return cookie.Value
}

// catalog returns the texts of the current request.
func (a *App) catalog(r *http.Request) *i18n.Catalog {
	return a.Catalogs.Catalog(a.language(r))
}

// handleLanguageChange stores the choice and reloads the page.
//
// A reload rather than a swap, because every text on the page comes from the
// template set of one language and the whole document has to be rendered
// again with the other one.
func (a *App) handleLanguageChange(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	choice := r.PostFormValue("language")
	if !a.Catalogs.Has(choice) {
		http.Error(w, "unknown language", http.StatusBadRequest)
		return
	}

	// #nosec G124 -- Secure follows COOKIE_SECURE; HttpOnly and SameSite are set.
	http.SetCookie(w, &http.Cookie{
		Name:     LanguageCookieName,
		Value:    choice,
		Path:     "/",
		MaxAge:   int(preferenceMaxAge.Seconds()),
		HttpOnly: true,
		Secure:   a.Config.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})

	w.Header().Set("HX-Refresh", "true")
	w.WriteHeader(http.StatusNoContent)
}

// clientStrings renders the texts the scripts raise as a JSON attribute.
//
// Only the client prefix travels. Sending the whole catalogue would put every
// page of the panel into every response for the sake of six dialogs.
//
// The result is a plain string, so the template escapes it for the attribute
// it sits in and the browser hands the scripts the JSON back.
func clientStrings(catalog *i18n.Catalog) string {
	texts := map[string]string{}
	for _, key := range catalog.Keys() {
		if strings.HasPrefix(key, clientStringPrefix) {
			texts[key] = catalog.T(key)
		}
	}

	encoded, err := json.Marshal(texts)
	if err != nil {
		// A page without its dialog texts still works, and the scripts fall
		// back to the key.
		slog.Error("cannot encode the interface texts", "error", err)
		return "{}"
	}
	return string(encoded)
}
