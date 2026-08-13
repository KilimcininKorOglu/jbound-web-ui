package web

import (
	"net/http"
	"slices"
	"time"

	"unbound-web/internal/settings"
)

// Preference cookies. They hold a display choice and nothing else, so they
// carry no session fact and no identifier.
const (
	ThemeCookieName = "unbound_web_theme"
)

// preferenceMaxAge keeps a choice for a year. A display preference that
// expired with the browser would be made again every morning.
const preferenceMaxAge = 365 * 24 * time.Hour

// theme returns the theme of the current request.
//
// The cookie wins, the panel default answers when there is none, and a value
// the registry does not know is ignored rather than rendered. The cookie is
// the only place a choice is stored, so nothing about a person is kept on the
// server.
func (a *App) theme(r *http.Request) string {
	fallback := a.Settings.String(settings.DefaultTheme)

	cookie, err := r.Cookie(ThemeCookieName)
	if err != nil || cookie.Value == "" {
		return fallback
	}
	if !themeIsKnown(cookie.Value) {
		return fallback
	}
	return cookie.Value
}

// handleThemeChange stores the choice and reloads the page.
//
// A reload rather than a swap, because the theme sits on the html element and
// the whole document has to be re-rendered with it.
func (a *App) handleThemeChange(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	choice := r.PostFormValue("theme")
	if !themeIsKnown(choice) {
		http.Error(w, "unknown theme", http.StatusBadRequest)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     ThemeCookieName,
		Value:    choice,
		Path:     "/",
		MaxAge:   int(preferenceMaxAge.Seconds()),
		HttpOnly: true,
		Secure:   a.Config.CookieSecure,
		// Lax rather than Strict. A link from outside should arrive with the
		// theme the person chose, and the cookie decides nothing else.
		SameSite: http.SameSiteLaxMode,
	})

	w.Header().Set("HX-Refresh", "true")
	w.WriteHeader(http.StatusNoContent)
}

// themeIsKnown reports whether the registry offers this theme.
func themeIsKnown(value string) bool {
	definition, ok := settings.Lookup(settings.DefaultTheme)
	if !ok {
		return false
	}
	return slices.Contains(definition.Options, value)
}
