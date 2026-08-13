package web

import (
	"errors"
	"net/http"
	"strings"

	"unbound-web/internal/audit"
	"unbound-web/internal/i18n"
	"unbound-web/internal/settings"
)

// settingsGroup is one card of the settings page.
type settingsGroup struct {
	Key    string
	Title  string
	Help   string
	Fields []settingsField
}

// settingsField is one control.
type settingsField struct {
	settings.Definition

	// Value is what the control shows. After a refusal it is what the operator
	// typed rather than what is stored, so the correction starts from there.
	Value string

	// Checked is only read for a boolean, where the control is a switch.
	Checked bool
}

// optionPrefixes names the catalogue keys that label the choices of an enum.
// The choices are interface names the layout already carries, so the page reads
// those texts rather than keeping a second copy of them.
var optionPrefixes = map[string]string{
	settings.DefaultLanguage: "layout.language.",
	settings.DefaultTheme:    "layout.theme.",
}

// OptionLabel returns the catalogue key that names one choice. A setting with
// no named choices falls back to printing the stored value.
func (f settingsField) OptionLabel(option string) string {
	return optionPrefixes[f.Key] + option
}

// settingsPageData feeds the page and the fragment a save swaps back in.
type settingsPageData struct {
	Groups  []settingsGroup
	Problem string
}

func (a *App) handleSettingsPage(w http.ResponseWriter, r *http.Request) {
	a.Render(w, r, http.StatusOK, "settings", PageData{
		Title: "nav.settings",
		Data:  a.settingsPageData(nil, ""),
	})
}

// handleSettingsSave validates the whole submission and stores it.
//
// The page is one form, so a refusal keeps every field the operator typed and
// names the problems above them. Storing the good half would leave the panel
// running on a combination nobody approved.
func (a *App) handleSettingsSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.settingsProblem(w, r, nil, a.catalog(r).T("error.form_unreadable"), http.StatusBadRequest)
		return
	}

	submitted := map[string]string{}
	for _, definition := range settings.Definitions() {
		switch definition.Kind {
		case settings.KindBool:
			// An unchecked box sends nothing, so absence is the false here.
			submitted[definition.Key] = boolValue(r.PostForm.Has(definition.Key))
		default:
			if !r.PostForm.Has(definition.Key) {
				continue
			}
			submitted[definition.Key] = strings.TrimSpace(r.PostFormValue(definition.Key))
		}
	}

	if err := a.Settings.Save(r.Context(), submitted); err != nil {
		if errors.Is(err, settings.ErrInvalid) {
			a.settingsProblem(w, r, submitted, settingsMessage(a.catalog(r), err), http.StatusUnprocessableEntity)
			return
		}
		a.internalError(w, "cannot store the settings", err)
		return
	}

	a.auditSettings(r)
	SetToast(w, ToastSuccess, a.catalog(r).T("toast.settings_saved"))
	a.RenderPartial(w, r, http.StatusOK, "settings-panel", a.settingsPageData(nil, ""))
}

// settingsProblem re-renders the form with what the operator typed.
func (a *App) settingsProblem(w http.ResponseWriter, r *http.Request,
	submitted map[string]string, problem string, status int) {

	a.RenderPartial(w, r, status, "settings-panel", a.settingsPageData(submitted, problem))
}

// settingsPageData builds the cards in registry order.
//
// The submitted map wins over the stored values, so a refused submission comes
// back as it was typed instead of as it is stored.
func (a *App) settingsPageData(submitted map[string]string, problem string) settingsPageData {
	stored := a.Settings.Values().All()

	byGroup := map[string][]settingsField{}
	for _, definition := range settings.Definitions() {
		value := stored[definition.Key]
		if typed, ok := submitted[definition.Key]; ok {
			value = typed
		}

		byGroup[definition.Group] = append(byGroup[definition.Group], settingsField{
			Definition: definition,
			Value:      value,
			Checked:    value == "true",
		})
	}

	// The card titles are catalogue keys. The registry names the settings and
	// the page names its own cards, so a new group needs no Go text.
	data := settingsPageData{Problem: problem}
	for _, name := range settings.Groups() {
		data.Groups = append(data.Groups, settingsGroup{
			Key:    name,
			Title:  "settings.group." + name,
			Help:   "settings.group." + name + ".help",
			Fields: byGroup[name],
		})
	}
	return data
}

// auditSettings records that the configuration changed.
//
// The values are not listed. Reading them back is one page load, and a details
// column carrying fifteen keys is a line nobody reads.
func (a *App) auditSettings(r *http.Request) {
	actor := a.actor(r)

	_ = a.Audit.Write(r.Context(), audit.Entry{
		UID:       actor.UID,
		Username:  actor.Username,
		Action:    audit.ActionSettingsUpdate,
		Details:   "Panel settings updated",
		IPAddress: actor.IPAddress,
	})
}

// settingsMessage turns a refusal into a sentence the form can show.
func settingsMessage(catalog *i18n.Catalog, err error) string {
	if !errors.Is(err, settings.ErrInvalid) {
		return userMessage(catalog, err)
	}
	return capitalise(strings.TrimPrefix(err.Error(), settings.ErrInvalid.Error()+": ")) + "."
}

// boolValue renders a checkbox as the registry stores it.
func boolValue(checked bool) string {
	if checked {
		return "true"
	}
	return "false"
}
