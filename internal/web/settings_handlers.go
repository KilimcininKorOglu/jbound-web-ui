package web

import (
	"errors"
	"net/http"
	"strings"

	"unbound-web/internal/audit"
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

// settingsPageData feeds the page and the fragment a save swaps back in.
type settingsPageData struct {
	Groups  []settingsGroup
	Problem string
}

// groupTitles and groupHelp name the cards. They live here rather than in the
// registry, because they describe the page and not the settings.
var (
	groupTitles = map[string]string{
		settings.GroupTiming:    "Timing",
		settings.GroupLimits:    "Limits",
		settings.GroupSIEM:      "SIEM",
		settings.GroupInterface: "Interface defaults",
	}

	groupHelp = map[string]string{
		settings.GroupTiming: "Durations are written as a number and a unit, " +
			"such as 30s, 15m or 24h.",
		settings.GroupLimits:    "Whole numbers. Each one bounds how much work the panel takes on at once.",
		settings.GroupSIEM:      "The forwarding rules themselves live on the SIEM page.",
		settings.GroupInterface: "What a browser gets before anybody picks a language or a theme.",
	}
)

func (a *App) handleSettingsPage(w http.ResponseWriter, r *http.Request) {
	a.Render(w, r, http.StatusOK, "settings", PageData{
		Title: "Settings",
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
		a.settingsProblem(w, nil, "The form could not be read.", http.StatusBadRequest)
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
			a.settingsProblem(w, submitted, settingsMessage(err), http.StatusUnprocessableEntity)
			return
		}
		a.internalError(w, "cannot store the settings", err)
		return
	}

	a.auditSettings(r)
	SetToast(w, ToastSuccess, "The settings were saved and are in effect.")
	a.RenderPartial(w, http.StatusOK, "settings-panel", a.settingsPageData(nil, ""))
}

// settingsProblem re-renders the form with what the operator typed.
func (a *App) settingsProblem(w http.ResponseWriter, submitted map[string]string,
	problem string, status int) {

	a.RenderPartial(w, status, "settings-panel", a.settingsPageData(submitted, problem))
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

	data := settingsPageData{Problem: problem}
	for _, name := range settings.Groups() {
		data.Groups = append(data.Groups, settingsGroup{
			Key:    name,
			Title:  groupTitles[name],
			Help:   groupHelp[name],
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
func settingsMessage(err error) string {
	if !errors.Is(err, settings.ErrInvalid) {
		return userMessage(err)
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
