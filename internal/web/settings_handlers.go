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

	// Problem is why this control was refused, if it was. The control carries
	// it as its own text rather than only in the message above the form.
	Problem string
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
		Data:  a.settingsPageData(a.catalog(r), nil, nil),
	})
}

// handleSettingsSave validates the whole submission and stores it.
//
// The page is one form, so a refusal keeps every field the operator typed and
// names the problems above them. Storing the good half would leave the panel
// running on a combination nobody approved.
func (a *App) handleSettingsSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		data := a.settingsPageData(a.catalog(r), nil, nil)
		data.Problem = a.catalog(r).T("error.form_unreadable")
		a.RenderPartial(w, r, http.StatusBadRequest, "settings-panel", data)
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

	// Save swaps the snapshot before it returns, so a submission that turns the
	// SIEM mirror off has to be judged against the state that is still here.
	silencing := a.Settings.Bool(settings.SIEMForwardingEnabled) &&
		submitted[settings.SIEMForwardingEnabled] == boolValue(false)

	if err := a.Settings.Save(r.Context(), submitted); err != nil {
		var refusal *settings.Refusal
		if errors.As(err, &refusal) {
			a.settingsProblem(w, r, submitted, refusal, http.StatusUnprocessableEntity)
			return
		}
		a.internalError(w, "cannot store the settings", err)
		return
	}

	a.auditSettings(r, silencing)
	SetToast(w, ToastSuccess, a.catalog(r).T("toast.settings_saved"))
	a.RenderPartial(w, r, http.StatusOK, "settings-panel", a.settingsPageData(a.catalog(r), nil, nil))
}

// settingsProblem re-renders the form with what the operator typed.
func (a *App) settingsProblem(w http.ResponseWriter, r *http.Request,
	submitted map[string]string, refusal *settings.Refusal, status int) {

	a.RenderPartial(w, r, status, "settings-panel", a.settingsPageData(a.catalog(r), submitted, refusal))
}

// settingsPageData builds the cards in registry order.
//
// The submitted map wins over the stored values, so a refused submission comes
// back as it was typed instead of as it is stored.
func (a *App) settingsPageData(catalog *i18n.Catalog, submitted map[string]string,
	refusal *settings.Refusal) settingsPageData {

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
			Problem:    problemText(catalog, refusal.Of(definition.Key)),
		})
	}

	// The card titles are catalogue keys. The registry names the settings and
	// the page names its own cards, so a new group needs no Go text.
	data := settingsPageData{Problem: refusalMessage(catalog, refusal)}
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
//
// mirrored asks for the entry to reach the receiver even though the switch
// this save turned off already answers false.
func (a *App) auditSettings(r *http.Request, mirrored bool) {
	actor := a.actor(r)

	entry := audit.Entry{
		UID:       actor.UID,
		Username:  actor.Username,
		Action:    audit.ActionSettingsUpdate,
		Details:   "Panel settings updated",
		IPAddress: actor.IPAddress,
	}

	if mirrored {
		_ = a.Audit.WriteMirrored(r.Context(), entry)
		return
	}
	_ = a.Audit.Write(r.Context(), entry)
}

// problemText writes one refused value out in the language of the reader.
//
// The problem carries a code and its values rather than a sentence, so the same
// refusal reads as English in the log and as Turkish on the page.
func problemText(catalog *i18n.Catalog, problem *settings.Problem) string {
	if problem == nil {
		return ""
	}
	return catalog.Tf("settings.problem."+problem.Code, problem.Args...)
}

// refusalMessage turns a refusal into the sentence above the form.
//
// The controls carry their own problem as well. This one stays because it names
// the settings, and because it is what a reader is taken to when the form comes
// back.
func refusalMessage(catalog *i18n.Catalog, refusal *settings.Refusal) string {
	if refusal == nil {
		return ""
	}

	var sentences []string
	for _, problem := range refusal.Problems() {
		label := catalog.T("setting." + problem.Key + ".label")
		sentences = append(sentences, label+": "+problemText(catalog, problem))
	}
	return strings.Join(sentences, " ")
}

// boolValue renders a checkbox as the registry stores it.
func boolValue(checked bool) string {
	if checked {
		return "true"
	}
	return "false"
}
