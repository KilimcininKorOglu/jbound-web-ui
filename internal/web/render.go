package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"maps"
	"net/http"
	"path"
	"strings"
	"time"

	"unbound-web/internal/auth"
	"unbound-web/internal/i18n"
	"unbound-web/internal/logging"
	"unbound-web/internal/settings"
)

// Toast severities. They map onto the SweetAlert2 icon names.
const (
	ToastSuccess = "success"
	ToastError   = "error"
	ToastWarning = "warning"
	ToastInfo    = "info"
)

// authLayout is used by the pages that have no session yet.
const authLayout = "auth"

// pageLayouts names the layout of every page.
//
// A page without an entry is a mistake rather than a default, so a new page
// cannot silently render without navigation.
var pageLayouts = map[string]string{
	"login":    authLayout,
	"dns":      "app",
	"diff":     "app",
	"servers":  "app",
	"logs":     "app",
	"siem":     "app",
	"settings": "app",
	"sessions": "app",
	"system":   "app",
}

// templateSet holds the parsed templates of one language.
//
// Each page gets its own set, because every page defines a template named
// "content" and one shared set could not hold them all. Each language gets its
// own copy of all of them, because the text comes from a template function
// bound to a catalogue rather than from the data: an htmx fragment carries no
// page data, and threading a catalogue through every fragment struct would put
// the same field on all of them.
type templateSet struct {
	pages    map[string]*template.Template
	partials *template.Template
}

// funcs are available to every template. The text helpers are added per
// language in parseTemplates.
var funcs = template.FuncMap{
	// localTime turns a stored UTC timestamp into the reader's local zone.
	// Every timestamp in the database is UTC, and showing it raw would make
	// an audit trail read an hour or more off.
	"localTime": func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.Local().Format("2006-01-02 15:04:05")
	},
	// localTimePtr renders an optional timestamp, such as the last contact
	// with a server nobody has reached yet.
	"localTimePtr": func(t *time.Time) string {
		if t == nil || t.IsZero() {
			return ""
		}
		return t.Local().Format("2006-01-02 15:04:05")
	},
	// alert builds the value the alert partial expects, so a template can
	// raise one without the handler assembling it first.
	"alert": func(severity, message string) *Alert {
		return &Alert{Severity: severity, Message: message}
	},
	// join renders a list of names as a sentence fragment. Printing the slice
	// itself would put Go's bracket syntax in front of the reader.
	"join": func(values []string) string {
		return strings.Join(values, ", ")
	},
	// duration writes a bound the way an operator types it. The settings package
	// writes the same durations into its refusals, so both read alike.
	"duration": settings.Human,
}

// parseTemplates builds one set per language.
func parseTemplates(catalogs *i18n.Catalogs) (map[string]*templateSet, error) {
	sets := map[string]*templateSet{}

	for _, language := range catalogs.Languages() {
		set, err := parseLanguage(catalogs.Catalog(language))
		if err != nil {
			return nil, err
		}
		sets[language] = set
	}
	return sets, nil
}

// textFuncs binds the lookup helpers to one catalogue.
func textFuncs(catalog *i18n.Catalog) template.FuncMap {
	bound := template.FuncMap{}
	maps.Copy(bound, funcs)

	bound["t"] = catalog.T
	bound["tf"] = catalog.Tf
	bound["lang"] = catalog.Language
	bound["clientStrings"] = func() string { return clientStrings(catalog) }

	return bound
}

// parseLanguage builds the page and partial templates of one language.
func parseLanguage(catalog *i18n.Catalog) (*templateSet, error) {
	bound := textFuncs(catalog)

	partials, err := template.New("partials").Funcs(bound).
		ParseFS(templateFS, "templates/partials/*.html")
	if err != nil {
		return nil, fmt.Errorf("cannot parse the partials: %w", err)
	}

	entries, err := fs.Glob(templateFS, "templates/pages/*.html")
	if err != nil {
		return nil, fmt.Errorf("cannot list the pages: %w", err)
	}

	set := &templateSet{pages: map[string]*template.Template{}, partials: partials}

	for _, entry := range entries {
		name := stripExtension(path.Base(entry))

		layout, ok := pageLayouts[name]
		if !ok {
			return nil, fmt.Errorf("page %s has no layout, add it to pageLayouts", name)
		}

		tmpl, err := template.New(name).Funcs(bound).ParseFS(templateFS,
			"templates/layouts/"+layout+".html",
			"templates/partials/*.html",
			entry,
		)
		if err != nil {
			return nil, fmt.Errorf("cannot parse the page %s: %w", name, err)
		}
		set.pages[name] = tmpl
	}

	for name := range pageLayouts {
		if _, ok := set.pages[name]; !ok {
			return nil, fmt.Errorf("pageLayouts names %s but templates/pages/%s.html is missing",
				name, name)
		}
	}
	return set, nil
}

func stripExtension(name string) string {
	return name[:len(name)-len(path.Ext(name))]
}

// PageData is what every page template receives.
type PageData struct {
	Title      string
	Session    auth.Session
	CSRFToken  string
	Menu       []MenuSection
	ActivePath string
	Year       int
	Alert      *Alert

	// Language is what the html element carries and what the language control
	// shows as chosen.
	Language string

	// Languages are the codes the panel was built with, for the control.
	Languages []string

	// Theme is what the html element carries. It is read from the cookie on
	// every render, so the first paint is already in the chosen theme and
	// nothing flashes.
	Theme string

	// PanelName is what the installation calls itself. It is a setting rather
	// than a catalogue text, so an operator can name their own panel.
	PanelName string
	// Data carries whatever the page itself needs.
	Data any
}

// Alert is a message rendered into the page rather than raised as a toast.
type Alert struct {
	Severity string
	Message  string
}

// Render writes a full page.
//
// The template runs into a buffer first. A failure halfway through would
// otherwise leave a truncated page behind a 200.
func (a *App) Render(w http.ResponseWriter, r *http.Request, status int,
	page string, data PageData) {

	language := a.language(r)

	tmpl, ok := a.tmpl[language].pages[page]
	if !ok {
		logging.From(r.Context()).Error("unknown page requested", "page", page)
		serverError(w, r)
		return
	}

	session, hasSession := SessionFrom(r.Context())
	if hasSession {
		data.Session = session
		data.CSRFToken = session.CSRFToken
		data.Menu = menuFor(session, r.URL.Path)
	}
	data.ActivePath = r.URL.Path
	data.Year = time.Now().Year()
	data.Theme = a.theme(r)
	data.Language = language
	data.Languages = a.Catalogs.Languages()
	data.PanelName = a.Settings.String(settings.PanelName)

	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "layout", data); err != nil {
		logging.From(r.Context()).Error("cannot render the page", "page", page, "error", err)
		serverError(w, r)
		return
	}
	// A page is sent as it is. It carries the session CSRF token in the body
	// element and most pages echo a filter the reader typed, and a response
	// that holds both gives its secret away through its compressed length.
	writeHTML(w, r, status, buf.Bytes(), false)
}

// RenderPartial writes one fragment, which is what an htmx swap expects.
//
// It takes the request because the language does, and a fragment carries no
// page data to read it from.
func (a *App) RenderPartial(w http.ResponseWriter, r *http.Request, status int,
	name string, data any) {

	var buf bytes.Buffer

	if err := a.tmpl[a.language(r)].partials.ExecuteTemplate(&buf, name, data); err != nil {
		logging.From(r.Context()).Error("cannot render the partial", "partial", name, "error", err)
		serverError(w, r)
		return
	}
	// A fragment carries no token, and the record table is the largest thing
	// the panel sends after the stylesheets: a hundred rows of markup, each
	// naming the servers that hold the record.
	writeHTML(w, r, status, buf.Bytes(), true)
}

// writeHTML sends a rendered body, compressing it when the caller says the
// response is free to be compressed.
func writeHTML(w http.ResponseWriter, r *http.Request, status int,
	body []byte, compress bool) {

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	writeCompressed(w, r, status, body, compress)
}

// SetToast asks the browser to raise a toast once the response lands.
//
// It must be called before the body is written, because it sets a header.
func SetToast(w http.ResponseWriter, severity, message string) {
	SetTrigger(w, "toast", map[string]string{
		"severity": severity,
		"message":  message,
	})
}

// SetTrigger adds one client side event to the response.
//
// Existing triggers are preserved, so a handler that raises a toast and
// refreshes a table does not lose one of the two.
func SetTrigger(w http.ResponseWriter, event string, detail any) {
	const header = "HX-Trigger"

	triggers := map[string]any{}
	if existing := w.Header().Get(header); existing != "" {
		if err := json.Unmarshal([]byte(existing), &triggers); err != nil {
			slog.Error("cannot read the existing trigger header", "error", err)
			return
		}
	}
	triggers[event] = detail

	encoded, err := json.Marshal(triggers)
	if err != nil {
		slog.Error("cannot encode the trigger header", "event", event, "error", err)
		return
	}
	w.Header().Set(header, string(encoded))
}
