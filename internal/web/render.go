package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"time"

	"unbound-web/internal/auth"
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
	"system":   "app",
}

// templateSet holds the parsed templates.
//
// Each page gets its own set, because every page defines a template named
// "content" and one shared set could not hold them all.
type templateSet struct {
	pages    map[string]*template.Template
	partials *template.Template
}

// funcs are available to every template.
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
	// duration writes a bound the way an operator types it. Go prints 24h as
	// 24h0m0s, which is three units for a value that has one.
	"duration": func(d time.Duration) string {
		text := d.String()
		if strings.HasSuffix(text, "m0s") {
			text = strings.TrimSuffix(text, "0s")
		}
		if strings.HasSuffix(text, "h0m") {
			text = strings.TrimSuffix(text, "0m")
		}
		return text
	},
}

// parseTemplates builds one set per page plus the partial set.
func parseTemplates() (*templateSet, error) {
	partials, err := template.New("partials").Funcs(funcs).
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

		tmpl, err := template.New(name).Funcs(funcs).ParseFS(templateFS,
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

	// Theme is what the html element carries. It is read from the cookie on
	// every render, so the first paint is already in the chosen theme and
	// nothing flashes.
	Theme string
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

	tmpl, ok := a.tmpl.pages[page]
	if !ok {
		slog.Error("unknown page requested", "page", page)
		http.Error(w, "internal error", http.StatusInternalServerError)
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

	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "layout", data); err != nil {
		slog.Error("cannot render the page", "page", page, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeHTML(w, status, buf.Bytes())
}

// RenderPartial writes one fragment, which is what an htmx swap expects.
func (a *App) RenderPartial(w http.ResponseWriter, status int, name string, data any) {
	var buf bytes.Buffer

	if err := a.tmpl.partials.ExecuteTemplate(&buf, name, data); err != nil {
		slog.Error("cannot render the partial", "partial", name, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeHTML(w, status, buf.Bytes())
}

func writeHTML(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if _, err := w.Write(body); err != nil {
		slog.Error("cannot write the response", "error", err)
	}
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
