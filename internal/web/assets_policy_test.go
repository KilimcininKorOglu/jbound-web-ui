package web

import (
	"io/fs"
	"path"
	"strings"
	"testing"
)

// evalFree lists the scripts that run on page load. None of them may call eval.
//
// The content security policy of the panel refuses eval, and the vendor
// bundles of the reference interface are development builds that wrap every
// module in a call to it. Loading one of those would break the page with
// nothing more than a console message, so the check belongs here.
func TestLoadedScriptsDoNotCallEval(t *testing.T) {
	loaded := []string{
		"static/js/layout.js",
		"static/js/helpers.js",
		"static/js/menu.js",
		"static/js/app.js",
		"static/js/bootstrap.bundle.min.js",
		"static/js/perfect-scrollbar.min.js",
		"static/js/sweetalert2.min.js",
	}

	for _, name := range loaded {
		t.Run(path.Base(name), func(t *testing.T) {
			body, err := fs.ReadFile(staticFS, name)
			if err != nil {
				t.Fatalf("cannot read %s: %v", name, err)
			}
			if strings.Contains(string(body), "eval(") {
				t.Errorf("%s calls eval, which the content security policy refuses", name)
			}
		})
	}
}

// htmx is the exception. It exposes eval through its own helper and through
// the js: prefix, neither of which the panel uses, so the call never runs.
func TestHtmxIsTheOnlyScriptAllowedToContainEval(t *testing.T) {
	body, err := fs.ReadFile(staticFS, "static/js/htmx.min.js")
	if err != nil {
		t.Fatalf("cannot read the htmx bundle: %v", err)
	}
	if !strings.Contains(string(body), "version:\"2.") {
		t.Error("the bundled htmx is not version 2")
	}
}

// No dialog heading may go through the option SweetAlert2 parses as HTML.
//
// A toast message reaches the client as JSON in a response header, so the
// template engine that escapes everything else never sees it, and SetToast
// takes free form text from any handler. titleText is written with innerText,
// so a message cannot become markup whatever a future caller puts into it.
func TestNoDialogRendersItsHeadingAsHTML(t *testing.T) {
	body, err := fs.ReadFile(staticFS, "static/js/app.js")
	if err != nil {
		t.Fatalf("cannot read the panel script: %v", err)
	}

	if strings.Contains(string(body), "title:") {
		t.Error("app.js sets title:, which SweetAlert2 parses as HTML; use titleText:")
	}
	if !strings.Contains(string(body), "titleText:") {
		t.Error("app.js sets no heading at all, so this check guards nothing")
	}
}

// Every asset the layouts reference must exist. A typo in a path would
// otherwise only appear as a missing stylesheet in the browser.
func TestLayoutsReferenceOnlyAssetsThatExist(t *testing.T) {
	layouts := []string{"templates/layouts/app.html", "templates/layouts/auth.html"}

	for _, layout := range layouts {
		body, err := fs.ReadFile(templateFS, layout)
		if err != nil {
			t.Fatalf("cannot read %s: %v", layout, err)
		}

		for _, reference := range extractStaticPaths(string(body)) {
			// The template carries the asset root as an attribute of its own.
			// It names a directory rather than a file.
			if strings.HasSuffix(reference, "/") {
				continue
			}
			name := "static/" + strings.TrimPrefix(reference, "/static/")
			if _, err := fs.Stat(staticFS, name); err != nil {
				t.Errorf("%s references %s, which is not embedded", layout, reference)
			}
		}
	}
}

// extractStaticPaths pulls every /static/ reference out of a template.
func extractStaticPaths(body string) []string {
	const marker = "/static/"

	var found []string
	for index := strings.Index(body, marker); index >= 0; {
		rest := body[index:]
		end := strings.IndexAny(rest, "\"'")
		if end < 0 {
			break
		}
		found = append(found, rest[:end])

		next := strings.Index(body[index+len(marker):], marker)
		if next < 0 {
			break
		}
		index += len(marker) + next
	}
	return found
}

// ownScripts are the files the panel writes, as opposed to the ones it
// vendors. A rule about how the panel behaves can only be held against these.
var ownScripts = []string{
	"static/js/app.js",
	"static/js/layout.js",
}

func TestThePanelWritesNoBrowserDialog(t *testing.T) {
	// A native dialog freezes the page, ignores the language and the theme the
	// reader chose, and words its buttons in the browser's language rather
	// than the panel's. Every confirmation goes through SweetAlert2 instead,
	// and the way that stays true is that nothing here calls the originals.
	for _, name := range ownScripts {
		t.Run(path.Base(name), func(t *testing.T) {
			body, err := fs.ReadFile(staticFS, name)
			if err != nil {
				t.Fatalf("cannot read %s: %v", name, err)
			}

			for _, call := range []string{"alert(", "confirm(", "prompt("} {
				if strings.Contains(string(body), call) {
					t.Errorf("%s calls %s", name, call)
				}
			}
		})
	}
}

func TestBothHtmxDialogsAreHandedToSweetAlert(t *testing.T) {
	// htmx calls window.confirm for hx-confirm and window.prompt for
	// hx-prompt. Those two are the only native dialogs the panel can produce,
	// and each one appears only when nothing has taken the event first. Losing
	// either handler brings the browser dialog back with no error anywhere.
	body, err := fs.ReadFile(staticFS, "static/js/app.js")
	if err != nil {
		t.Fatalf("cannot read app.js: %v", err)
	}
	source := string(body)

	for _, event := range []string{"htmx:confirm", "htmx:prompt"} {
		if !strings.Contains(source, event) {
			t.Errorf("app.js does not handle %s", event)
		}
	}
	// Taking the event without preventing the default leaves htmx free to open
	// the native dialog anyway.
	if strings.Count(source, "event.preventDefault()") < 2 {
		t.Error("a dialog handler does not stop the browser dialog behind it")
	}
}

func TestEveryDialogOpensInTheMiddleOfThePage(t *testing.T) {
	// A dialog that asks whether to delete a record from every server of a
	// group has to be read before it is answered. The toast may sit in the
	// corner; a question may not.
	body, err := fs.ReadFile(staticFS, "static/js/app.js")
	if err != nil {
		t.Fatalf("cannot read app.js: %v", err)
	}
	source := string(body)

	// Every Swal.fire is either a dialog placed in the middle or the toast
	// mixin, which is built once and says where it goes.
	dialogs := strings.Count(source, "Swal.fire({")
	centred := strings.Count(source, "position: 'center'")
	if dialogs != centred {
		t.Errorf("%d dialog(s) open and %d say they open in the middle", dialogs, centred)
	}
}
