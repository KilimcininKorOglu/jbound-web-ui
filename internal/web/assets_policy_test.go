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
