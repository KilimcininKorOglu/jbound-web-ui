package web

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"time"
)

//go:embed static
var staticFS embed.FS

// staticAsset is one embedded file, ready to serve.
type staticAsset struct {
	body        []byte
	etag        string
	contentType string
}

// staticAssets serves the embedded stylesheets, scripts, fonts and images.
//
// Everything ships inside the binary, so a deployment is one file and an air
// gapped install needs no font provider or script CDN.
type staticAssets struct {
	files map[string]staticAsset
}

// newStaticAssets reads every embedded file and computes its tag.
//
// The tags are built once at startup. The content cannot change while the
// process runs, and hashing three megabytes on every request would be waste.
func newStaticAssets() (*staticAssets, error) {
	assets := &staticAssets{files: map[string]staticAsset{}}

	err := fs.WalkDir(staticFS, "static", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}

		body, err := staticFS.ReadFile(name)
		if err != nil {
			return fmt.Errorf("cannot read %s: %w", name, err)
		}
		sum := sha256.Sum256(body)

		contentType := mime.TypeByExtension(path.Ext(name))
		if contentType == "" {
			contentType = "application/octet-stream"
		}

		assets.files[name[len("static/"):]] = staticAsset{
			body: body,
			// A strong tag. The content is fixed at build time, so a byte for
			// byte match is exactly what the tag has to promise.
			etag:        `"` + hex.EncodeToString(sum[:16]) + `"`,
			contentType: contentType,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return assets, nil
}

func (s *staticAssets) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Path

	// The path arrives with the prefix already removed, so the root of the
	// tree is the empty string. A directory listing would expose the asset
	// tree and serve no purpose.
	asset, ok := s.files[name]
	if !ok {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", asset.contentType)
	w.Header().Set("ETag", asset.etag)
	// Revalidate rather than cache blindly. The assets change whenever the
	// binary does, and the path stays the same, so a stale copy would survive
	// an upgrade and load the previous version of a script.
	//
	// This replaces the no-store the security headers set for every other
	// route. An asset carries nothing about the reader, and refusing to store
	// it would mean fetching every stylesheet and font on every page.
	w.Header().Set("Cache-Control", "no-cache")

	// ServeContent answers a conditional request from the tag above, so a
	// browser that already holds the file gets a 304 and no body.
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(asset.body))
}

// staticHandler mounts the assets under /static/.
func staticHandler() http.Handler {
	assets, err := newStaticAssets()
	if err != nil {
		// The directory is embedded at compile time. A failure here means the
		// binary was built wrong, and there is nothing to serve.
		panic("cannot read the embedded static directory: " + err.Error())
	}
	return http.StripPrefix("/static/", assets)
}
