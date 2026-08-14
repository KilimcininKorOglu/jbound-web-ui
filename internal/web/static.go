package web

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"sync"
	"time"
)

//go:embed static
var staticFS embed.FS

// staticAsset is one embedded file, ready to serve.
type staticAsset struct {
	body        []byte
	etag        string
	contentType string

	// packed is the same file compressed, and packedEtag names that copy. Both
	// stay empty for a format that is already compressed, and for a file that
	// compression made no smaller.
	packed     []byte
	packedEtag string
}

// staticAssets serves the embedded stylesheets, scripts, fonts and images.
//
// Everything ships inside the binary, so a deployment is one file and an air
// gapped install needs no font provider or script CDN.
type staticAssets struct {
	files map[string]staticAsset
}

// newStaticAssets reads every embedded file, computes its tag and compresses
// what is worth compressing.
//
// It runs once per process, through staticOnce. The content cannot change
// while the process runs, so hashing and compressing three megabytes a second
// time would produce the same bytes at the same cost.
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

		asset := staticAsset{
			body: body,
			// A strong tag. The content is fixed at build time, so a byte for
			// byte match is exactly what the tag has to promise.
			etag:        `"` + hex.EncodeToString(sum[:16]) + `"`,
			contentType: contentType,
		}

		// Compressed once, at startup, rather than per request. The bytes never
		// change while the process runs, and the stylesheets are the largest
		// thing the panel sends.
		if packed, ok := packAsset(body, contentType); ok {
			asset.packed = packed
			// A copy with its own bytes needs its own tag, or a cache that
			// holds one would answer a request for the other with a 304.
			asset.packedEtag = asset.etag[:len(asset.etag)-1] + `-gzip"`
		}

		assets.files[name[len("static/"):]] = asset
		return nil
	})
	if err != nil {
		return nil, err
	}
	return assets, nil
}

// packAsset compresses one embedded file, or reports that it is not worth it.
//
// A font or an image is already compressed, and running deflate over it costs
// memory at startup to send more bytes than the original.
func packAsset(body []byte, contentType string) ([]byte, bool) {
	if !compressibleType(contentType) {
		return nil, false
	}

	var buf bytes.Buffer
	writer, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, false
	}
	if _, err := writer.Write(body); err != nil {
		return nil, false
	}
	if err := writer.Close(); err != nil {
		return nil, false
	}

	if buf.Len() >= len(body) {
		return nil, false
	}
	return buf.Bytes(), true
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

	body, etag := asset.body, asset.etag
	if len(asset.packed) > 0 {
		// Answered either way, so a cache between the panel and the browser
		// cannot hand the compressed copy to a client that never asked for it.
		w.Header().Set("Vary", "Accept-Encoding")

		if acceptsGzip(r) {
			body, etag = asset.packed, asset.packedEtag
			w.Header().Set("Content-Encoding", "gzip")
		}
	}

	w.Header().Set("Content-Type", asset.contentType)
	w.Header().Set("ETag", etag)
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
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(body))
}

// staticOnce holds the one asset set of the process.
//
// Router is called once by the service and once per request by the tests, and
// the assets are immutable either way.
var staticOnce = sync.OnceValues(newStaticAssets)

// staticHandler mounts the assets under /static/.
func staticHandler() http.Handler {
	assets, err := staticOnce()
	if err != nil {
		// The directory is embedded at compile time. A failure here means the
		// binary was built wrong, and there is nothing to serve.
		panic("cannot read the embedded static directory: " + err.Error())
	}
	return http.StripPrefix("/static/", assets)
}
