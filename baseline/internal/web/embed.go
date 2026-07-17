// Package web embeds the built frontend assets via go:embed and provides
// an http.Handler that serves the SPA with proper fallback.
package web

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:dist
var distFS embed.FS

// Handler returns an http.Handler that serves the embedded frontend.
// Non-file paths fall back to index.html for client-side routing.
func Handler() http.Handler {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		panic("web: dist sub: " + err.Error())
	}
	fileServer := http.FileServer(http.FS(sub))
	indexBytes, _ := fs.ReadFile(sub, "index.html")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")

		// Empty path → serve index.html directly (avoid FileServer redirect loop).
		if path == "" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(indexBytes)
			return
		}

		// Check if the path refers to a real file in the embed FS.
		if info, err := fs.Stat(sub, path); err == nil && !info.IsDir() {
			fileServer.ServeHTTP(w, r)
			return
		}

		// Not a real file — serve index.html for SPA routing.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(indexBytes)
	})
}
