// Package web embeds the built frontend assets and serves the operations SPA.
package web

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:dist
var distFS embed.FS

// Handler returns an HTTP handler with SPA fallback.
func Handler() http.Handler {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		panic("web: dist sub: " + err.Error())
	}
	fileServer := http.FileServer(http.FS(sub))
	indexBytes, _ := fs.ReadFile(sub, "index.html")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(indexBytes)
			return
		}
		if info, err := fs.Stat(sub, path); err == nil && !info.IsDir() {
			fileServer.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(indexBytes)
	})
}
