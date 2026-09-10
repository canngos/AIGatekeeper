// Package web embeds the built admin UI. Run `npm ci && npm run build` in
// this directory (or `go generate ./web`) to populate dist/ before building
// the binary; without it the admin listener serves a "UI not built" page and
// the JSON API keeps working.
package web

import (
	"embed"
	"io/fs"
)

//go:generate npm ci
//go:generate npm run build

//go:embed all:dist
var dist embed.FS

// FS returns the built UI files rooted at dist/.
func FS() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		return dist
	}
	return sub
}

// Built reports whether an index.html is embedded.
func Built() bool {
	_, err := fs.Stat(FS(), "index.html")
	return err == nil
}
