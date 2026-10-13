// Package web embeds the static UI assets: the global stylesheets
// (styles/*.css). Templates live in internal/web; this package only ships files.
package web

import "embed"

// Static is served under /static/ by the admin listener.
//
//go:embed styles/*.css
var Static embed.FS
