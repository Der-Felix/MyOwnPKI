// Package web embeds the static UI assets: the global stylesheets
// (styles/*.css) and the icon sprite (icons.svg). Templates live in
// internal/web; this package only ships files.
package web

import "embed"

// Static is served under /static/ by the admin listener.
//
//go:embed styles/*.css icons.svg
var Static embed.FS
