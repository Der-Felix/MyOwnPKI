// Package assets embeds the brand files the admin UI serves: logo variants
// and favicons. assets/brand is their source of truth (see brand/README.md);
// only the files below are shipped in the binary.
package assets

import "embed"

// Brand is served under /static/brand/ by the admin listener.
//
//go:embed brand/*.svg brand/favicon.ico brand/png/apple-touch-icon.png
var Brand embed.FS
