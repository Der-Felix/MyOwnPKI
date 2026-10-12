// Package presets embeds the built-in certificate presets (*.yaml in this directory).
//
// The files are data: internal/ca/preset parses and validates them.
// They were ported from legacy/lib/presets.sh; a test keeps both in sync.
package presets

import "embed"

// FS holds every *.yaml file of this directory.
//
//go:embed *.yaml
var FS embed.FS
