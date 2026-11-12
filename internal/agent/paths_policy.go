package agent

import (
	"path"
	"path/filepath"
	"slices"

	"github.com/Der-Felix/MyOwnPKI/internal/agentpath"
)

// The directories "deployment add" refuses to make writable (docs/PHASE3.md
// §11.2). They name whole parts of the system; the agent's sandbox exists to
// keep it away from them. The same list is a warning of "config check", so an
// existing configuration keeps working. The list itself lives in
// internal/agentpath, so the server's Add host assistant refuses the same
// directories without linking the agent.

// wideParents hold system configuration; a direct child is legitimate but
// wider than needed (/etc/nginx rather than /etc/nginx/myownpki).
var wideParents = []string{"/etc", "/usr", "/boot", "/bin", "/sbin", "/root"}

var wideDirs = []string{"/var/lib", "/var/log", "/var/cache", "/var/spool", "/var/run"}

func slashClean(p string) string { return path.Clean(filepath.ToSlash(p)) }

// broadDir: a system root, or something below /proc, /sys or /dev.
func broadDir(p string) bool { return agentpath.Broad(p) }

// wideDir: legitimate, but wider than a certificate directory needs.
func wideDir(p string) bool {
	c := slashClean(p)
	return slices.Contains(wideDirs, c) || slices.Contains(wideParents, path.Dir(c)) || agentpath.IsLib(path.Dir(c))
}

// narrowerThan is the suggestion in the messages.
func narrowerThan(p string) string {
	c := slashClean(p)
	if broadDir(c) || c == "/etc/ssl" {
		return "/etc/ssl/myownpki"
	}
	return c + "/myownpki"
}

func tooBroadMessage(p string) string {
	return "too broad – the agent may write only where \"paths\" allows; use a subdirectory such as " + narrowerThan(p)
}
