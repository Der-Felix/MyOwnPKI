package agent

import (
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// The directories "deployment add" refuses to make writable (docs/PHASE3.md
// §11.2). They name whole parts of the system; the agent's sandbox exists to
// keep it away from them. The same list is a warning of "config check", so an
// existing configuration keeps working.

var systemRoots = []string{"/", "/etc", "/usr", "/var", "/boot", "/dev", "/proc", "/sys", "/run", "/root", "/home", "/tmp",
	"/bin", "/sbin", "/opt", "/srv", "/mnt"}

var libRoot = regexp.MustCompile(`^/lib[0-9a-z]*$`)

// wideParents hold system configuration; a direct child is legitimate but
// wider than needed (/etc/nginx rather than /etc/nginx/myownpki).
var wideParents = []string{"/etc", "/usr", "/boot", "/bin", "/sbin", "/root"}

var wideDirs = []string{"/var/lib", "/var/log", "/var/cache", "/var/spool", "/var/run"}

func slashClean(p string) string { return path.Clean(filepath.ToSlash(p)) }

// broadDir: a system root, or something below /proc, /sys or /dev.
func broadDir(p string) bool {
	c := slashClean(p)
	if slices.Contains(systemRoots, c) || libRoot.MatchString(c) {
		return true
	}
	for _, below := range []string{"/proc/", "/sys/", "/dev/"} {
		if strings.HasPrefix(c, below) {
			return true
		}
	}
	return false
}

// wideDir: legitimate, but wider than a certificate directory needs.
func wideDir(p string) bool {
	c := slashClean(p)
	return slices.Contains(wideDirs, c) || slices.Contains(wideParents, path.Dir(c)) || libRoot.MatchString(path.Dir(c))
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
