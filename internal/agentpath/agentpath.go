// Package agentpath holds the one path rule the agent and the server share:
// which directories "myownpki-agent deployment add" refuses to make writable
// (docs/PHASE3.md section 11.2).
//
// It imports only the standard library, so the server's Add host assistant can
// use the agent's own list without linking the agent (and its ACME client).
package agentpath

import (
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// systemRoots name whole parts of the system; the agent's sandbox exists to
// keep it away from them.
var systemRoots = []string{"/", "/etc", "/usr", "/var", "/boot", "/dev", "/proc", "/sys", "/run", "/root", "/home", "/tmp",
	"/bin", "/sbin", "/opt", "/srv", "/mnt"}

var libRoot = regexp.MustCompile(`^/lib[0-9a-z]*$`)

// IsLib reports whether p is /lib, /lib64, /libx32 and the like (cleaned).
func IsLib(p string) bool { return libRoot.MatchString(p) }

// Broad reports whether p is a system root, or something below /proc, /sys or
// /dev: a directory the agent must not be allowed to write.
func Broad(p string) bool {
	c := path.Clean(filepath.ToSlash(p))
	if slices.Contains(systemRoots, c) || IsLib(c) {
		return true
	}
	for _, below := range []string{"/proc/", "/sys/", "/dev/"} {
		if strings.HasPrefix(c, below) {
			return true
		}
	}
	return false
}
