//go:build unix

package agent

import (
	"sync"
	"syscall"
)

// hookUmask is the umask of the trust hook: the bundle tools of the
// distributions create the bundle with the mode their umask allows, so a root
// shell with umask 077 would leave a bundle that only root can read.
const hookUmask = 0o022

// umaskMu serializes the change: the umask belongs to the whole process, and
// two overlapping changes would restore each other's value.
var umaskMu sync.Mutex

// withHookUmask runs f with umask 022 and puts the previous umask back. A child
// started inside f inherits it. Only the trust hooks use this, in a one-shot
// command, so no other goroutine creates files meanwhile.
func withHookUmask(f func()) {
	umaskMu.Lock()
	defer umaskMu.Unlock()
	previous := syscall.Umask(hookUmask)
	defer syscall.Umask(previous)
	f()
}
