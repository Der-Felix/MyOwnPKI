//go:build !unix

package agent

// withHookUmask runs f. The trust hooks exist on Linux only; there is no umask
// to set elsewhere.
func withHookUmask(f func()) { f() }
