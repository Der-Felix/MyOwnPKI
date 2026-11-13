//go:build unix

package agent

import (
	"strings"
	"syscall"
	"testing"
)

// TestHookRunsWithUmask022: a caller with umask 077 (a root shell on a
// hardened host) must not leave a bundle only root can read. The test changes
// the umask of the whole process, so it is not parallel; the previous value is
// back when it ends.
func TestHookRunsWithUmask022(t *testing.T) {
	previous := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(previous) })

	f := newTrustFixture(t, osReleaseDebian)
	seen := -1
	f.runner.onRun = func([]string) {
		seen = syscall.Umask(0o022) // reads the value in force and sets the same one again
	}
	if err := f.install(); err != nil {
		t.Fatal(err)
	}
	if seen != 0o022 {
		t.Errorf("umask during the hook = %04o, want 0022", seen)
	}
	if got := syscall.Umask(0o077); got != 0o077 {
		t.Errorf("umask after the hook = %04o, want the caller's 0077", got)
	}
	if len(f.runner.calls) != 1 || !strings.Contains(strings.Join(f.runner.calls[0], " "), "update-ca-certificates") {
		t.Errorf("calls = %v", f.runner.calls)
	}
}
