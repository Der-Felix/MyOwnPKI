//go:build !windows

package agent

import (
	"fmt"
	"os"
	"syscall"
)

// The account key and deployment journal share one process lock. flock
// releases it after a crash, allowing the next process to recover safely.
func (a *Agent) deploymentLock() (func(), error) {
	f, err := os.OpenFile(a.st.path("deployment.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("another agent is using this state: %w", err)
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
}
