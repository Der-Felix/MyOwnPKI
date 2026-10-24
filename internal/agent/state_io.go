package agent

import (
	"os"
	"runtime"
)

func syncDirectory(root *os.Root, name string) error {
	// Windows only has to compile; Linux is the v0.3.0 deployment target.
	if runtime.GOOS == "windows" {
		return nil
	}
	f, err := root.Open(name)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return f.Sync()
}

// durableState persists the account key before its thumbprint can be
// registered, and the deployment journal before any target is replaced.
func (a *Agent) durableState(name string, data []byte) error {
	if err := writeFile(a.st.path(name), data, 0o600); err != nil {
		return err
	}
	root, err := os.OpenRoot(a.st.dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	return syncDirectory(root, ".")
}
