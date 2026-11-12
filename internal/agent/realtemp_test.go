package agent

import (
	"path/filepath"
	"testing"
)

// realTempDir is t.TempDir() with every symbolic link resolved. The checks of
// "deployment add" refuse a path with a link on its way (checkNoSymlink), and
// on macOS t.TempDir() lives below /var, which is a link to /private/var. A
// test that feeds paths below its root into those checks must start from the
// real directory, or it would be refused for the machine's layout instead of
// for what it is about.
func realTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}
