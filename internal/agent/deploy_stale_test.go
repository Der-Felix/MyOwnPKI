package agent

import (
	"bytes"
	"crypto/rand"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRecoverRemovesStaleTemporaryFiles: a killed agent leaves the exclusive
// temporary file of atomicTarget behind, with a copy of the target (for a
// combined file the private key). The recovery step before the first pass
// removes exactly those files from the target directories and nothing else.
func TestRecoverRemovesStaleTemporaryFiles(t *testing.T) {
	t.Parallel()
	r := newDeployRig(t, ProfileNginx, rigCombined)
	var logs bytes.Buffer
	r.a.log = slog.New(slog.NewTextHandler(&logs, nil))
	root := r.a.cfg.Paths[0]
	nginxDir := filepath.Join(root, "service0")
	r.installOld(t)

	stale := []string{
		filepath.Join(nginxDir, ".myownpki-"+rand.Text()),
		filepath.Join(root, ".myownpki-"+rand.Text()), // next to the combined file
	}
	for _, p := range stale {
		if err := os.WriteFile(p, []byte("PRIVATE KEY copy"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Never touched: other names, wrong length or alphabet, a directory.
	keep := []string{
		filepath.Join(nginxDir, ".myownpki-"),
		filepath.Join(nginxDir, ".myownpki-"+strings.Repeat("A", 25)),
		filepath.Join(nginxDir, ".myownpki-"+strings.Repeat("A", 27)),
		filepath.Join(nginxDir, ".myownpki-"+strings.Repeat("a", 26)),
		filepath.Join(nginxDir, ".myownpki-"+strings.Repeat("1", 26)),
		filepath.Join(nginxDir, "x.myownpki-"+strings.Repeat("A", 26)),
		filepath.Join(nginxDir, "notes.txt"),
		filepath.Join(root, "unrelated.pem"),
	}
	for _, p := range keep {
		if err := os.WriteFile(p, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	dirNamed := filepath.Join(nginxDir, ".myownpki-"+strings.Repeat("B", 26))
	if err := os.Mkdir(dirNamed, 0o750); err != nil {
		t.Fatal(err)
	}
	// A symlink with a temporary name stays, and so does its target.
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(nginxDir, ".myownpki-"+strings.Repeat("C", 26))
	if err := os.Symlink(outside, link); err != nil {
		t.Logf("no symlinks here, that part is skipped: %v", err)
		link = ""
	}
	// A directory that is no target directory is not looked at.
	other := filepath.Join(root, "other")
	if err := os.Mkdir(other, 0o750); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(other, ".myownpki-"+rand.Text())
	if err := os.WriteFile(foreign, []byte("not ours to clean"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := r.a.Recover(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, p := range stale {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("%s: the stale temporary file remained: %v", p, err)
		}
		if !strings.Contains(logs.String(), filepath.Base(p)) {
			t.Errorf("%s: no warning with the path", p)
		}
	}
	for _, p := range append(keep, dirNamed, outside, foreign) {
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("%s: must be left alone: %v", p, err)
		}
	}
	if link != "" {
		if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Errorf("the symlink was removed or replaced: %v", err)
		}
	}
	if strings.Contains(logs.String(), "PRIVATE KEY") {
		t.Error("file contents reached the log")
	}
	r.assertFiles(t, r.old)
}
