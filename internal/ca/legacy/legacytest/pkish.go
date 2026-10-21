package legacytest

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Step is one pki.sh command with extra environment variables.
type Step struct {
	Args []string
	Env  []string
}

// NeedPkiSh returns bash and the OpenSSL pki.sh should use ("" = its own
// lookup), or skips: the real pki.sh runs on Linux, and in Git Bash with
// LEGACY_TEST_OPENSSL=/usr/bin/openssl (a POSIX OpenSSL for POSIX paths).
// In CI on Linux a missing bash is fatal – the test must not vanish.
func NeedPkiSh(tb testing.TB) (bash, openssl string) {
	tb.Helper()
	bash, err := exec.LookPath("bash")
	openssl = os.Getenv("LEGACY_TEST_OPENSSL")
	if err != nil || (runtime.GOOS != "linux" && openssl == "") {
		if runtime.GOOS == "linux" && os.Getenv("CI") != "" {
			tb.Fatal("bash missing in CI")
		}
		tb.Skip("the pki.sh fixture needs bash and POSIX paths: Linux, or LEGACY_TEST_OPENSSL=/usr/bin/openssl in Git Bash")
	}
	return bash, openssl
}

// PkiSh runs legacy/pki.sh --dir <dir>/pki -y with each step and returns
// the pki directory. Not a testing helper on purpose: callers build it
// once per process (sync.Once) and keep the error.
func PkiSh(bash, openssl, dir string, steps []Step) (string, error) {
	root, err := repoRoot()
	if err != nil {
		return "", err
	}
	script := filepath.Join(root, "legacy", "pki.sh")
	pkiDir := filepath.Join(dir, "pki")
	for _, s := range steps {
		// #nosec G204 -- test: runs the repository's own legacy script
		cmd := exec.CommandContext(context.Background(), bash, append([]string{PosixPath(script), "--dir", PosixPath(pkiDir), "-y", "--no-color"}, s.Args...)...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), s.Env...)
		if openssl != "" {
			cmd.Env = append(cmd.Env, "OPENSSL="+openssl)
		}
		if out, cerr := cmd.CombinedOutput(); cerr != nil {
			return "", errors.New("pki " + strings.Join(s.Args, " ") + ": " + cerr.Error() + "\n" + string(out))
		}
	}
	return pkiDir, nil
}

// repoRoot is the directory with go.mod above the working directory (a
// test runs in its package directory).
func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, serr := os.Stat(filepath.Join(dir, "go.mod")); serr == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("go.mod not found above the working directory")
		}
		dir = parent
	}
}

// PosixPath turns C:\x into /c/x for Git Bash; other paths stay.
func PosixPath(p string) string {
	if runtime.GOOS != "windows" || len(p) < 2 || p[1] != ':' {
		return p
	}
	return "/" + strings.ToLower(p[:1]) + filepath.ToSlash(p[2:])
}
