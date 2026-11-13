package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// The root of this PKI in the system trust store of the host (docs/PHASE3.md
// §15, decision 4). It is an opt-in command run by root ("trust install",
// "setup --system-trust", the Salt formula), never part of "run": the confined
// service process has no write access to the host's trust anchors and must not
// get any.
//
// What the code does, and nothing else:
//
//   - the file is the root the host already pinned at enrollment: ca_bundle is
//     read once, must hold exactly one self-signed CA certificate whose SHA-256
//     equals the pin, and the bytes written are the ones that were checked
//   - the target and the hook are fixed per family; nothing from agent.yaml
//     reaches a path or an argument vector
//   - a failed hook puts the previous state back, so "file present" means "the
//     hook succeeded"

// trustFamily is one family of Linux distributions with its fixed targets.
type trustFamily struct {
	// Name is the family as shown to the operator.
	Name string
	// Dir and File are slash paths below the file system root.
	Dir  string
	File string
	// Install and Remove are the argument vectors of the hook, no shell.
	Install []string
	Remove  []string
}

var (
	trustDebian = trustFamily{
		Name: "Debian", Dir: "/usr/local/share/ca-certificates", File: "myownpki-agent-root.crt",
		Install: []string{"/usr/sbin/update-ca-certificates"},
		// A normal run already drops the dangling link of the removed file;
		// --fresh would rebuild every link of the store for nothing.
		Remove: []string{"/usr/sbin/update-ca-certificates"},
	}
	trustRedHat = trustFamily{
		Name: "RedHat", Dir: "/etc/pki/ca-trust/source/anchors", File: "myownpki-agent-root.pem",
		Install: []string{"/usr/bin/update-ca-trust"},
		Remove:  []string{"/usr/bin/update-ca-trust"},
	}
)

const (
	trustHookTimeout = 60 * time.Second
	trustHookPATH    = "/usr/sbin:/usr/bin:/sbin:/bin"
	maxOSReleaseSize = 64 << 10
	// trustConfigKey is the top-level key of agent.yaml.
	trustConfigKey = "system_trust"
)

// trustRunner runs one fixed argument vector with a fixed environment and
// returns the end of its combined output.
type trustRunner interface {
	Run(ctx context.Context, argv, env []string) (output string, err error)
}

type trustExecRunner struct{}

func (trustExecRunner) Run(ctx context.Context, argv, env []string) (string, error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) // #nosec G204 G702 -- the argument vector is a constant of this file, never a shell
	cmd.Env = env
	cmd.Dir = "/"
	cmd.WaitDelay = 5 * time.Second
	var out tailWriter
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return string(out.data), err
}

// trustEnv is everything the trust code takes from the host: the file system
// root, the runner and the effective user. Tests set all three, so they need
// no root and run on every platform; production uses defaultTrustEnv.
type trustEnv struct {
	// Root is the prefix of every fixed path ("" is the real root).
	Root   string
	Runner trustRunner
	EUID   func() int
}

func defaultTrustEnv() trustEnv {
	return trustEnv{Runner: trustExecRunner{}, EUID: os.Geteuid}
}

// trustHost is the environment of the commands; tests replace it.
var trustHost = defaultTrustEnv

func (e trustEnv) path(slash string) string {
	return filepath.Join(e.Root, filepath.FromSlash(slash))
}

// detect names the family of this host from os-release: ID or ID_LIKE says
// debian, or one of rhel, fedora, centos. Anything else is refused.
func (e trustEnv) detect() (*trustFamily, error) {
	var data []byte
	var err error
	for _, name := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		if data, err = readLimited(e.path(name), maxOSReleaseSize); err == nil {
			break
		}
	}
	if err != nil {
		return nil, errors.New("system trust supports Debian- and RedHat-family Linux only; this host has no readable os-release")
	}
	id, like := parseOSRelease(data)
	return familyOf(id, like)
}

func familyOf(id, like string) (*trustFamily, error) {
	names := strings.Fields(strings.ToLower(id + " " + like))
	has := func(want ...string) bool {
		for _, n := range names {
			for _, w := range want {
				if n == w {
					return true
				}
			}
		}
		return false
	}
	switch {
	case has("debian"):
		return &trustDebian, nil
	case has("rhel", "fedora", "centos"):
		return &trustRedHat, nil
	}
	return nil, fmt.Errorf("system trust supports Debian-family (os-release ID or ID_LIKE debian) and RedHat-family (rhel, fedora, centos) hosts only; this host reports ID=%q ID_LIKE=%q",
		clipUTF8(sanitizeHookOutput([]byte(id)), 64, false), clipUTF8(sanitizeHookOutput([]byte(like)), 64, false))
}

// parseOSRelease returns ID and ID_LIKE of an os-release file.
func parseOSRelease(data []byte) (id, like string) {
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if n := len(value); n >= 2 && (value[0] == '"' && value[n-1] == '"' || value[0] == '\'' && value[n-1] == '\'') {
			value = value[1 : n-1]
		}
		switch key {
		case "ID":
			id = value
		case "ID_LIKE":
			like = value
		}
	}
	return id, like
}

func readLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 G703 -- a fixed path below the file system root
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, limit))
	if err != nil {
		return nil, err
	}
	return data, nil
}

// trustTarget is the fixed file of a family and what is there now.
type trustTarget struct {
	Dir, File string
	// Have: the file exists; Current is its content.
	Have    bool
	Current []byte
}

// target inspects the fixed directory and file. Neither may be a symlink. A
// missing directory is an error for an install (the ca-certificates package is
// missing) and "nothing there" for everything else.
func (e trustEnv) target(f *trustFamily, forInstall bool) (*trustTarget, error) {
	t := &trustTarget{Dir: e.path(f.Dir)}
	t.File = filepath.Join(t.Dir, f.File)
	st, err := os.Lstat(t.Dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if forInstall {
			return nil, fmt.Errorf("%s does not exist: is the CA certificates package of this %s host installed? nothing was changed", t.Dir, f.Name)
		}
		return t, nil
	case err != nil:
		return nil, fmt.Errorf("check %s: %w", t.Dir, err)
	case !st.IsDir():
		return nil, fmt.Errorf("%s is not a directory (a symbolic link is refused too); nothing was changed", t.Dir)
	}
	if _, err = os.Lstat(t.File); errors.Is(err, os.ErrNotExist) {
		return t, nil
	} else if err != nil {
		return nil, fmt.Errorf("check %s: %w", t.File, err)
	}
	if t.Current, err = readSetupRegular(t.File, maxSetupRootSize, false); err != nil {
		return nil, fmt.Errorf("%s: %w (a symbolic link is refused); nothing was changed", t.File, err)
	}
	t.Have = true
	return t, nil
}

// runHook runs one fixed argument vector under the trust timeout. The
// environment is a fixed PATH: no proxy and no SSL_CERT_* variable reaches it.
func (e trustEnv) runHook(ctx context.Context, argv []string) error {
	ctx, cancel := context.WithTimeout(ctx, trustHookTimeout)
	defer cancel()
	output, err := e.Runner.Run(ctx, argv, []string{"PATH=" + trustHookPATH, "LC_ALL=C"})
	output = sanitizeHookOutput([]byte(output)) // control characters out, the end kept, bounded
	if err != nil {
		return errors.New(hookErrorText(filepath.Base(argv[0]), err, output))
	}
	return nil
}

// restoreTrustFile puts back the state found: the old content or no file.
func restoreTrustFile(t *trustTarget) error {
	if t.Have {
		return atomicSetupFile(t.File, t.Current, 0o644)
	}
	if err := os.Remove(t.File); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// installTrustFile writes the checked certificate and runs the hook. A failed
// hook restores the previous state. changed is false when the file already
// held exactly these bytes: then nothing is written and no hook runs.
func (e trustEnv) installTrustFile(ctx context.Context, f *trustFamily, t *trustTarget, pem []byte) (changed bool, err error) {
	if t.Have && bytes.Equal(t.Current, pem) {
		return false, nil
	}
	if err = atomicSetupFile(t.File, pem, 0o644); err != nil {
		return false, err
	}
	if err = e.runHook(ctx, f.Install); err != nil {
		if restoreErr := restoreTrustFile(t); restoreErr != nil {
			return false, fmt.Errorf("%w; putting the previous state back failed too, check %s: %w", err, t.File, restoreErr)
		}
		return false, fmt.Errorf("%w; the previous state of %s was restored", err, t.File)
	}
	return true, nil
}

// removeTrustFile deletes the file and runs the hook; a failed hook puts the
// file back, because the store still holds the root.
func (e trustEnv) removeTrustFile(ctx context.Context, f *trustFamily, t *trustTarget) error {
	if err := os.Remove(t.File); err != nil {
		return fmt.Errorf("remove %s: %w", t.File, err)
	}
	if err := e.runHook(ctx, f.Remove); err != nil {
		if restoreErr := restoreTrustFile(t); restoreErr != nil {
			return fmt.Errorf("%w; putting the file back failed too, check %s: %w", err, t.File, restoreErr)
		}
		return fmt.Errorf("%w; %s was put back", err, t.File)
	}
	return nil
}

// editConfigFile applies mutate to agent.yaml and writes the result (and the
// previous file as .bak) when it changed. The result is checked with the loader
// of "run" before a byte is written. It reports whether the file changed.
func editConfigFile(path string, mutate func(*yamlEditor) error) (bool, error) {
	data, err := readSetupRegular(path, maxConfigSize, false)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", path, err)
	}
	st, err := os.Stat(path)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", path, err)
	}
	ed, err := openYAMLEditor(data)
	if err != nil {
		return false, err
	}
	if err = mutate(ed); err != nil {
		return false, err
	}
	out, err := ed.bytes()
	if err != nil {
		return false, err
	}
	if bytes.Equal(out, data) {
		return false, nil
	}
	if _, err = ParseConfig(path, out); err != nil {
		return false, fmt.Errorf("the change would make agent.yaml invalid; nothing was changed:\n%w", err)
	}
	if err = editWriteFile(path+".bak", data, st.Mode().Perm()); err != nil {
		return false, err
	}
	if err = editWriteFile(path, out, st.Mode().Perm()); err != nil {
		return false, err
	}
	return true, nil
}
