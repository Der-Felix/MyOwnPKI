//go:build unix

package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// These tests need POSIX modes, owners and links; Windows has no mode to
// check (like the enrollment token file), so they do not build there.

const goodCreds = "api_token: " + sentinel + "\n"

func TestCredentialsFileModes(t *testing.T) {
	t.Parallel()
	for mode, wantOK := range map[os.FileMode]bool{
		0o600: true, 0o400: true,
		0o640: false, 0o644: false, 0o660: false, 0o666: false, 0o604: false, 0o602: false, 0o700: false, 0o500: false, 0o610: false, 0o620: false,
	} {
		path := credsFile(t, goodCreds)
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		c, err := loadDNSCredentials(path, DNSTypeCloudflare)
		switch {
		case wantOK && err != nil:
			t.Errorf("mode %04o refused: %v", mode, err)
		case wantOK:
			c.wipe()
		case err == nil:
			t.Errorf("mode %04o accepted", mode)
		default:
			ce := credsErr(t, err, credWrongMode)
			if want := fmt.Sprintf("is %04o, want 0600 or 0400", mode.Perm()); ce.Detail != want {
				t.Errorf("detail %q, want %q", ce.Detail, want)
			}
			if strings.Contains(err.Error(), "SENTINEL") {
				t.Errorf("a mode error contains the content: %v", err)
			}
		}
	}
}

func TestCredentialsFileModeMessage(t *testing.T) {
	t.Parallel()
	path := credsFile(t, goodCreds)
	chmod(t, path, 0o644)
	_, err := loadDNSCredentials(path, DNSTypeCloudflare)
	ce := credsErr(t, err, credWrongMode)
	if ce.Detail != "is 0644, want 0600 or 0400" || ce.Path != path {
		t.Fatalf("%+v", ce)
	}
	if err.Error() != "credentials file "+path+": wrong mode: is 0644, want 0600 or 0400" {
		t.Fatalf("%v", err)
	}
}

func TestCredentialsFileSpecialBits(t *testing.T) {
	t.Parallel()
	for name, bits := range map[string]os.FileMode{"setuid": os.ModeSetuid, "setgid": os.ModeSetgid, "sticky": os.ModeSticky} {
		path := credsFile(t, goodCreds)
		if err := os.Chmod(path, 0o600|bits); err != nil {
			t.Logf("%s: not testable here: %v", name, err)
			continue
		}
		if fi, err := os.Stat(path); err != nil || fi.Mode()&bits == 0 {
			t.Logf("%s: the bit does not stick on this file system", name)
			continue
		}
		_, err := loadDNSCredentials(path, DNSTypeCloudflare)
		ce := credsErr(t, err, credWrongMode)
		if !strings.Contains(ce.Detail, "setuid, setgid or sticky") {
			t.Errorf("%s: %q", name, ce.Detail)
		}
	}
}

func TestCredentialsFileSymlink(t *testing.T) {
	t.Parallel()
	real := credsFile(t, goodCreds)
	link := filepath.Join(filepath.Dir(real), "link.yaml")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	_, err := loadDNSCredentials(link, DNSTypeCloudflare)
	ce := credsErr(t, err, credSymlink)
	if !strings.Contains(ce.Detail, "does not follow links") {
		t.Fatalf("%q", ce.Detail)
	}
	// A dangling link and a link to a directory are refused the same way.
	dangling := filepath.Join(filepath.Dir(real), "dangling.yaml")
	if err = os.Symlink(filepath.Join(filepath.Dir(real), "absent.yaml"), dangling); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	_, err = loadDNSCredentials(dangling, DNSTypeCloudflare)
	wantCredsState(t, err, credSymlink)
	dirLink := filepath.Join(filepath.Dir(real), "dir.yaml")
	if err = os.Symlink(filepath.Dir(real), dirLink); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	_, err = loadDNSCredentials(dirLink, DNSTypeCloudflare)
	wantCredsState(t, err, credSymlink)
	// A link in the directory part of the path is the admin's choice (the
	// parent directory is what is checked): the real file still loads.
	parentLink := filepath.Join(t.TempDir(), "etc-dns")
	if err = os.Symlink(filepath.Dir(real), parentLink); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if c, err := loadDNSCredentials(filepath.Join(parentLink, filepath.Base(real)), DNSTypeCloudflare); err != nil {
		t.Fatalf("a symlinked directory: %v", err)
	} else {
		c.wipe()
	}
}

func TestCredentialsFileForeignOwner(t *testing.T) {
	t.Parallel()
	path := credsFile(t, goodCreds)
	euid := os.Geteuid()
	foreign := euid + 4242
	env := defaultCredsEnv()

	// Another user owns the file: refused, whoever runs the test.
	env.uidOf = func(os.FileInfo) (int, bool) { return foreign, true }
	_, err := loadDNSCredentialsEnv(path, DNSTypeCloudflare, env)
	ce := credsErr(t, err, credWrongOwner)
	if !strings.Contains(ce.Detail, "want root or the agent's user") || strings.Contains(err.Error(), "SENTINEL") {
		t.Fatalf("%q", ce.Detail)
	}

	// Root owns it while the agent runs as someone else: accepted.
	env = defaultCredsEnv()
	env.uidOf, env.euid = func(os.FileInfo) (int, bool) { return 0, true }, 1234
	if c, lerr := loadDNSCredentialsEnv(path, DNSTypeCloudflare, env); lerr != nil {
		t.Fatalf("a root-owned file: %v", lerr)
	} else {
		c.wipe()
	}
	// The agent's own user owns it: accepted.
	env.uidOf, env.euid = func(os.FileInfo) (int, bool) { return 1234, true }, 1234
	if c, lerr := loadDNSCredentialsEnv(path, DNSTypeCloudflare, env); lerr != nil {
		t.Fatalf("an own file: %v", lerr)
	} else {
		c.wipe()
	}
	// Another user (not root) owns it while the agent is someone else.
	env.uidOf, env.euid = func(os.FileInfo) (int, bool) { return 1000, true }, 1234
	_, err = loadDNSCredentialsEnv(path, DNSTypeCloudflare, env)
	wantCredsState(t, err, credWrongOwner)
	// No owner to read: refused rather than assumed.
	env.uidOf = func(os.FileInfo) (int, bool) { return 0, false }
	_, err = loadDNSCredentialsEnv(path, DNSTypeCloudflare, env)
	ce = credsErr(t, err, credWrongOwner)
	if !strings.Contains(ce.Detail, "cannot be determined") {
		t.Fatalf("%q", ce.Detail)
	}
}

func TestCredentialsParentDirectory(t *testing.T) {
	t.Parallel()
	for mode, wantOK := range map[os.FileMode]bool{
		0o700: true, 0o750: true, 0o755: true, 0o555: true,
		0o770: false, 0o775: false, 0o757: false, 0o777: false, 0o720: false, 0o702: false,
	} {
		path := credsFile(t, goodCreds)
		if err := os.Chmod(filepath.Dir(path), mode); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(filepath.Dir(path), ownerOnly) }) // so TempDir can remove it
		c, err := loadDNSCredentials(path, DNSTypeCloudflare)
		switch {
		case wantOK && err != nil:
			t.Errorf("directory %04o refused: %v", mode, err)
		case wantOK:
			c.wipe()
		case err == nil:
			t.Errorf("directory %04o accepted", mode)
		default:
			ce := credsErr(t, err, credUnsafeDir)
			if !strings.Contains(ce.Detail, "can be written by group or others") {
				t.Errorf("directory %04o: %q", mode, ce.Detail)
			}
		}
	}
}

func TestCredentialsParentDirectoryOwnerAndStat(t *testing.T) {
	t.Parallel()
	path := credsFile(t, goodCreds)
	env := defaultCredsEnv()
	foreignDir := os.Geteuid() + 4242
	// The file is ours; the directory belongs to someone else.
	env.uidOf = func(fi os.FileInfo) (int, bool) {
		if fi.IsDir() {
			return foreignDir, true
		}
		return os.Geteuid(), true
	}
	_, err := loadDNSCredentialsEnv(path, DNSTypeCloudflare, env)
	ce := credsErr(t, err, credUnsafeDir)
	if !strings.Contains(ce.Detail, "owned by uid") {
		t.Fatalf("%q", ce.Detail)
	}
	env = defaultCredsEnv()
	env.statDir = func(string) (os.FileInfo, error) {
		return nil, &os.PathError{Op: "stat", Path: filepath.Dir(path), Err: syscall.EACCES}
	}
	_, err = loadDNSCredentialsEnv(path, DNSTypeCloudflare, env)
	wantCredsState(t, err, credUnsafeDir)
	env.statDir = func(string) (os.FileInfo, error) { return os.Stat(path) } // not a directory
	_, err = loadDNSCredentialsEnv(path, DNSTypeCloudflare, env)
	ce = credsErr(t, err, credUnsafeDir)
	if !strings.Contains(ce.Detail, "is not a directory") {
		t.Fatalf("%q", ce.Detail)
	}
}

func TestCredentialsEnforcementCanBeSwitchedOff(t *testing.T) {
	t.Parallel()
	// What Windows does: no mode, no owner. The content rules still apply.
	path := credsFile(t, goodCreds)
	chmod(t, path, 0o666)
	env := defaultCredsEnv()
	env.enforce = false
	c, err := loadDNSCredentialsEnv(path, DNSTypeCloudflare, env)
	if err != nil {
		t.Fatal(err)
	}
	c.wipe()
	if _, err = loadDNSCredentials(path, DNSTypeCloudflare); err == nil {
		t.Fatal("the default environment must enforce on this platform")
	}
	if !defaultCredsEnv().enforce {
		t.Fatal("enforcement is off on a POSIX platform")
	}
}

func TestCredentialsFileIsNotAPipe(t *testing.T) {
	t.Parallel()
	path := filepath.Join(credsDir(t), "pipe.yaml")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("no named pipes here: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := loadDNSCredentials(path, DNSTypeCloudflare)
		done <- err
	}()
	select {
	case err := <-done:
		wantCredsState(t, err, credNotRegular)
	case <-time.After(10 * time.Second):
		t.Fatal("the load blocked on a named pipe")
	}
}

func TestCredentialsDirectoryIsRefused(t *testing.T) {
	t.Parallel()
	dir := credsDir(t)
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := loadDNSCredentials(filepath.Join(dir, "sub"), DNSTypeCloudflare)
	wantCredsState(t, err, credNotRegular)
}

func TestDNSProviderStatusReportsModeAndOwner(t *testing.T) {
	t.Parallel()
	path := credsFile(t, goodCreds)
	chmod(t, path, 0o640)
	c := &Config{
		DNSProviders: map[string]DNSProvider{"homelab-dns": {Type: DNSTypeCloudflare, CredentialsFile: path}},
		Deployments:  []Deployment{{Name: "wild", Challenge: ChallengeDNS01, DNSProvider: "homelab-dns"}},
	}
	got := c.DNSProviderStatuses()
	if len(got) != 1 || got[0].State != credWrongMode || got[0].Detail != "is 0640, want 0600 or 0400" || got[0].OK() {
		t.Fatalf("%+v", got)
	}
	chmod(t, path, 0o600)
	if got = c.DNSProviderStatuses(); !got[0].OK() {
		t.Fatalf("after the fix: %+v", got)
	}
}

// ownerOnly is the mode that lets the test directory be removed again.
const ownerOnly os.FileMode = 0o700

func chmod(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}
