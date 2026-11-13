//go:build unix

package trustkit

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The stubs stand in for the programs that need the network or root. curl
// copies $FAKE_ROOT to the file of -o inside the current directory and logs
// where it ran; sudo logs its command line and does nothing; openssl creates
// the file of -out. The check (sha256sum or shasum) is the real one.
const (
	stubCurl = `#!/bin/sh
out=
while [ $# -gt 0 ]; do
  if [ "$1" = "-o" ]; then out=$2; fi
  shift
done
pwd -P > "$LOGDIR/curl-cwd"
cp "$FAKE_ROOT" "$out"
`
	stubSudo = `#!/bin/sh
echo "$*" >> "$LOGDIR/sudo.log"
`
	stubOpenSSL = `#!/bin/sh
out=
while [ $# -gt 0 ]; do
  if [ "$1" = "-out" ]; then out=$2; fi
  shift
done
: > "$out"
`
)

// TestGuideChainRunsInAPrivateDirectoryAndStopsOnAFailedCheck runs the pasted
// chains with stubs: the download lands in a new directory that only the user
// can enter (not in the directory the shell was in, where a planted root.crt
// link is not followed), and a download that fails the SHA-256 check stops the
// chain before the first sudo.
func TestGuideChainRunsInAPrivateDirectoryAndStopsOnAFailedCheck(t *testing.T) {
	t.Parallel()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not on the PATH")
	}
	r := fixtureRoot(t)
	for _, tc := range []struct {
		platform Platform
		check    string
	}{{Debian, "sha256sum"}, {Fedora, "sha256sum"}, {Java, "sha256sum"}, {MacOS, "shasum"}} {
		if _, lerr := exec.LookPath(tc.check); lerr != nil {
			continue
		}
		for _, tampered := range []bool{false, true} {
			name := string(tc.platform) + "/genuine"
			if tampered {
				name = string(tc.platform) + "/tampered"
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				base := t.TempDir()
				bin, logs, shared := filepath.Join(base, "bin"), filepath.Join(base, "log"), filepath.Join(base, "shared")
				for _, d := range []string{bin, logs, shared} {
					if merr := os.Mkdir(d, 0o700); merr != nil {
						t.Fatal(merr)
					}
				}
				for stub, body := range map[string]string{"curl": stubCurl, "sudo": stubSudo, "openssl": stubOpenSSL} {
					// #nosec G306 -- a test stub that has to be executable.
					if werr := os.WriteFile(filepath.Join(bin, stub), []byte(body), 0o700); werr != nil {
						t.Fatal(werr)
					}
				}
				served := r.DER
				if tampered {
					served = append([]byte("not the root: "), r.DER...)
				}
				fake := filepath.Join(base, "served.der")
				victim := filepath.Join(base, "victim")
				for f, b := range map[string][]byte{fake: served, victim: []byte("untouched")} {
					if werr := os.WriteFile(f, b, 0o600); werr != nil {
						t.Fatal(werr)
					}
				}
				// What a local attacker does in a shared directory: plant root.crt as a link.
				if lerr := os.Symlink(victim, filepath.Join(shared, "root.crt")); lerr != nil {
					t.Fatal(lerr)
				}
				script := commandText(Guide(tc.platform, r))
				cmd := exec.CommandContext(t.Context(), bash, "-c", script)
				cmd.Dir = shared
				cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "FAKE_ROOT="+fake, "LOGDIR="+logs)
				out, runErr := cmd.CombinedOutput()

				if got, _ := os.ReadFile(victim); string(got) != "untouched" {
					t.Errorf("curl wrote through the planted link: %q", got)
				}
				cwd, _ := os.ReadFile(filepath.Join(logs, "curl-cwd"))
				dir := strings.TrimSpace(string(cwd))
				realShared, _ := filepath.EvalSymlinks(shared)
				if dir == "" || dir == realShared {
					t.Fatalf("curl ran in %q, not in a new directory (shared: %s)", dir, realShared)
				}
				// #nosec G703 -- the directory that mktemp -d made and the stub curl reported, in this test only.
				if st, serr := os.Stat(dir); serr != nil || st.Mode().Perm()&0o077 != 0 {
					t.Errorf("the working directory %s is not private: %v %v", dir, st, serr)
				}
				sudoLog, _ := os.ReadFile(filepath.Join(logs, "sudo.log"))
				if tampered {
					if runErr == nil {
						t.Errorf("a download that fails the check ended with success:\n%s", out)
					}
					if len(sudoLog) != 0 {
						t.Errorf("sudo ran after a failed check:\n%s", sudoLog)
					}
					return
				}
				if runErr != nil {
					t.Fatalf("the chain failed: %v\n%s", runErr, out)
				}
				if len(sudoLog) == 0 {
					t.Error("a genuine download was not installed")
				}
			})
		}
	}
}
