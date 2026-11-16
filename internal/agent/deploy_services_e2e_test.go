package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/recipe"
)

// Shared parts of the real-service tests for the Apache and HAProxy recipes
// (docs/PHASE3.md section 17, step 69). Like TestNginxDeployProfiles, each test
// starts the service itself with its own configuration, pid and port, never
// touching an installed system service. Unlike nginx, these tests run only
// when the switch of the service is set (MYOWNPKI_E2E_APACHE=1,
// MYOWNPKI_E2E_HAPROXY=1): the GitHub runner images ship apache2, and the
// other jobs must not start a web server by accident. With the switch set a
// missing binary is a failure, never a skip.
const (
	envE2EApache  = "MYOWNPKI_E2E_APACHE"
	envE2EHAProxy = "MYOWNPKI_E2E_HAPROXY"
)

// requireRealService skips unless the switch env is set. It then insists that
// every named path exists and that every absolute hook command of the recipe
// exists on this machine: a recipe that names /usr/sbin/apache2ctl on a
// layout that has no such file is a defect of the recipe.
func requireRealService(t *testing.T, label, env, recipeName string, paths ...string) recipe.Recipe {
	t.Helper()
	if os.Getenv(env) != "1" {
		t.Skipf("%s=1 is not set: this test starts the real %s of the distribution; CI runs it in the job \"agent end-to-end (Apache, HAProxy)\", locally install the package and run scripts/ci/agent-e2e-%s.sh", env, label, label)
	}
	rec, ok := recipe.Get(recipeName)
	if !ok {
		t.Fatalf("recipe %q does not exist", recipeName)
	}
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("%s is set but %s is missing: %v", env, path, err)
		}
	}
	for _, hook := range rec.Hooks {
		if _, err := os.Stat(hook.Command[0]); err != nil {
			t.Fatalf("recipe %q: hook %q runs %s, which does not exist on this machine (Debian and Ubuntu layout expected): %v – correct the path in internal/recipe/recipe.go", recipeName, hook.Name, hook.Command[0], err)
		}
	}
	return rec
}

func recipeHook(t *testing.T, rec recipe.Recipe, name string) []string {
	t.Helper()
	for _, hook := range rec.Hooks {
		if hook.Name == name {
			return slices.Clone(hook.Command)
		}
	}
	t.Fatalf("recipe %q has no hook %q", rec.Name, name)
	return nil
}

// newServiceRig is the deployment rig with the profile and the file layout
// the recipe prescribes: a directory with fullchain.pem and privkey.pem, or
// the one combined file.
func newServiceRig(t *testing.T, rec recipe.Recipe) *deployRig {
	t.Helper()
	profile := rec.Profile
	if rec.Combined != "" {
		profile = rigCombined
	}
	return newDeployRig(t, profile)
}

func freeLoopbackAddress(t *testing.T) string {
	t.Helper()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

// realService is a service process started by a test, stopped in t.Cleanup.
type realService struct {
	name   string
	cmd    *exec.Cmd
	exited chan struct{}
	err    error // the result of Wait, valid after exited is closed
}

// startRealService starts argv in the foreground with its output in
// dir/<name>.out. logs are further files of the service whose end is printed
// when the test fails (they hold messages and paths, never key material).
func startRealService(t *testing.T, name, dir string, argv []string, logs ...string) *realService {
	t.Helper()
	outPath := filepath.Join(dir, name+".out")
	output, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304 -- test-owned directory
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), argv[0], argv[1:]...) // #nosec G204 G702 -- test-only service executable and private config
	cmd.Stdout, cmd.Stderr = output, output
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 10 * time.Second
	if err := cmd.Start(); err != nil {
		_ = output.Close()
		t.Fatalf("start %s: %v", name, err)
	}
	s := &realService{name: name, cmd: cmd, exited: make(chan struct{})}
	go func() {
		s.err = cmd.Wait()
		close(s.exited)
	}()
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		timer := time.NewTimer(10 * time.Second)
		defer timer.Stop()
		select {
		case <-s.exited:
		case <-timer.C:
			_ = cmd.Process.Kill()
			<-s.exited
		}
		_ = output.Close()
		t.Logf("%s stopped: %v", name, s.err)
		if t.Failed() {
			for _, path := range append([]string{outPath}, logs...) {
				t.Logf("end of %s:\n%s", path, tailOfFile(path, 4096))
			}
		}
	})
	return s
}

func tailOfFile(path string, limit int) string {
	data, err := os.ReadFile(path) // #nosec G304 -- test-owned log file
	if err != nil {
		return "(unreadable: " + err.Error() + ")"
	}
	if len(data) > limit {
		data = data[len(data)-limit:]
	}
	return string(data)
}

// waitListening polls with a deadline until addr accepts a connection.
func (s *realService) waitListening(t *testing.T, addr string) {
	t.Helper()
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-s.exited:
			t.Fatalf("%s exited before it listened on %s: %v", s.name, addr, s.err)
		case <-deadline.C:
			t.Fatalf("%s did not listen on %s within 15s", s.name, addr)
		case <-ticker.C:
			conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(t.Context(), "tcp", addr)
			if err == nil {
				_ = conn.Close()
				return
			}
		}
	}
}

// reloadWrapper is a reload hook that appends one line to marker before it
// runs command, so a test can count the reloads the agent really issued.
func reloadWrapper(marker string, command ...string) []string {
	return append([]string{"/bin/sh", "-c", `echo reload >>"$1"; shift; exec "$@"`, "sh", marker}, command...)
}

func reloadCount(t *testing.T, marker string) int {
	t.Helper()
	data, err := os.ReadFile(marker) // #nosec G304 -- test-owned marker file
	if errors.Is(err, os.ErrNotExist) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Count(data, []byte("\n"))
}

// servedLeaf connects to addr with the given SNI and returns the leaf the
// service sends. It trusts nothing: the caller compares the leaf.
func servedLeaf(ctx context.Context, addr, sni string) (*x509.Certificate, error) {
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 3 * time.Second}, Config: &tls.Config{
		MinVersion: tls.VersionTLS12, ServerName: sni,
		InsecureSkipVerify: true, // #nosec G402 -- reads the certificate a test service sends; the caller compares it
	}}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, errors.New("not a TLS connection")
	}
	peers := tlsConn.ConnectionState().PeerCertificates
	if len(peers) == 0 {
		return nil, errors.New("the service sent no certificate")
	}
	return peers[0], nil
}

// opensslLeaf reads the leaf with openssl s_client, a TLS client that shares
// no code with Go.
func opensslLeaf(ctx context.Context, openssl, addr, sni string) (*x509.Certificate, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, openssl, "s_client", "-connect", addr, "-servername", sni) // #nosec G204 -- fixed argv, loopback address of a test service
	cmd.Stdin = strings.NewReader("")
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("openssl s_client: %w", err)
	}
	for rest := out; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, errors.New("openssl s_client printed no certificate")
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
	}
}

// assertServes compares the certificate the service serves with the deployed
// one, by fingerprint and serial: with Go's TLS and, when openssl is
// installed, with openssl s_client.
func assertServes(t *testing.T, addr, sni string, want *x509.Certificate) {
	t.Helper()
	got, err := servedLeaf(t.Context(), addr, sni)
	if err != nil {
		t.Fatalf("read the served certificate: %v", err)
	}
	if fingerprint(got.Raw) != fingerprint(want.Raw) || got.SerialNumber.Cmp(want.SerialNumber) != 0 {
		t.Fatalf("the service serves serial %s (%s), want serial %s (%s)", got.SerialNumber, fingerprint(got.Raw), want.SerialNumber, fingerprint(want.Raw))
	}
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Log("openssl is not installed; the served certificate was read with Go TLS only")
		return
	}
	got, err = opensslLeaf(t.Context(), openssl, addr, sni)
	if err != nil {
		t.Fatalf("read the served certificate with openssl: %v", err)
	}
	if fingerprint(got.Raw) != fingerprint(want.Raw) {
		t.Fatalf("openssl s_client sees %s, want %s", fingerprint(got.Raw), fingerprint(want.Raw))
	}
}

// corruptStaged leaves the certificate of newer together with key in the files
// the staged deployment wrote: a certificate/key mismatch on disk, as if the
// key file had been damaged after the agent's own pair check.
func corruptStaged(t *testing.T, r *deployRig, d Deployment, newer *Material, key []byte) {
	t.Helper()
	files := deploymentPaths(d)
	target := targetFile{path: files.KeyPath(), data: key, mode: 0o600, uid: -1, gid: -1}
	if files.Combined != "" {
		target.data = combinedPEM(&Material{Certificate: newer.Certificate, Fullchain: newer.Fullchain, Key: key})
	}
	if err := r.a.atomicTarget(target); err != nil {
		t.Fatal(err)
	}
}

// oneLine shortens the output of a command for a log line.
func oneLine(s string) string {
	s = strings.Join(strings.Fields(strings.ReplaceAll(s, "\n", " | ")), " ")
	if len(s) > 500 {
		s = s[:500] + "..."
	}
	return s
}

// noteClaim ties an observation of a real service to the notes of the recipe.
// The notes say either nothing definite (still "to verify", or silent), or
// what the observation showed. A note that says the opposite of what was
// observed fails the test and names the text to write instead. A note that
// has not caught up yet is reported as a NOTES-UPDATE line: the CI script
// turns it into a warning annotation.
type noteClaim struct {
	recipe  string
	topic   string
	result  string // what was observed, for the message
	seen    bool
	ifSeen  string // the sentence the notes carry when seen is true
	ifNot   string // the sentence the notes carry when seen is false
	pending string // the wording of the "to be verified" note, if the notes still have it
}

// noteVerdict says how the notes stand against the observation.
type noteVerdict int

const (
	noteAgrees noteVerdict = iota
	noteContradicts
	noteBehind // says nothing definite yet: report, do not fail
)

// verdict compares the observation with the text of the notes. message is
// what to write in the notes (for noteContradicts and noteBehind).
func (c noteClaim) verdict(notes []string) (noteVerdict, string) {
	text := strings.Join(notes, "\n")
	want, other := c.ifSeen, c.ifNot
	if !c.seen {
		want, other = c.ifNot, c.ifSeen
	}
	switch {
	case strings.Contains(text, other):
		return noteContradicts, fmt.Sprintf("the notes of recipe %q contradict the real service (%s): observed %s. In internal/recipe/recipe.go (and site/recipes.md) replace the sentence containing %q by one that says: %s", c.recipe, c.topic, c.result, other, want)
	case strings.Contains(text, want):
		return noteAgrees, ""
	}
	hint := "the notes say nothing definite on this"
	if c.pending != "" && strings.Contains(text, c.pending) {
		hint = fmt.Sprintf("the notes still say %q", c.pending)
	}
	return noteBehind, fmt.Sprintf("NOTES-UPDATE recipe %q, %s: observed %s; %s. Write in internal/recipe/recipe.go and site/recipes.md: %s", c.recipe, c.topic, c.result, hint, want)
}

func (c noteClaim) check(t *testing.T) {
	t.Helper()
	rec, ok := recipe.Get(c.recipe)
	if !ok {
		t.Fatalf("recipe %q does not exist", c.recipe)
	}
	t.Logf("OBSERVED %s: %s", c.topic, c.result)
	switch verdict, message := c.verdict(rec.Notes); verdict {
	case noteContradicts:
		t.Error(message)
	case noteAgrees:
		t.Logf("the notes of recipe %q agree with the observation (%s)", c.recipe, c.topic)
	case noteBehind:
		fallthrough
	default:
		t.Log(message)
	}
}
