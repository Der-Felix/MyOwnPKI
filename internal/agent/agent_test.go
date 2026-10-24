package agent

import (
	"crypto/x509"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func yamlPath(p string) string { return `"` + strings.ReplaceAll(p, `\`, `\\`) + `"` }

// TestConfig: the rules of docs/PHASE3.md §1.3 – every path under paths,
// hooks by name with an absolute command, unknown keys refused.
func TestConfig(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	ssl, www := filepath.Join(dir, "ssl"), filepath.Join(dir, "www")
	base := "server: https://pki.homelab.lan:8444\nca_bundle: " + yamlPath(filepath.Join(dir, "root.pem")) +
		"\nhostname: Proxy1.homelab.lan.\nstate_dir: " + yamlPath(filepath.Join(dir, "state")) +
		"\nacme_directory: https://pki.homelab.lan/acme/directory\npaths: [" + yamlPath(ssl) + ", " + yamlPath(www) + "]\n" +
		"hooks:\n  nginx-test: [" + yamlPath(filepath.Join(dir, "nginx")) + ", \"-t\"]\n"
	deployment := func(extra string) string {
		return base + "deployments:\n  - name: proxy\n    profile: nginx\n    names: [proxy1.homelab.lan]\n    challenge: webroot\n    webroot: " +
			yamlPath(www) + "\n    dir: " + yamlPath(filepath.Join(ssl, "proxy")) + "\n    test_hook: nginx-test\n    check: 127.0.0.1:443\n" + extra
	}
	cfg, err := ParseConfig("good", []byte(deployment("")))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Hostname != "proxy1.homelab.lan" || cfg.Enrollment.Challenge != ChallengeStandalone {
		t.Errorf("defaults: %+v", cfg)
	}
	for name, tc := range map[string]struct{ yaml, want string }{
		"unknown key":      {base + "bogus: 1\n", "field bogus not found"},
		"http server":      {strings.Replace(base, "https://pki.homelab.lan:8444", "http://pki.homelab.lan:8444", 1), "server: want https://"},
		"short hostname":   {strings.Replace(base, "Proxy1.homelab.lan.", "proxy1", 1), "hostname: not fully qualified"},
		"bad proxy":        {base + "proxy: socks5://x:1\n", "proxy: want http"},
		"relative hook":    {base + "  bad: [nginx, -t]\n", "hooks: bad: a command line whose first element is an absolute path"},
		"webroot outside":  {base + "enrollment:\n  challenge: webroot\n  webroot: " + yamlPath(filepath.Join(dir, "elsewhere")) + "\n", "not under one of paths"},
		"dotdot in paths":  {strings.Replace(base, yamlPath(www), yamlPath(www+string(filepath.Separator)+".."+string(filepath.Separator)+"x"), 1), "without .."},
		"dir outside":      {strings.Replace(deployment(""), yamlPath(filepath.Join(ssl, "proxy")), yamlPath(filepath.Join(dir, "etc")), 1), "dir: "},
		"unknown hook":     {deployment("    reload_hook: nope\n"), `reload_hook: "nope" is not under hooks`},
		"world-readable":   {deployment("    key_mode: \"0644\"\n"), "key_mode"},
		"bad check":        {strings.Replace(deployment(""), "127.0.0.1:443", "localhost", 1), "check: host:port"},
		"no acme":          {strings.Replace(deployment(""), "acme_directory: https://pki.homelab.lan/acme/directory\n", "", 1), "acme_directory"},
		"file without key": {base + "deployments:\n  - name: x\n    profile: file\n    names: [a.homelab.lan]\n    challenge: standalone\n    files:\n      certificate: " + yamlPath(filepath.Join(ssl, "c.pem")) + "\n", "files: key and certificate"},
		"duplicate name":   {deployment("  - name: proxy\n    profile: nginx\n    names: [a.homelab.lan]\n    challenge: standalone\n    dir: " + yamlPath(ssl) + "\n"), `"proxy" twice`},
	} {
		if _, err := ParseConfig(name, []byte(tc.yaml)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}

// TestWebroot: the token file appears under the webroot (0644 for the web
// server) and goes away; a crashed run's file is cleaned up; and every
// write goes through an os.Root – a challenge directory that leads out of
// the webroot, also one swapped for a symlink after the check, makes the
// write fail and writes nothing outside.
func TestWebroot(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	www := filepath.Join(dir, "www")
	if err := os.MkdirAll(www, 0o750); err != nil {
		t.Fatal(err)
	}
	st := state{dir: filepath.Join(dir, "state")}
	if err := st.ensure(); err != nil {
		t.Fatal(err)
	}
	if err := newResponder(ChallengeWebroot, filepath.Join(dir, "missing"), []string{dir}, st, "", slog.New(slog.DiscardHandler)).place(strings.Repeat("C", 43), "x"); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("missing webroot: %v", err)
	}
	w := newResponder(ChallengeWebroot, www, []string{www}, st, "", slog.New(slog.DiscardHandler))
	token := strings.Repeat("A", 43)
	if err := w.place(token, "content"); err != nil {
		t.Fatal(err)
	}
	challenge := filepath.Join(www, ".well-known", "acme-challenge")
	file := filepath.Join(challenge, token)
	got, rerr := os.ReadFile(file)
	if rerr != nil || string(got) != "content" {
		t.Fatalf("%q %v", got, rerr)
	}
	if fi, _ := os.Stat(file); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o644 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
	if len(st.written()) != 1 {
		t.Errorf("not recorded: %v", st.written())
	}
	w.remove(token)
	if _, err := os.Stat(file); !os.IsNotExist(err) || len(st.written()) != 0 {
		t.Errorf("still there: %v %v", err, st.written())
	}
	if err := w.place("../../etc", "x"); err == nil {
		t.Error("a path as token was accepted")
	}
	// A crash between place and remove: the next start cleans up.
	if err := w.place(token, "content"); err != nil {
		t.Fatal(err)
	}
	st.cleanupWritten()
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Errorf("left behind after a crash: %v", err)
	}
	if left, _ := os.ReadDir(challenge); len(left) != 0 {
		t.Errorf("temporary files left: %v", left)
	}

	outside := filepath.Join(dir, "outside")
	if err := os.MkdirAll(outside, 0o750); err != nil {
		t.Fatal(err)
	}
	empty := func(where string) {
		t.Helper()
		if entries, _ := os.ReadDir(outside); len(entries) != 0 {
			t.Errorf("%s: written outside the webroot: %v", where, entries)
		}
	}
	// The web server's user swaps the checked directory for a symlink to
	// another place: the next write fails.
	if err := os.RemoveAll(challenge); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, challenge); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
	if err := w.place(token, "content"); err == nil || !strings.Contains(err.Error(), "escapes") {
		t.Errorf("written through a symlink that leads out of the webroot: %v", err)
	}
	empty("challenge directory swapped")
	// The same with .well-known.
	if err := os.Remove(challenge); err != nil {
		t.Fatal(err)
	}
	wk := filepath.Join(www, ".well-known")
	if err := os.Remove(wk); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, wk); err != nil {
		t.Fatal(err)
	}
	if err := w.place(token, "content"); err == nil || !strings.Contains(err.Error(), "escapes") {
		t.Errorf("written through .well-known as a symlink out of the webroot: %v", err)
	}
	empty(".well-known swapped")
	// Swapped between the check and the write: the root is open already, the
	// directory turns into a symlink, the write through the root fails.
	if err := os.Remove(wk); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(challenge, 0o750); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(www)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := os.RemoveAll(challenge); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, challenge); err != nil {
		t.Fatal(err)
	}
	if err := rootWrite(root, filepath.Join(challengeDir, token), []byte("x"), 0o644); err == nil || !strings.Contains(err.Error(), "escapes") {
		t.Errorf("written after the swap: %v", err)
	}
	empty("swapped after the check")
	if err := os.RemoveAll(wk); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, wk); err != nil {
		t.Fatal(err)
	}
	// A recorded file outside its webroot is never deleted by the clean-up.
	victim := filepath.Join(outside, "acme-challenge", token)
	if err := os.MkdirAll(filepath.Dir(victim), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := st.addWritten(writtenEntry{Root: www, Token: token}); err != nil {
		t.Fatal(err)
	}
	st.cleanupWritten()
	if _, err := os.Stat(victim); err != nil {
		t.Errorf("the clean-up followed the symlink out of the webroot: %v", err)
	}
	// The webroot itself must lie under paths.
	other := newResponder(ChallengeWebroot, outside, []string{www}, st, "", slog.New(slog.DiscardHandler))
	if err := other.place(token, "x"); err == nil || !strings.Contains(err.Error(), "not under paths") {
		t.Errorf("webroot outside paths: %v", err)
	}
}

// TestStandalone: the listener answers only while a token is placed.
func TestStandalone(t *testing.T) {
	t.Parallel()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	s := newResponder(ChallengeStandalone, "", nil, state{}, addr, slog.New(slog.DiscardHandler))
	token := strings.Repeat("B", 43)
	if perr := s.place(token, "key-authorization"); perr != nil {
		t.Fatal(perr)
	}
	get := func(path string) (int, string, error) {
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+addr+path, nil)
		resp, derr := http.DefaultClient.Do(req)
		if derr != nil {
			return 0, "", derr
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b), nil
	}
	if code, body, gerr := get(challengePath + token); gerr != nil || code != 200 || body != "key-authorization" {
		t.Errorf("placed: %d %q %v", code, body, gerr)
	}
	if code, _, _ := get(challengePath + "other"); code != 404 {
		t.Errorf("other token: %d", code)
	}
	s.remove(token)
	if _, _, gerr := get(challengePath + token); gerr == nil {
		t.Error("the listener is still open after the check")
	}
	// Port in use: a clear hint to webroot.
	busy, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = busy.Close() }()
	b := newResponder(ChallengeStandalone, "", nil, state{}, busy.Addr().String(), slog.New(slog.DiscardHandler))
	if err := b.place(token, "x"); err == nil || !strings.Contains(err.Error(), "use challenge: webroot") {
		t.Errorf("busy port: %v", err)
	}
}

// TestRenewAt: at 2/3, up to 10 % of the lifetime earlier, stable for one
// certificate.
func TestRenewAt(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)
	leaf := &x509.Certificate{NotBefore: start, NotAfter: start.Add(7 * 24 * time.Hour), SerialNumber: big.NewInt(12345)}
	life := 7 * 24 * time.Hour
	if got := RenewAt(leaf, 0); got != start.Add(life*2/3) {
		t.Errorf("r=0: %v", got)
	}
	if got := RenewAt(leaf, 0.999); got.Before(start.Add(life*2/3-life/10)) || !got.Before(start.Add(life*2/3)) {
		t.Errorf("r=0.999: %v", got)
	}
	if a, b := serialFraction(leaf), serialFraction(leaf); a != b || a < 0 || a >= 1 {
		t.Errorf("fraction %v %v", a, b)
	}
	for range 100 {
		if j := jitter(30 * time.Second); j < 25*time.Second || j > 35*time.Second {
			t.Errorf("jitter %v", j)
		}
	}
}
