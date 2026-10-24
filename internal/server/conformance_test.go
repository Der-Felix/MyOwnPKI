//go:build conformance

package server

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/testutil"
)

// TestConformanceTLS (v0.2.2): real ACME clients – lego and certbot – talk
// directly to the server's own TLS listener (acme.tls_issuer), with the
// root as their only trust anchor; no proxy in between. Runs in the
// conformance CI job (test/conformance/run.sh, -tags conformance) after the
// tests of internal/acme, with the same BIND (every name below homelab.lan
// is CONF_HOST_IP) and port 80 for http-01.
//
// The base URL's host is CONF_HOST_IP: the clients resolve the ACME server
// with the system resolver, which doesn't know homelab.lan. So the
// listener's certificate names an IP address – what the server issues for
// an IP host.
func TestConformanceTLS(t *testing.T) {
	env := map[string]string{}
	for _, name := range []string{"CONF_HOST_IP", "CONF_DNS", "LEGO_BIN", "CONF_WORK", "CONF_CERTBOT_IMAGE"} {
		if env[name] = os.Getenv(name); env[name] == "" {
			t.Fatalf("%s is not set – run test/conformance/run.sh", name)
		}
	}
	openssl := testutil.OpenSSL(t)
	work := filepath.Join(env["CONF_WORK"], "tls")
	if err := os.MkdirAll(work, 0o755); err != nil { // #nosec G301 -- written by the client container
		t.Fatal(err)
	}
	ctx := t.Context()

	cfg := testConfig(t)
	pass := initialized(t, cfg)
	base := "https://" + env["CONF_HOST_IP"] + ":14443/acme"
	cfg.ACME.BaseURL, cfg.ACME.Listen, cfg.ACME.TLSIssuer, cfg.ACME.Resolver = base, ":14443", "issuing", env["CONF_DNS"]
	var logs logBuf
	srv, err := Open(ctx, Options{Config: cfg, Log: slog.New(slog.NewJSONHandler(&logs, nil)), Hostname: "pki01", Version: "conformance"})
	if err != nil {
		t.Fatal(err)
	}
	if lerr := srv.Listen(ctx); lerr != nil {
		t.Fatal(lerr)
	}
	sctx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- srv.Serve(sctx) }()
	defer func() {
		cancel()
		<-done
		if t.Failed() {
			t.Logf("server log:\n%s", logs.String())
		}
	}()
	if uerr := srv.Unseal(ctx, []byte(pass), console); uerr != nil {
		t.Fatal(uerr)
	}
	issuing, open := "issuing", ca.ApprovalOpen
	if _, derr := srv.engine.CreateDomain(ctx, ca.DomainRequest{Name: "homelab.lan", DomainSettings: ca.DomainSettings{CA: &issuing, Approval: &open}, Who: console}); derr != nil {
		t.Fatal(derr)
	}
	rootFile := filepath.Join(work, "root.pem")
	cas, err := ca.ListCAs(ctx, srv.pki.Read)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cas {
		if c.Name == "root" {
			chain, cerr := srv.engine.CAChain(ctx, console, c.ID)
			if cerr != nil {
				t.Fatal(cerr)
			}
			if werr := os.WriteFile(rootFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: chain[0]}), 0o644); werr != nil { // #nosec G306 -- read by the client container
				t.Fatal(werr)
			}
		}
	}
	directory := base + "/directory"

	run := func(t *testing.T, extraEnv []string, name string, args ...string) {
		t.Helper()
		c := exec.CommandContext(ctx, name, args...) // #nosec G204 -- test: the pinned tools of run.sh
		c.Env = append(os.Environ(), extraEnv...)
		if out, rerr := c.CombinedOutput(); rerr != nil {
			t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), rerr, out)
		}
	}
	// verify: the chain file names the host and OpenSSL verifies it with the
	// root alone.
	verify := func(t *testing.T, chainFile, host string) {
		t.Helper()
		data, rerr := os.ReadFile(chainFile) // #nosec G304 -- the test's work directory
		if rerr != nil {
			t.Fatal(rerr)
		}
		b, rest := pem.Decode(data)
		if b == nil {
			t.Fatalf("%s holds no certificate", chainFile)
		}
		leaf, perr := x509.ParseCertificate(b.Bytes)
		if perr != nil {
			t.Fatal(perr)
		}
		if leaf.VerifyHostname(host) != nil {
			t.Errorf("%s does not name %s: %v", chainFile, host, leaf.DNSNames)
		}
		inter, leafFile := filepath.Join(work, "untrusted.pem"), filepath.Join(work, "leaf.pem")
		if werr := os.WriteFile(inter, rest, 0o600); werr != nil { // #nosec G703 -- the test's work directory
			t.Fatal(werr)
		}
		if werr := os.WriteFile(leafFile, pem.EncodeToMemory(b), 0o600); werr != nil { // #nosec G703 -- the test's work directory
			t.Fatal(werr)
		}
		out, verr := exec.CommandContext(ctx, openssl, "verify", "-purpose", "sslserver", "-CAfile", rootFile, "-untrusted", inter, leafFile).CombinedOutput() // #nosec G204 -- test
		if verr != nil || !strings.Contains(string(out), ": OK") {
			t.Errorf("openssl verify %s: %v\n%s", chainFile, verr, out)
		}
	}

	t.Run("the listener's certificate verifies against the root", func(t *testing.T) {
		out, verr := exec.CommandContext(ctx, openssl, "s_client", "-connect", env["CONF_HOST_IP"]+":14443", "-CAfile", rootFile, // #nosec G204 -- test
			"-verify_ip", env["CONF_HOST_IP"], "-verify_return_error").CombinedOutput()
		if verr != nil || !strings.Contains(string(out), "Verify return code: 0 (ok)") {
			t.Fatalf("openssl s_client: %v\n%s", verr, out)
		}
	})

	t.Run("lego http-01, directly over TLS", func(t *testing.T) {
		path := filepath.Join(work, "lego")
		run(t, []string{"LEGO_CA_CERTIFICATES=" + rootFile, "LEGO_LOG_FORMAT=text"}, env["LEGO_BIN"], "run", "--server", directory, "--path", path,
			"--email", "admin@homelab.lan", "--accept-tos", "--domains", "tls-lego.homelab.lan", "--http", "--http.address", ":80", "--no-random-sleep")
		verify(t, find(t, path, "tls-lego.homelab.lan.crt"), "tls-lego.homelab.lan")
	})

	t.Run("certbot http-01 (standalone), directly over TLS", func(t *testing.T) {
		dirs := []string{"--config-dir", "/work/tls/certbot/config", "--work-dir", "/work/tls/certbot/work", "--logs-dir", "/work/tls/certbot/logs"}
		certbot := func(args ...string) {
			full := []string{"run", "--rm", "--network", "host", "-v", env["CONF_WORK"] + ":/work"}
			if uid := os.Getuid(); uid >= 0 {
				full = append(full, "--user", fmt.Sprintf("%d:%d", uid, os.Getgid()))
			}
			full = append(full, "-e", "REQUESTS_CA_BUNDLE=/work/tls/root.pem", env["CONF_CERTBOT_IMAGE"])
			run(t, nil, "docker", append(append(full, args...), append([]string{"--non-interactive", "--server", directory}, dirs...)...)...)
		}
		certbot("register", "--agree-tos", "--email", "admin@homelab.lan")
		certbot("certonly", "--standalone", "-d", "tls-certbot.homelab.lan")
		verify(t, filepath.Join(work, "certbot", "config", "live", "tls-certbot.homelab.lan", "fullchain.pem"), "tls-certbot.homelab.lan")
	})
}

// find finds a file by its name below dir (lego's layout differs between
// versions).
func find(t *testing.T, dir, name string) string {
	t.Helper()
	var found string
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && filepath.Base(p) == name {
			found = p
		}
		return nil
	})
	if found == "" {
		t.Fatalf("no %s below %s", name, dir)
	}
	return found
}
