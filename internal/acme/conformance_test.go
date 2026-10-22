//go:build conformance

package acme

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
	"github.com/Der-Felix/MyOwnPKI/internal/testutil"
)

// Conformance (PHASE2 step 14, owner Q5): real ACME clients against the
// server, with a real DNS server (BIND) and real port 80 – nothing of the
// validator is replaced. test/conformance/run.sh prepares the environment
// (BIND in a container, lego and Pebble built at pinned versions, the
// client images pinned by digest) and runs this test with -tags
// conformance; it needs Linux and Docker, so it runs in its own CI job.
//
// Every test name resolves to CONF_HOST_IP (a wildcard A record in the zone
// homelab.lan); the clients listen on port 80 of that address. The control
// run against Pebble – Let's Encrypt's test server – proves the harness: if
// a client works against Pebble and fails against us, the fault is ours.

type confEnv struct {
	hostIP, dns, tsigName, tsigSecret string
	lego, pebble, pebbleDir, work     string
	certbotImage, acmeshImage         string
	openssl                           string
}

func conformanceEnv(t *testing.T) *confEnv {
	t.Helper()
	e := &confEnv{
		hostIP: os.Getenv("CONF_HOST_IP"), dns: os.Getenv("CONF_DNS"), tsigName: os.Getenv("CONF_TSIG_NAME"), tsigSecret: os.Getenv("CONF_TSIG_SECRET"),
		lego: os.Getenv("LEGO_BIN"), pebble: os.Getenv("PEBBLE_BIN"), pebbleDir: os.Getenv("PEBBLE_DIR"), work: os.Getenv("CONF_WORK"),
		certbotImage: os.Getenv("CONF_CERTBOT_IMAGE"), acmeshImage: os.Getenv("CONF_ACMESH_IMAGE"),
	}
	for name, v := range map[string]string{"CONF_HOST_IP": e.hostIP, "CONF_DNS": e.dns, "CONF_TSIG_NAME": e.tsigName, "CONF_TSIG_SECRET": e.tsigSecret,
		"LEGO_BIN": e.lego, "PEBBLE_BIN": e.pebble, "PEBBLE_DIR": e.pebbleDir, "CONF_WORK": e.work,
		"CONF_CERTBOT_IMAGE": e.certbotImage, "CONF_ACMESH_IMAGE": e.acmeshImage} {
		if v == "" {
			t.Fatalf("%s is not set – run test/conformance/run.sh", name)
		}
	}
	e.openssl = testutil.OpenSSL(t)
	return e
}

// waitForDNS waits until BIND answers for the zone.
func (e *confEnv) waitForDNS(t *testing.T) {
	t.Helper()
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, e.dns)
	}}
	deadline := time.Now().Add(60 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		addrs, err := r.LookupHost(ctx, "probe.homelab.lan")
		cancel()
		if err == nil && len(addrs) > 0 && addrs[0] == e.hostIP {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("BIND at %s does not answer for homelab.lan: %v %v", e.dns, addrs, err)
		}
		time.Sleep(time.Second)
	}
}

// cmd runs a command and returns its output; the output is shown only on
// failure (it never holds the TSIG secret: that is in a file or the
// environment).
func (e *confEnv) cmd(t *testing.T, env []string, name string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	c := exec.CommandContext(ctx, name, args...) // #nosec G204 -- test: the pinned tools of run.sh
	c.Env = append(os.Environ(), env...)
	out, err := c.CombinedOutput()
	return string(out), err
}

func (e *confEnv) must(t *testing.T, env []string, name string, args ...string) {
	t.Helper()
	if out, err := e.cmd(t, env, name, args...); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}

// docker runs a client image on the host network with the work directory
// mounted at /work.
func (e *confEnv) docker(t *testing.T, image string, mounts []string, args ...string) {
	t.Helper()
	full := []string{"run", "--rm", "--network", "host", "-v", e.work + ":/work"}
	for _, m := range mounts {
		full = append(full, "-v", m)
	}
	full = append(full, "-e", "REQUESTS_CA_BUNDLE=/work/proxy-ca.pem", image)
	e.must(t, nil, "docker", append(full, args...)...)
}

// verify checks a PEM chain file: the leaf names the given names and
// OpenSSL verifies it against the root.
func (e *confEnv) verify(t *testing.T, chainFile, rootFile string, names ...string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(chainFile) // #nosec G304 -- the test's work directory
	if err != nil {
		t.Fatal(err)
	}
	b, rest := pem.Decode(data)
	if b == nil {
		t.Fatalf("%s holds no certificate", chainFile)
	}
	leaf, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if leaf.VerifyHostname(n) != nil {
			t.Errorf("%s: the certificate does not cover %s (it names %v %v)", chainFile, n, leaf.DNSNames, leaf.IPAddresses)
		}
	}
	inter := filepath.Join(e.work, "untrusted.pem")
	if werr := os.WriteFile(inter, rest, 0o600); werr != nil { // #nosec G703 -- the test's work directory
		t.Fatal(werr)
	}
	leafFile := filepath.Join(e.work, "leaf.pem")
	if werr := os.WriteFile(leafFile, pem.EncodeToMemory(b), 0o600); werr != nil { // #nosec G703 -- the test's work directory
		t.Fatal(werr)
	}
	out, err := e.cmd(t, nil, e.openssl, "verify", "-purpose", "sslserver", "-CAfile", rootFile, "-untrusted", inter, leafFile)
	if err != nil || !strings.Contains(out, ": OK") {
		t.Errorf("openssl verify %s: %v\n%s", chainFile, err, out)
	}
	return leaf
}

func TestConformance(t *testing.T) {
	e := conformanceEnv(t)
	e.waitForDNS(t)
	inst := testinstance.New(t, testinstance.Options{})
	inst.Unseal(t)
	issuing, open, yes := "issuing", ca.ApprovalOpen, true
	if _, err := inst.Engine.CreateDomain(t.Context(), ca.DomainRequest{Name: "homelab.lan", DomainSettings: ca.DomainSettings{
		CA: &issuing, Approval: &open, Wildcards: &yes,
	}, Who: testinstance.Console}); err != nil {
		t.Fatal(err)
	}
	handler := http.NotFoundHandler()
	proxy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	proxy.StartTLS()
	t.Cleanup(proxy.Close)
	// Nothing replaced: acme.resolver is BIND, the dialer is the real one.
	s, err := New(Options{Engine: inst.Engine, BaseURL: proxy.URL + "/acme", TrustedProxies: "127.0.0.1, ::1", Resolver: e.dns, Clock: inst.Clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	handler = s
	directory := proxy.URL + "/acme/directory"
	proxyCA := filepath.Join(e.work, "proxy-ca.pem")
	if werr := os.WriteFile(proxyCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: proxy.Certificate().Raw}), 0o644); werr != nil { // #nosec G306 -- read by the client containers
		t.Fatal(werr)
	}
	root, err := inst.Engine.CAChain(t.Context(), testinstance.Console, inst.CAIDs["root"])
	if err != nil {
		t.Fatal(err)
	}
	rootFile := filepath.Join(e.work, "root.pem")
	if werr := os.WriteFile(rootFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root[0]}), 0o600); werr != nil {
		t.Fatal(werr)
	}
	legoEnv := []string{"LEGO_CA_CERTIFICATES=" + proxyCA, "LEGO_LOG_FORMAT=text"}
	dnsEnv := []string{"DNSUPDATE_NAMESERVER=" + e.dns, "DNSUPDATE_TSIG_KEY=" + e.tsigName, "DNSUPDATE_TSIG_SECRET=" + e.tsigSecret,
		"DNSUPDATE_TSIG_ALGORITHM=hmac-sha256.", "DNSUPDATE_ZONES=homelab.lan"}
	legoDNSFlags := []string{"--dns", "dnsupdate", "--dns.resolvers", e.dns, "--dns.propagation.wait", "2s"}

	t.Run("control: lego against Pebble", func(t *testing.T) {
		cfg := filepath.Join(e.work, "pebble.json")
		conf := fmt.Sprintf(`{"pebble":{"listenAddress":"127.0.0.1:14000","managementListenAddress":"127.0.0.1:15000",`+
			`"certificate":%q,"privateKey":%q,"httpPort":80,"tlsPort":443,"ocspResponderURL":"","externalAccountBindingRequired":false}}`,
			filepath.Join(e.pebbleDir, "test", "certs", "localhost", "cert.pem"), filepath.Join(e.pebbleDir, "test", "certs", "localhost", "key.pem"))
		if werr := os.WriteFile(cfg, []byte(conf), 0o600); werr != nil {
			t.Fatal(werr)
		}
		ctx, cancel := context.WithCancel(t.Context())
		pebble := exec.CommandContext(ctx, e.pebble, "-config", cfg, "-dnsserver", e.dns) // #nosec G204 -- test: the pinned Pebble of run.sh
		pebble.Env = append(os.Environ(), "PEBBLE_VA_NOSLEEP=1", "PEBBLE_WFE_NONCEREJECT=0")
		var logs strings.Builder
		pebble.Stdout, pebble.Stderr = &logs, &logs
		if serr := pebble.Start(); serr != nil {
			t.Fatal(serr)
		}
		defer func() {
			cancel()
			_ = pebble.Wait()
			if t.Failed() {
				t.Logf("pebble:\n%s", logs.String())
			}
		}()
		time.Sleep(2 * time.Second)
		env := []string{"LEGO_CA_CERTIFICATES=" + filepath.Join(e.pebbleDir, "test", "certs", "pebble.minica.pem"), "LEGO_LOG_FORMAT=text"}
		e.must(t, env, e.lego, "run", "--server", "https://localhost:14000/dir", "--path", filepath.Join(e.work, "lego-pebble"),
			"--email", "admin@homelab.lan", "--accept-tos", "--domains", "pebble.homelab.lan", "--http", "--http.address", ":80", "--no-random-sleep")
	})

	t.Run("lego http-01", func(t *testing.T) {
		path := filepath.Join(e.work, "lego-http")
		e.must(t, legoEnv, e.lego, "run", "--server", directory, "--path", path, "--email", "admin@homelab.lan", "--accept-tos",
			"--domains", "lego-http.homelab.lan", "--http", "--http.address", ":80", "--key-type", "RSA2048", "--no-random-sleep")
		e.verify(t, findFile(t, path, "lego-http.homelab.lan.crt"), rootFile, "lego-http.homelab.lan")
		e.must(t, legoEnv, e.lego, "certificates", "revoke", "--server", directory, "--path", path, "--email", "admin@homelab.lan",
			"--cert.name", "lego-http.homelab.lan", "--reason", "4", "--keep")
	})

	t.Run("lego dns-01 wildcard (RFC 2136)", func(t *testing.T) {
		path := filepath.Join(e.work, "lego-dns")
		e.must(t, append(legoEnv, dnsEnv...), e.lego, append([]string{"run", "--server", directory, "--path", path, "--email", "admin@homelab.lan",
			"--accept-tos", "--domains", "*.lego-dns.homelab.lan", "--domains", "lego-dns.homelab.lan", "--key-type", "EC384", "--no-random-sleep"}, legoDNSFlags...)...)
		e.verify(t, findFile(t, path, "_.lego-dns.homelab.lan.crt"), rootFile, "x.lego-dns.homelab.lan", "lego-dns.homelab.lan")
	})

	certbotDirs := []string{"--config-dir", "/work/certbot/config", "--work-dir", "/work/certbot/work", "--logs-dir", "/work/certbot/logs"}
	certbot := func(t *testing.T, args ...string) {
		t.Helper()
		e.docker(t, e.certbotImage, nil, append(append(args, "--non-interactive", "--server", directory), certbotDirs...)...)
	}
	t.Run("certbot http-01 (standalone)", func(t *testing.T) {
		certbot(t, "register", "--agree-tos", "--email", "admin@homelab.lan")
		certbot(t, "certonly", "--standalone", "-d", "certbot-http.homelab.lan")
		live := filepath.Join(e.work, "certbot", "config", "live", "certbot-http.homelab.lan")
		e.verify(t, filepath.Join(live, "fullchain.pem"), rootFile, "certbot-http.homelab.lan")
		certbot(t, "revoke", "--cert-path", "/work/certbot/config/live/certbot-http.homelab.lan/cert.pem", "--reason", "superseded", "--no-delete-after-revoke")
	})

	t.Run("certbot dns-01 wildcard (certbot-dns-rfc2136 against BIND)", func(t *testing.T) {
		ini := filepath.Join(e.work, "rfc2136.ini")
		host, port, _ := net.SplitHostPort(e.dns)
		creds := fmt.Sprintf("dns_rfc2136_server = %s\ndns_rfc2136_port = %s\ndns_rfc2136_name = %s\ndns_rfc2136_secret = %s\ndns_rfc2136_algorithm = HMAC-SHA256\n",
			host, port, e.tsigName, e.tsigSecret)
		if werr := os.WriteFile(ini, []byte(creds), 0o600); werr != nil {
			t.Fatal(werr)
		}
		certbot(t, "certonly", "--dns-rfc2136", "--dns-rfc2136-credentials", "/work/rfc2136.ini", "--dns-rfc2136-propagation-seconds", "2",
			"-d", "*.certbot-dns.homelab.lan", "--cert-name", "certbot-dns")
		e.verify(t, filepath.Join(e.work, "certbot", "config", "live", "certbot-dns", "fullchain.pem"), rootFile, "x.certbot-dns.homelab.lan")
	})

	t.Run("acme.sh http-01 (standalone)", func(t *testing.T) {
		home := filepath.Join(e.work, "acmesh")
		if merr := os.MkdirAll(home, 0o755); merr != nil { // #nosec G301 -- written by the container
			t.Fatal(merr)
		}
		acmesh := func(args ...string) {
			t.Helper()
			e.docker(t, e.acmeshImage, []string{home + ":/acme.sh"}, append(args, "--server", directory, "--ca-bundle", "/work/proxy-ca.pem")...)
		}
		acmesh("--register-account", "-m", "admin@homelab.lan")
		acmesh("--issue", "--standalone", "-d", "acmesh.homelab.lan", "--keylength", "ec-256")
		e.verify(t, filepath.Join(home, "acmesh.homelab.lan_ecc", "fullchain.cer"), rootFile, "acmesh.homelab.lan")
	})
}

// findFile finds a file by its name below dir (lego's layout differs
// between versions).
func findFile(t *testing.T, dir, name string) string {
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
