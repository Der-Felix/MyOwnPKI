package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca/legacy/legacytest"
	"github.com/Der-Felix/MyOwnPKI/internal/config"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/server"
	"github.com/Der-Felix/MyOwnPKI/internal/setup"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
	"github.com/Der-Felix/MyOwnPKI/internal/testutil"
)

// TestPkiShReplaced is the end-to-end test of phase 1 (PHASE1 step 20):
// a PKI made by legacy/pki.sh moves into MyOwnPKI and keeps working.
//
//  1. pki.sh builds a root, an intermediate, two leaves, revokes one, signs a CRL.
//  2. `init --demo`, then `import legacy` (the console commands).
//  3. The server runs; `healthcheck` says ok.
//  4. Through the REST API: sign in, issue a certificate, revoke it.
//  5. The CRL from the URL in the old and in the new certificates: OpenSSL
//     finds both revocations (the legacy one too), accepts the valid leaf.
//  6. `backup` while the server runs, `backup verify`, `restore` into a new
//     data directory, `audit verify` there.
//  7. The restored server serves the same CRL, and `healthcheck` says ok.
func TestPkiShReplaced(t *testing.T) {
	t.Parallel()
	bash, legacyOpenSSL := legacytest.NeedPkiSh(t)
	bin := testutil.OpenSSL(t)
	ctx := t.Context()

	// 1. The pki.sh directory.
	var steps []legacytest.Step
	for _, s := range [][]string{
		{"init", "--org", "Homelab", "--country", "DE", "--cn", "Homelab Root CA", "--key", "rsa3072", "--no-pass",
			"--leaf-key", "rsa2048", "--aia-url", "http://pki.homelab.example", "--intermediate", "server-ca"},
		{"issue", "server", "--cn", "nas.homelab.example", "--dns", "nas.homelab.example", "--ip", "192.0.2.10", "--ca", "server-ca"},
		{"issue", "server", "--cn", "old.homelab.example", "--dns", "old.homelab.example", "--ca", "server-ca"},
		{"revoke", "old.homelab.example", "--reason", "superseded"},
		{"crl"},
	} {
		steps = append(steps, legacytest.Step{Args: s})
	}
	pkiDir, err := legacytest.PkiSh(bash, legacyOpenSSL, t.TempDir(), steps)
	if err != nil {
		t.Fatal(err)
	}

	// 2. init and the import.
	cfgFile, cfg := e2eConfig(t, filepath.Join(t.TempDir(), "data"))
	var out bytes.Buffer
	opt, code := parseInit([]string{"--config", cfgFile, "--demo"}, nil, &out)
	if code >= 0 {
		t.Fatal(out.String())
	}
	if code = finishInit(ctx, opt, setup.NewLineInput(strings.NewReader(""), &out), &out, &out); code != exitOK {
		t.Fatalf("init: %d\n%s", code, out.String())
	}
	demo := readDemoSecrets(t, filepath.Join(cfg.DataDir, "init-demo-secrets.txt"))
	out.Reset()
	uio := userIO{stdin: strings.NewReader(demo.passphrase + "\n"), stdout: &out, stderr: &out}
	if code = runImportLegacy(ctx, []string{pkiDir, "--config", cfgFile}, nil, uio); code != exitOK || !strings.Contains(out.String(), "Imported.") {
		t.Fatalf("import legacy: %d\n%s", code, out.String())
	}

	// 3. The server.
	srv := startServer(t, cfg, demo.passphrase)
	live := cfg
	live.Admin.Listen = srv.AdminAddr()
	if herr := healthcheck(ctx, live, 5*time.Second); herr != nil {
		t.Fatalf("healthcheck: %v", herr)
	}

	// 4. Sign in, issue, revoke.
	api := newAPIClient(t, srv.AdminAddr())
	api.call(t, http.MethodPost, "/auth/login", map[string]string{"username": "demo", "password": demo.password}, http.StatusOK, nil)
	api.call(t, http.MethodPost, "/auth/totp", map[string]string{"code": testinstance.TOTP(demo.secret, time.Now())}, http.StatusOK, nil)
	var cas []struct{ ID, Name, Kind string }
	api.call(t, http.MethodGet, "/cas", nil, http.StatusOK, &cas)
	var rootName, interID string
	for _, c := range cas {
		switch {
		case c.Kind == "root":
			rootName = c.Name
		case c.Name == "server-ca":
			interID = c.ID
		}
	}
	if rootName == "" || interID == "" {
		t.Fatalf("CAs after the import: %+v", cas)
	}
	var issued struct{ ID, Serial string }
	api.call(t, http.MethodPost, "/certificates", map[string]any{
		"ca_id": interID, "preset": "server", "key": map[string]string{"algorithm": "ecdsa-p256"},
		"subject": map[string]string{"common_name": "new.homelab.example"},
		"sans":    map[string][]string{"dns": {"new.homelab.example"}},
	}, http.StatusCreated, &issued)
	api.call(t, http.MethodPost, "/certificates/"+issued.ID+"/revoke", map[string]string{"reason": "keyCompromise"}, http.StatusOK, nil)
	newPEM := api.raw(t, "/certificates/"+issued.ID+"/download/pem")
	var nas struct {
		Items []struct{ ID, Serial string } `json:"items"`
	}
	api.call(t, http.MethodGet, "/certificates?q=nas.homelab.example", nil, http.StatusOK, &nas)
	if len(nas.Items) != 1 {
		t.Fatalf("the imported nas certificate: %+v", nas)
	}
	nasPEM := api.raw(t, "/certificates/"+nas.Items[0].ID+"/download/pem")

	// 5. The CRL, fetched from where the certificates point.
	public := srv.PublicAddr()
	oldCRL := httpGet(t, public+crlPath(t, nasPEM)) // legacy URL of pki.sh
	newCRL := httpGet(t, public+crlPath(t, newPEM)) // MyOwnPKI URL
	if !bytes.Equal(oldCRL, newCRL) {
		t.Error("the legacy CRL URL and the new one serve different CRLs")
	}
	crl, err := x509.ParseRevocationList(newCRL)
	if err != nil {
		t.Fatal(err)
	}
	reasons := map[string]int{}
	for _, e := range crl.RevokedCertificateEntries {
		reasons[strings.ToUpper(e.SerialNumber.Text(16))] = e.ReasonCode
	}
	if reasons[strings.TrimLeft(issued.Serial, "0")] != x509KeyCompromise || len(reasons) != 2 {
		t.Errorf("CRL entries %v, want the new serial %s (keyCompromise) and the legacy one", reasons, issued.Serial)
	}
	if crl.Number.Cmp(big.NewInt(1)) <= 0 {
		t.Errorf("CRL number %v: must continue after the pki.sh numbers", crl.Number)
	}
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if werr := os.WriteFile(p, data, 0o600); werr != nil {
			t.Fatal(werr)
		}
		return p
	}
	root := write("root.pem", derToPEM(httpGet(t, public+"/ca/"+rootName+"/1.crt")))
	inter := write("inter.pem", derToPEM(httpGet(t, public+"/ca/server-ca/1.crt")))
	crlFile := write("crl.der", newCRL)
	crlPEM := write("crl.pem", pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: newCRL}))
	verify := func(leaf []byte) (string, error) {
		// #nosec G204 -- test: the openssl binary and temp files
		b, verr := exec.CommandContext(ctx, bin, "verify", "-crl_check", "-CAfile", root, "-untrusted", inter,
			"-CRLfile", crlPEM, write("leaf.pem", leaf)).CombinedOutput()
		return string(b), verr
	}
	if got, verr := verify(nasPEM); verr != nil || !strings.Contains(got, ": OK") {
		t.Errorf("openssl verify of the valid imported certificate: %v\n%s", verr, got)
	}
	if got, verr := verify(newPEM); verr == nil || !strings.Contains(got, "certificate revoked") {
		t.Errorf("openssl verify of the revoked certificate: %v\n%s", verr, got)
	}
	// #nosec G204 -- test: the openssl binary and a temp file
	text, err := exec.CommandContext(ctx, bin, "crl", "-inform", "DER", "-in", crlFile, "-noout", "-text").CombinedOutput()
	if err != nil || !strings.Contains(string(text), "Key Compromise") || !strings.Contains(string(text), "Superseded") {
		t.Errorf("openssl crl -text: %v\n%s", err, text)
	}

	// 6. Backup while the server runs, verify, restore.
	backupDir := filepath.Join(t.TempDir(), "backup")
	out.Reset()
	if code = runBackup(ctx, []string{backupDir, "--config", cfgFile}, &out, &out); code != exitOK {
		t.Fatalf("backup: %d\n%s", code, out.String())
	}
	srv.stop(t)
	out.Reset()
	if code = runBackup(ctx, []string{"verify", backupDir}, &out, &out); code != exitOK {
		t.Fatalf("backup verify: %d\n%s", code, out.String())
	}
	cfgFile2, cfg2 := e2eConfig(t, filepath.Join(t.TempDir(), "restored"))
	out.Reset()
	if code = runRestore(ctx, []string{backupDir, "--config", cfgFile2}, &out, &out); code != exitOK {
		t.Fatalf("restore: %d\n%s", code, out.String())
	}
	out.Reset()
	if code = runAudit(ctx, []string{"verify", "--config", cfgFile2}, &out, &out); code != exitOK {
		t.Fatalf("audit verify after the restore: %d\n%s", code, out.String())
	}

	// 7. The restored server: sealed, it still serves the same CRL.
	srv2 := startServer(t, cfg2, "")
	if got := httpGet(t, srv2.PublicAddr()+crlPath(t, newPEM)); !bytes.Equal(got, newCRL) {
		t.Error("the restored server serves another CRL")
	}
	live2 := cfg2
	live2.Admin.Listen = srv2.AdminAddr()
	if herr := healthcheck(ctx, live2, 5*time.Second); herr != nil {
		t.Errorf("healthcheck after the restore: %v", herr)
	}
	// A foreign certificate in the place of the served one: unhealthy.
	other := live2
	other.Admin.TLSCertFile = filepath.Join(cfg.DataDir, "tls", "admin-bootstrap.crt")
	if herr := healthcheck(ctx, other, 5*time.Second); herr == nil || !strings.Contains(herr.Error(), "another certificate") {
		t.Errorf("healthcheck against another certificate: %v", herr)
	}
}

const x509KeyCompromise = 1 // RFC 5280 §5.3.1

func e2eConfig(t *testing.T, dataDir string) (string, config.Config) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "config.yaml")
	content := "data_dir: \"" + strings.ReplaceAll(dataDir, `\`, `\\`) + "\"\n" +
		"admin:\n  listen: \"127.0.0.1:9443\"\npublic:\n  listen: \"127.0.0.1:8080\"\nlog:\n  format: text\n"
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := config.Load(file, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The console commands only read the file; the test server takes free ports.
	cfg.Admin.Listen, cfg.Public.Listen = "127.0.0.1:0", "127.0.0.1:0"
	return file, cfg
}

type demoSecrets struct{ passphrase, password, secret string }

func readDemoSecrets(t *testing.T, path string) demoSecrets {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- test file
	if err != nil {
		t.Fatal(err)
	}
	var d demoSecrets
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if v, ok := strings.CutPrefix(line, "unseal passphrase: "); ok {
			d.passphrase = v
		}
		if v, ok := strings.CutPrefix(line, "admin password: "); ok {
			d.password = v
		}
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "secret:"); ok {
			d.secret = strings.TrimSpace(v)
		}
	}
	if d.passphrase == "" || d.password == "" || d.secret == "" {
		t.Fatal("the demo secrets file lacks a value")
	}
	return d
}

type runningServer struct {
	*server.Server
	cancel context.CancelFunc
	done   chan error
}

// startServer opens, listens, serves and – with a passphrase – unseals.
// The cleanup stops it before the temp directories go (Windows locks open
// files).
func startServer(t *testing.T, cfg config.Config, passphrase string) *runningServer {
	t.Helper()
	srv, err := server.Open(t.Context(), server.Options{Config: cfg, Log: slog.New(slog.DiscardHandler), Hostname: "pki01", Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if lerr := srv.Listen(t.Context()); lerr != nil {
		t.Fatal(lerr)
	}
	ctx, cancel := context.WithCancel(context.WithoutCancel(t.Context()))
	rs := &runningServer{Server: srv, cancel: cancel, done: make(chan error, 1)}
	go func() { rs.done <- srv.Serve(ctx) }()
	t.Cleanup(func() { rs.stop(t) })
	if passphrase != "" {
		who := keys.Who{Actor: consoleWho().Actor, Principal: authz.Console()}
		if uerr := srv.Unseal(t.Context(), []byte(passphrase), who); uerr != nil {
			t.Fatal(uerr)
		}
	}
	return rs
}

func (rs *runningServer) stop(t *testing.T) {
	t.Helper()
	if rs.done == nil {
		return
	}
	rs.cancel()
	if err := <-rs.done; err != nil {
		t.Errorf("server stop: %v", err)
	}
	rs.done = nil
}

// apiClient talks to the REST API like a browser would: cookies, the CSRF
// token of the last answer. The bootstrap certificate is accepted as is –
// healthcheck tests the pinning.
type apiClient struct {
	base string
	http *http.Client
	csrf string
}

func newAPIClient(t *testing.T, addr string) *apiClient {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &apiClient{base: "https://" + addr + "/api/v1", http: &http.Client{Jar: jar, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- test client of the local bootstrap certificate
	}}}
}

func (c *apiClient) do(t *testing.T, method, path string, body any) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, c.base+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var tok struct {
		CSRF string `json:"csrf_token"`
	}
	if json.Unmarshal(data, &tok) == nil && tok.CSRF != "" {
		c.csrf = tok.CSRF
	}
	return resp.StatusCode, data
}

func (c *apiClient) call(t *testing.T, method, path string, body any, want int, into any) {
	t.Helper()
	code, data := c.do(t, method, path, body)
	if code != want {
		t.Fatalf("%s %s: %d, want %d\n%s", method, path, code, want, data)
	}
	if into != nil {
		if err := json.Unmarshal(data, into); err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
	}
}

func (c *apiClient) raw(t *testing.T, path string) []byte {
	t.Helper()
	code, data := c.do(t, http.MethodGet, path, nil)
	if code != http.StatusOK {
		t.Fatalf("GET %s: %d\n%s", path, code, data)
	}
	return data
}

func httpGet(t *testing.T, u string) []byte {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %d %v", u, resp.StatusCode, err)
	}
	return data
}

// crlPath is the path of the certificate's CRL distribution point.
func crlPath(t *testing.T, certPEM []byte) string {
	t.Helper()
	b, _ := pem.Decode(certPEM)
	if b == nil {
		t.Fatal("no PEM certificate")
	}
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.CRLDistributionPoints) != 1 {
		t.Fatalf("%s: CRL distribution points %v", cert.Subject, cert.CRLDistributionPoints)
	}
	u, err := url.Parse(cert.CRLDistributionPoints[0])
	if err != nil {
		t.Fatal(err)
	}
	return u.Path
}

func derToPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
