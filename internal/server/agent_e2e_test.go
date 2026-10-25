package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/agent"
	"github.com/Der-Felix/MyOwnPKI/internal/auth"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

// newTestAgent writes an agent.yaml in webroot mode and returns the agent,
// connected to the test server's agent listener.
func (e *agentEnv) newTestAgent(t *testing.T, configure ...func(*agent.Config)) (*agent.Agent, string) {
	t.Helper()
	dir := t.TempDir()
	www := filepath.Join(dir, "www")
	if err := os.MkdirAll(www, 0o750); err != nil { // the web server's directory exists before the agent
		t.Fatal(err)
	}
	e.webroot = www
	bundle := filepath.Join(dir, "root.pem")
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.rootDER})
	if err := os.WriteFile(bundle, pemData, 0o600); err != nil {
		t.Fatal(err)
	}
	q := func(p string) string { return `"` + strings.ReplaceAll(p, `\`, `\\`) + `"` }
	cfg, err := agent.ParseConfig("agent.yaml", []byte("server: https://pki.homelab.lan:8444\nca_bundle: "+q(bundle)+
		"\nhostname: proxy1.homelab.lan\nstate_dir: "+q(filepath.Join(dir, "state"))+
		"\nacme_directory: https://pki.homelab.lan/acme/directory"+
		"\nenrollment:\n  challenge: webroot\n  webroot: "+q(www)+"\npaths: ["+q(www)+"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, fn := range configure {
		fn(cfg)
	}
	if validateErr := cfg.Validate(); validateErr != nil {
		t.Fatal(validateErr)
	}
	a, err := agent.New(cfg, slog.New(slog.DiscardHandler), "0.3.0-test")
	if err != nil {
		t.Fatal(err)
	}
	var d net.Dialer
	a.SetDial(func(ctx context.Context, network, _ string) (net.Conn, error) {
		return d.DialContext(ctx, network, e.srv.AgentAddr())
	})
	a.SetACMEDial(func(ctx context.Context, network, _ string) (net.Conn, error) {
		return d.DialContext(ctx, network, e.srv.ACMEAddr())
	})
	return a, www
}

// TestAgentEndToEnd (blocks B): the real agent against the real server, in
// webroot mode – enroll with a join token (verified), the check file is gone
// afterwards; the service renews the agent certificate at 2/3 with a new
// key; after the certificate expired it enrolls again with the key of the
// last one and stays the same agent.
func TestAgentEndToEnd(t *testing.T) {
	t.Parallel()
	e := newAgentEnv(t)
	ctx := t.Context()
	a, www := e.newTestAgent(t)
	token, _, err := e.srv.Agents().CreateJoinToken(ctx, console, "proxy1", []string{"proxy1.homelab.lan"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	res, err := a.Enroll(ctx, token)
	if err != nil || !res.Admitted() {
		t.Fatalf("enroll: %+v %v", res, err)
	}
	id := res.AgentID
	if left, _ := filepath.Glob(filepath.Join(www, ".well-known", "acme-challenge", "*")); len(left) != 0 {
		t.Errorf("check files left in the webroot: %v", left)
	}
	if _, err := a.Enroll(ctx, ""); err == nil || !strings.Contains(err.Error(), "enrolled") {
		t.Errorf("enroll twice: %v", err)
	}
	first := a.Identity().Leaf

	// Renewal: the clock at 6 of 7 days; Run renews, then sleeps – the
	// the first wait after rotation ends the test run.
	runOnce(t, a, func() time.Time {
		if a.Identity().Leaf.SerialNumber.Cmp(first.SerialNumber) == 0 {
			return first.NotBefore.Add(6 * 24 * time.Hour)
		}
		return time.Now().UTC()
	})
	second := a.Identity().Leaf
	if second.SerialNumber.Cmp(first.SerialNumber) == 0 || string(second.RawSubjectPublicKeyInfo) == string(first.RawSubjectPublicKeyInfo) {
		t.Fatal("not renewed with a new key")
	}
	if c, err := e.srv.Agents().Identify(ctx, second, ""); err != nil || c.Agent.ID != id {
		t.Fatalf("the renewed certificate: %v", err)
	}

	// Expired: Run enrolls again with the key of the last certificate –
	// no token, a passed check – and it is the same agent.
	runOnce(t, a, func() time.Time {
		if a.Identity().Leaf.SerialNumber.Cmp(second.SerialNumber) == 0 {
			return second.NotAfter.Add(time.Hour)
		}
		return time.Now().UTC()
	})
	third := a.Identity().Leaf
	if third.SerialNumber.Cmp(second.SerialNumber) == 0 || string(third.RawSubjectPublicKeyInfo) != string(second.RawSubjectPublicKeyInfo) {
		t.Fatal("not enrolled again with the last key")
	}
	if c, err := e.srv.Agents().Identify(ctx, third, ""); err != nil || c.Agent.ID != id {
		t.Fatalf("enrolled again as another agent: %v", err)
	}
	if list, _ := e.srv.Agents().ListAgents(ctx, console); len(list) != 1 {
		t.Errorf("%d agents, want 1", len(list))
	}
}

// runOnce waits for the identity change. Concurrent report/watch/schedule
// waits must not cancel the run before certificate maintenance completes.
func runOnce(t *testing.T, a *agent.Agent, now func() time.Time) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	var slept atomic.Bool
	before := a.Identity().Leaf.SerialNumber
	a.Now = now
	a.Sleep = func(ctx context.Context, _ time.Duration) error {
		slept.Store(true)
		if a.Identity().Leaf.SerialNumber.Cmp(before) != 0 {
			cancel()
		}
		<-ctx.Done()
		return ctx.Err()
	}
	if err := a.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if !slept.Load() {
		t.Fatal("Run ended without sleeping")
	}
}

type demoAccess struct {
	user, password, secret string
}

func readDemoAccess(t *testing.T, dataDir string) demoAccess {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dataDir, "init-demo-secrets.txt")) // #nosec G304 -- test fixture of this instance
	if err != nil {
		t.Fatal(err)
	}
	var out demoAccess
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case strings.HasPrefix(line, "admin user: "):
			out.user = strings.TrimPrefix(line, "admin user: ")
		case strings.HasPrefix(line, "admin password: "):
			out.password = strings.TrimPrefix(line, "admin password: ")
		case strings.HasPrefix(line, "secret:"):
			out.secret = strings.TrimPrefix(line, "secret:")
		}
	}
	if out.user == "" || out.password == "" || out.secret == "" {
		t.Fatal("incomplete demo access fixture")
	}
	return out
}

func servedSerial(ctx context.Context, client *http.Client, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK || resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return "", fmt.Errorf("test endpoint returned %s without a leaf", resp.Status)
	}
	return resp.TLS.PeerCertificates[0].SerialNumber.Text(16), nil
}

func waitServedSerial(t *testing.T, client *http.Client, url, previous string, within time.Duration) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), within)
	defer cancel()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		serial, err := servedSerial(ctx, client, url)
		if err == nil && serial != previous {
			return serial
		}
		select {
		case <-ctx.Done():
			t.Fatalf("certificate did not change within %s: %v", within, err)
		case <-ticker.C:
		}
	}
}

func TestRenewNowOverRESTServesNewCertificate(t *testing.T) {
	t.Parallel()
	e := newAgentEnv(t)
	var fullchain, keyFile string
	var a *agent.Agent
	a, _ = e.newTestAgent(t, func(cfg *agent.Config) {
		fullchain = filepath.Join(cfg.Enrollment.Webroot, "fullchain.pem")
		keyFile = filepath.Join(cfg.Enrollment.Webroot, "privkey.pem")
		cfg.Deployments = []agent.Deployment{{Name: "proxy", Profile: agent.ProfileFile, Names: []string{"proxy1.homelab.lan"},
			Challenge: agent.ChallengeWebroot, Webroot: cfg.Enrollment.Webroot, Files: agent.Files{Fullchain: fullchain, Key: keyFile}}}
	})
	token, _, err := e.srv.Agents().CreateJoinToken(t.Context(), console, "proxy", []string{"proxy1.homelab.lan"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	res, err := a.Enroll(t.Context(), token)
	if err != nil || !res.Admitted() {
		t.Fatalf("enroll: %+v %v", res, err)
	}

	endpointTLS := &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		chain, chainErr := os.ReadFile(fullchain) // #nosec G304 -- test deployment target
		if chainErr != nil {
			return nil, chainErr
		}
		key, keyErr := os.ReadFile(keyFile) // #nosec G304 -- test deployment target
		if keyErr != nil {
			return nil, keyErr
		}
		pair, pairErr := tls.X509KeyPair(chain, key)
		if pairErr != nil {
			return nil, pairErr
		}
		pair.Leaf, pairErr = x509.ParseCertificate(pair.Certificate[0])
		return &pair, pairErr
	}}
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}), ErrorLog: slog.NewLogLogger(slog.New(slog.DiscardHandler).Handler(), slog.LevelDebug), ReadHeaderTimeout: 5 * time.Second}
	serveDone := make(chan error, 1)
	go func() { serveDone <- endpoint.Serve(tls.NewListener(ln, endpointTLS)) }()
	t.Cleanup(func() {
		_ = endpoint.Shutdown(context.Background())
		if serveErr := <-serveDone; serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			t.Errorf("test endpoint: %v", serveErr)
		}
	})

	runCtx, cancelRun := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- a.Run(runCtx) }()
	t.Cleanup(func() {
		cancelRun()
		select {
		case runErr := <-runDone:
			if runErr != nil {
				t.Errorf("agent run: %v", runErr)
			}
		case <-time.After(5 * time.Second):
			t.Error("agent did not stop")
		}
	})
	endpointClient := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{
		RootCAs: e.root, ServerName: "proxy1.homelab.lan", MinVersion: tls.VersionTLS12,
	}}}
	endpointURL := "https://" + ln.Addr().String()
	first := waitServedSerial(t, endpointClient, endpointURL, "", 30*time.Second)

	access := readDemoAccess(t, e.srv.opt.Config.DataDir)
	adminRoots := x509.NewCertPool()
	adminRoots.AddCert(e.srv.cert.Leaf)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	adminClient := &http.Client{Timeout: 5 * time.Second, Jar: jar, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: adminRoots, MinVersion: tls.VersionTLS12,
	}}}
	adminBase := "https://" + e.srv.AdminAddr() + "/api/v1"
	csrfToken := ""
	api := func(method, path string, body any) (int, string, error) {
		var reader io.Reader
		if body != nil {
			data, err := json.Marshal(body)
			if err != nil {
				return 0, "", err
			}
			reader = bytes.NewReader(data)
		}
		req, err := http.NewRequestWithContext(t.Context(), method, adminBase+path, reader)
		if err != nil {
			return 0, "", err
		}
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		if csrfToken != "" {
			req.Header.Set(auth.CSRFHeader, csrfToken)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := adminClient.Do(req)
		if err != nil {
			return 0, "", err
		}
		defer func() { _ = resp.Body.Close() }()
		data, err := io.ReadAll(resp.Body)
		var fields map[string]any
		if json.Unmarshal(data, &fields) == nil {
			if token, ok := fields["csrf_token"].(string); ok {
				csrfToken = token
			}
		}
		return resp.StatusCode, string(data), err
	}
	if status, _, err := api(http.MethodPost, "/auth/login", map[string]string{"username": access.user, "password": access.password}); err != nil || status != http.StatusOK {
		t.Fatalf("REST login: %d, %v", status, err)
	}
	if status, _, err := api(http.MethodPost, "/auth/totp", map[string]string{"code": testinstance.TOTP(access.secret, time.Now().UTC())}); err != nil || status != http.StatusOK {
		t.Fatalf("REST second factor: %d, %v", status, err)
	}
	if status, _, err := api(http.MethodGet, "/auth/session", nil); err != nil || status != http.StatusOK || csrfToken == "" {
		t.Fatalf("REST session: %d, %v", status, err)
	}
	if status, body, err := api(http.MethodPost, "/agents/"+res.AgentID+"/deployments/proxy/renew", nil); err != nil || status != http.StatusAccepted {
		t.Fatalf("renew now over REST: %d, %v: %s", status, err, body)
	}
	second := waitServedSerial(t, endpointClient, endpointURL, first, 5*time.Second)
	if second == first {
		t.Fatal("the endpoint kept the old certificate")
	}
}
