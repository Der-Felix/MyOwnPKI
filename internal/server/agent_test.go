package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"

	"github.com/Der-Felix/MyOwnPKI/internal/acme"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	agentv1 "github.com/Der-Felix/MyOwnPKI/internal/gen/myownpki/agent/v1"
	"github.com/Der-Felix/MyOwnPKI/internal/gen/myownpki/agent/v1/agentv1connect"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// agentEnv is a running server with the agent and the ACME listener (both
// with issued certificates), and a host on "port 80" that answers checks.
type agentEnv struct {
	srv     *Server
	root    *x509.CertPool
	rootDER []byte
	files   sync.Map // check token -> content, served like a webroot
	webroot string   // or a real webroot directory (the agent writes into it)
}

func newAgentEnv(t *testing.T) *agentEnv {
	t.Helper()
	cfg := testConfig(t)
	cfg.Agent.BaseURL, cfg.Agent.Listen, cfg.Agent.TLSIssuer, cfg.Agent.CA = "https://pki.homelab.lan:8444", "127.0.0.1:0", "issuing", "agent-ca"
	cfg.ACME.BaseURL, cfg.ACME.Listen, cfg.ACME.TLSIssuer = "https://pki.homelab.lan/acme", "127.0.0.1:0", "issuing"
	pass := initialized(t, cfg)
	srv, err := Open(t.Context(), Options{Config: cfg, Log: slog.New(slog.DiscardHandler), Hostname: "pki01", Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	if uerr := srv.Unseal(ctx, []byte(pass), console); uerr != nil {
		t.Fatal(uerr)
	}
	if _, cerr := srv.engine.CreateIntermediate(ctx, ca.IntermediateRequest{
		CASettings: ca.CASettings{Name: "agent-ca", BaseURL: "http://pki.homelab.lan"}, Parent: "root",
		Subject: ca.Subject{CommonName: "Agent CA"}, EKULimit: []string{"clientAuth"}, Who: console,
	}); cerr != nil {
		t.Fatal(cerr)
	}
	if _, derr := srv.engine.CreateDomain(ctx, ca.DomainRequest{Name: "homelab.lan", DomainSettings: ca.DomainSettings{CA: ptrTo("issuing")}, Who: console}); derr != nil {
		t.Fatal(derr)
	}
	srv.renewTLS(ctx) // the listener certificates, as at an unseal
	e := &agentEnv{srv: srv, root: x509.NewCertPool()}
	rootRow, err := pkidb.New(srv.pki.Read).GetCAByName(ctx, "root")
	if err != nil {
		t.Fatal(err)
	}
	gens, err := pkidb.New(srv.pki.Read).ListCAGenerations(ctx, rootRow.ID)
	if err != nil {
		t.Fatal(err)
	}
	rc, _ := x509.ParseCertificate(gens[0].CertDer)
	e.root.AddCert(rc)
	e.rootDER = gens[0].CertDer
	// The host: proxy1.homelab.lan resolves to 192.0.2.10, and port 80 of
	// it is this test server (webroot mode).
	host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/")
		if v, ok := e.files.Load(token); ok {
			s, _ := v.(string)
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, s) // #nosec G705 -- test: our own check token, served as text/plain
			return
		}
		if e.webroot != "" {
			http.FileServer(http.Dir(e.webroot)).ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(host.Close)
	var d net.Dialer
	checker, ok := srv.agent.svc.Checker.(*acme.HTTP01Checker)
	if !ok {
		t.Fatal("the agent service has no HTTP01Checker")
	}
	checker.SetNetwork(
		func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr != "192.0.2.10:80" {
				return nil, errors.New("unexpected address " + addr)
			}
			return d.DialContext(ctx, network, host.Listener.Addr().String())
		},
		func(_ context.Context, host string) ([]netip.Addr, error) {
			if host == "proxy1.homelab.lan" {
				return []netip.Addr{netip.MustParseAddr("192.0.2.10")}, nil
			}
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		})
	if err := srv.Listen(ctx); err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(runCtx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return e
}

func ptrTo[T any](v T) *T { return &v }

// client is an agent's connection; cert nil = without a client certificate.
// asked reports whether the server asked for a client certificate.
func (e *agentEnv) client(cert *tls.Certificate, asked *bool) agentv1connect.AgentServiceClient {
	return agentv1connect.NewAgentServiceClient(e.httpClient(cert, asked), "https://"+e.srv.AgentAddr())
}

func (e *agentEnv) httpClient(cert *tls.Certificate, asked *bool) *http.Client {
	tc := &tls.Config{RootCAs: e.root, ServerName: "pki.homelab.lan", MinVersion: tls.VersionTLS12,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if asked != nil {
				*asked = true
			}
			if cert == nil {
				return &tls.Certificate{}, nil
			}
			return cert, nil
		}}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: tc, ForceAttemptHTTP2: true, Proxy: nil}}
}

// enroll runs the whole enrollment over the listener with a join token and
// returns the agent's TLS certificate.
func (e *agentEnv) enroll(t *testing.T) (*tls.Certificate, string) {
	t.Helper()
	ctx := t.Context()
	token, _, err := e.srv.Agents().CreateJoinToken(ctx, console, "proxy1", []string{"proxy1.homelab.lan"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	key, csr := agentCSR(t)
	c := e.client(nil, nil)
	out, err := c.Enroll(ctx, connect.NewRequest(&agentv1.EnrollRequest{
		Hostname: "proxy1.homelab.lan", CsrDer: csr, JoinToken: token, CheckMethod: agentv1.CheckMethod_CHECK_METHOD_WEBROOT,
		AgentVersion: "0.3.0", Os: "linux", Arch: "amd64",
	}))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(mustCSR(t, csr).RawSubjectPublicKeyInfo)
	e.files.Store(out.Msg.CheckToken, out.Msg.CheckToken+"."+base64.RawURLEncoding.EncodeToString(sum[:]))
	st, err := c.EnrollStatus(ctx, connect.NewRequest(&agentv1.EnrollStatusRequest{EnrollmentId: out.Msg.EnrollmentId, Handle: out.Msg.Handle, CheckReady: true}))
	if err != nil {
		t.Fatal(err)
	}
	if st.Msg.State != agentv1.EnrollState_ENROLL_STATE_ADMITTED || len(st.Msg.CertificateDer) == 0 {
		t.Fatalf("enrollment: %v %q", st.Msg.State, st.Msg.Message)
	}
	return &tls.Certificate{Certificate: append([][]byte{st.Msg.CertificateDer}, st.Msg.ChainDer...), PrivateKey: key}, st.Msg.AgentId
}

func agentCSR(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, csr
}

func mustCSR(t *testing.T, der []byte) *x509.CertificateRequest {
	t.Helper()
	c, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestAgentListener (docs/PHASE3.md step 1): enrollment without a
// certificate, everything else only with an agent certificate; a client
// certificate from another CA fails the handshake; a disabled agent is cut
// off at its next call; an agent certificate gains nothing on the admin and
// the ACME listener – they never even ask for one.
func TestAgentListener(t *testing.T) {
	t.Parallel()
	e := newAgentEnv(t)
	ctx := t.Context()
	cert, id := e.enroll(t)

	// Without a certificate: only Enroll and EnrollStatus.
	_, csr := agentCSR(t)
	if _, err := e.client(nil, nil).RenewCertificate(ctx, connect.NewRequest(&agentv1.RenewCertificateRequest{CsrDer: csr})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("renew without a certificate: %v", err)
	}
	// With the agent certificate: a renewal.
	var asked bool
	renewed, err := e.client(cert, &asked).RenewCertificate(ctx, connect.NewRequest(&agentv1.RenewCertificateRequest{CsrDer: csr}))
	if err != nil || len(renewed.Msg.CertificateDer) == 0 || !asked {
		t.Fatalf("renew: %v (asked for a certificate: %v)", err, asked)
	}

	// A client certificate from another CA: the handshake fails.
	key, otherCSR := agentCSR(t)
	issued, err := e.srv.engine.Issue(ctx, ca.Request{CA: "issuing", Preset: "client", CSR: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: otherCSR}),
		DNSNames: []string{"proxy1.homelab.lan"}, IgnoreCSRNames: true, Subject: ca.Subject{CommonName: "proxy1.homelab.lan"}, Who: console})
	if err != nil {
		t.Fatal(err)
	}
	foreign := &tls.Certificate{Certificate: [][]byte{issued.CertDER}, PrivateKey: key}
	if _, ferr := e.client(foreign, nil).RenewCertificate(ctx, connect.NewRequest(&agentv1.RenewCertificateRequest{CsrDer: csr})); ferr == nil ||
		connect.CodeOf(ferr) == connect.CodePermissionDenied {
		t.Errorf("a certificate from another CA reached the service: %v", ferr)
	}

	// Only the service's path; nothing else on the listener.
	resp, err := get(t, e.httpClient(nil, nil), "https://"+e.srv.AgentAddr()+"/api/v1/system/status")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("other path: %d", resp.StatusCode)
	}

	// Disabled: cut off at the next call.
	if err := e.srv.Agents().SetDisabled(ctx, console, id, true); err != nil {
		t.Fatal(err)
	}
	_, csr3 := agentCSR(t)
	if _, err := e.client(cert, nil).RenewCertificate(ctx, connect.NewRequest(&agentv1.RenewCertificateRequest{CsrDer: csr3})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("disabled agent: %v", err)
	}

	// The admin and the ACME listener: no request for a client certificate,
	// so an agent certificate is never sent; the API answers 401.
	for name, url := range map[string]string{
		"admin": "https://" + e.srv.AdminAddr() + "/api/v1/auth/session",
		"acme":  "https://" + e.srv.ACMEAddr() + "/acme/directory",
	} {
		asked := false
		hc := e.httpClient(cert, &asked)
		if tr, ok := hc.Transport.(*http.Transport); ok && name == "admin" { // its bootstrap certificate: only the client certificate request is checked here
			tr.TLSClientConfig.InsecureSkipVerify = true // #nosec G402 -- test
		}
		resp, err := get(t, hc, url)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		_ = resp.Body.Close()
		if asked {
			t.Errorf("%s listener asked for a client certificate", name)
		}
		if name == "admin" && resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("admin API with an agent certificate: %d", resp.StatusCode)
		}
	}
}

// TestAgentCAProblemAtStart: a missing agent CA is named in the log and on
// the dashboard; nothing passes the listener's client authentication.
func TestAgentCAProblemAtStart(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t)
	cfg.Agent.BaseURL, cfg.Agent.Listen, cfg.Agent.TLSIssuer, cfg.Agent.CA = "https://pki.homelab.lan:8444", "127.0.0.1:0", "issuing", "agent-ca"
	initialized(t, cfg)
	var logs logBuf
	srv, err := Open(t.Context(), Options{Config: cfg, Log: slog.New(slog.NewJSONHandler(&logs, nil)), Hostname: "pki01", Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.closeDBs()
	srv.refreshAgentCAs(t.Context())
	if !strings.Contains(logs.String(), `there is no CA named \"agent-ca\" (agent.ca)`) {
		t.Errorf("log:\n%s", logs.String())
	}
	if got := kinds(srv.attention(true)); !strings.Contains(got, "crit: Agents can't enroll: there is no CA named") {
		t.Errorf("dashboard: %q", got)
	}
}

func get(t *testing.T, c *http.Client, url string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}
