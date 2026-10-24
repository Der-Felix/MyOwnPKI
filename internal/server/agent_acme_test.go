package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect"

	"github.com/Der-Felix/MyOwnPKI/internal/acme/jose"
	"github.com/Der-Felix/MyOwnPKI/internal/agent"
	agentv1 "github.com/Der-Felix/MyOwnPKI/internal/gen/myownpki/agent/v1"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
	"github.com/Der-Felix/MyOwnPKI/internal/testutil"
)

func TestAgentRegisterACMEAccountRPC(t *testing.T) {
	t.Parallel()
	e := newAgentEnv(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk, _ := jose.KeyFor(&key.PublicKey)
	req := connect.NewRequest(&agentv1.RegisterACMEAccountRequest{KeyThumbprint: jwk.Thumbprint()})
	if _, err := e.client(nil, nil).RegisterACMEAccount(t.Context(), req); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("anonymous registration: %v", err)
	}
	first, _ := e.enroll(t)
	for range 2 {
		if _, err := e.client(first, nil).RegisterACMEAccount(t.Context(), req); err != nil {
			t.Fatal(err)
		}
	}
	second, _ := e.enroll(t)
	if _, err := e.client(second, nil).RegisterACMEAccount(t.Context(), req); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("foreign registration: %v", err)
	}
	key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk, _ = jose.KeyFor(&key.PublicKey)
	if err := pkidb.New(e.srv.pki.Write).InsertACMEAccount(t.Context(), pkidb.InsertACMEAccountParams{
		ID: "ordinary-account", KeyThumbprint: jwk.Thumbprint(), Jwk: string(jwk.Canonical()), Status: "valid", Contact: "[]",
		CreatedAt: "2026-10-24T00:00:00Z", CreatedIp: "192.0.2.10", UpdatedAt: "2026-10-24T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.client(second, nil).RegisterACMEAccount(t.Context(), connect.NewRequest(&agentv1.RegisterACMEAccountRequest{KeyThumbprint: jwk.Thumbprint()})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("existing unlinked account registration: %v", err)
	}
}

func TestAgentReenrollmentRefusesPreviousACMEKey(t *testing.T) {
	t.Parallel()
	e := newAgentEnv(t)
	first, www := e.newTestAgent(t)
	enroll := func(a *agent.Agent) string {
		t.Helper()
		token, _, err := e.srv.Agents().CreateJoinToken(t.Context(), console, "proxy", []string{"proxy1.homelab.lan"}, 0)
		if err != nil {
			t.Fatal(err)
		}
		res, err := a.Enroll(t.Context(), token)
		if err != nil || !res.Admitted() {
			t.Fatalf("enroll: %v", err)
		}
		return res.AgentID
	}
	oldID := enroll(first)
	d := agent.Deployment{Name: "proxy", Names: []string{"proxy1.homelab.lan"}, Challenge: agent.ChallengeWebroot, Webroot: www}
	if _, err := first.Obtain(t.Context(), d); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.Agents().Revoke(t.Context(), console, oldID); err != nil {
		t.Fatal(err)
	}
	second, nextWWW := e.newTestAgent(t)
	newID := enroll(second)
	if oldID == newID {
		t.Fatal("a revoked identity was reused")
	}
	// Keep the old ACME state, as on a host whose agent identity was reset.
	files, globErr := filepath.Glob(filepath.Join(filepath.Dir(www), "state", "acme-*"))
	if globErr != nil || len(files) != 2 {
		t.Fatal("expected the previous account's key and registration")
	}
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(filepath.Dir(nextWWW), "state", filepath.Base(path))
		if err := os.WriteFile(target, data, 0o600); err != nil { // #nosec G703 -- generated account files copied between private test directories
			t.Fatal(err)
		}
		defer clear(data)
	}
	d.Webroot = nextWWW
	_, err := second.Obtain(t.Context(), d)
	if !errors.Is(err, agent.ErrACMEAccountRegistration) || !strings.Contains(err.Error(), "current agent identity") || !strings.Contains(err.Error(), ".key") || !strings.Contains(err.Error(), ".json") {
		t.Fatalf("re-enrollment needs a clear terminal error: %v", err)
	}
	for _, path := range files {
		old, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		kept, err := os.ReadFile(filepath.Join(filepath.Dir(nextWWW), "state", filepath.Base(path)))
		if err != nil || !bytes.Equal(old, kept) {
			t.Fatal("the previous account state was changed automatically")
		}
		clear(old)
		clear(kept)
	}
}

// The actual agent, mTLS gateway and ACME server, with both responder
// modes. Only network destinations are mapped to local ephemeral ports.
func TestAgentACMEEndToEnd(t *testing.T) {
	// Serial: t.Setenv deliberately poisons every relevant environment path.
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy"} {
		t.Setenv(name, "http://127.0.0.1:1")
	}
	t.Setenv("NO_PROXY", "")
	t.Setenv("LEGO_CA_CERTIFICATES", filepath.Join(t.TempDir(), "must-not-be-read.pem"))
	t.Setenv("LEGO_CA_SERVER_NAME", "foreign.homelab.lan")
	for _, mode := range []string{agent.ChallengeWebroot, agent.ChallengeStandalone} {
		t.Run(mode, func(t *testing.T) {
			e := newAgentEnv(t)
			a, www := e.newTestAgent(t)
			token, _, err := e.srv.Agents().CreateJoinToken(t.Context(), console, "proxy", []string{"proxy1.homelab.lan"}, 0)
			if err != nil {
				t.Fatal(err)
			}
			res, err := a.Enroll(t.Context(), token)
			if err != nil || !res.Admitted() {
				t.Fatalf("enroll: %v", err)
			}
			if mode == agent.ChallengeStandalone {
				ln, lerr := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
				if lerr != nil {
					t.Fatal(lerr)
				}
				a.StandaloneAddr = ln.Addr().String()
				_ = ln.Close()
				var dialer net.Dialer
				e.srv.acme.SetNetwork(func(ctx context.Context, network, _ string) (net.Conn, error) {
					return dialer.DialContext(ctx, network, a.StandaloneAddr)
				}, func(context.Context, string) ([]netip.Addr, error) {
					return []netip.Addr{netip.MustParseAddr("192.0.2.10")}, nil
				})
			}
			d := agent.Deployment{Name: "proxy", Names: []string{"proxy1.homelab.lan"}, Challenge: mode, Webroot: www}
			first, err := a.Obtain(t.Context(), d)
			if err != nil {
				t.Fatal(err)
			}
			second, err := a.Obtain(t.Context(), d)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(first.Leaf.RawSubjectPublicKeyInfo, second.Leaf.RawSubjectPublicKeyInfo) {
				t.Fatal("the certificate key was reused")
			}
			t.Run("openssl", func(t *testing.T) {
				bin := testutil.OpenSSL(t)
				dir := t.TempDir()
				leafPath, chainPath, rootPath := filepath.Join(dir, "leaf.pem"), filepath.Join(dir, "chain.pem"), filepath.Join(dir, "root.pem")
				for path, data := range map[string][]byte{leafPath: first.Certificate, chainPath: first.Chain, rootPath: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.rootDER})} {
					if werr := os.WriteFile(path, data, 0o600); werr != nil {
						t.Fatal(werr)
					}
				}
				cmd := exec.CommandContext(t.Context(), bin, "verify", "-purpose", "sslserver", "-CAfile", rootPath, "-untrusted", chainPath, leafPath) // #nosec G204 G702 -- test-only openssl and generated public certificates
				if output, verr := cmd.CombinedOutput(); verr != nil {
					t.Fatalf("openssl verify: %v: %s", verr, output)
				}
			})
			for bundle := first.Fullchain; len(bundle) > 0; {
				b, rest := pem.Decode(bundle)
				if b == nil {
					t.Fatal("invalid fullchain")
				}
				cert, perr := x509.ParseCertificate(b.Bytes)
				if perr != nil || bytes.Equal(cert.Raw, e.rootDER) {
					t.Fatal("the fullchain contains the root or invalid DER")
				}
				bundle = rest
			}
			row, err := pkidb.New(e.srv.pki.Read).GetAgent(t.Context(), res.AgentID)
			if err != nil || !row.AcmeKeyThumbprint.Valid {
				t.Fatalf("account key not registered: %v", err)
			}
			account, err := pkidb.New(e.srv.pki.Read).GetACMEAccountByThumbprint(t.Context(), row.AcmeKeyThumbprint.String)
			if err != nil || account.AgentID.String != row.ID {
				t.Fatalf("account not bound: %v", err)
			}
			entries, err := os.ReadDir(filepath.Join(www, ".well-known", "acme-challenge"))
			if err != nil || len(entries) != 0 {
				t.Fatalf("challenge files remain: %v", err)
			}
		})
	}
}
