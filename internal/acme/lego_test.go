package acme

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
	"github.com/Der-Felix/MyOwnPKI/internal/testutil"
)

// TestLegoWalkingSkeleton (PHASE2 part A): lego – a real ACME client –
// registers, orders by http-01 and gets a certificate that OpenSSL verifies
// against the chain. A TLS test server plays the reverse proxy; lego
// trusts exactly its certificate (no --tls-skip-verify). lego answers the
// challenge with its own server; the validator reaches it through the
// test's dialer, the port-80 rule stays as it is.
//
// lego is a test tool, never in go.mod: `task acme:lego` builds it and runs
// this test with LEGO_BIN set.
func TestLegoWalkingSkeleton(t *testing.T) {
	bin := os.Getenv("LEGO_BIN")
	if bin == "" {
		t.Skip("LEGO_BIN is not set – run `task acme:lego`")
	}
	opensslBin := testutil.OpenSSL(t)
	inst := testinstance.New(t, testinstance.Options{})
	inst.Unseal(t)
	issuing, open := "issuing", ca.ApprovalOpen
	if _, err := inst.Engine.CreateDomain(t.Context(), ca.DomainRequest{Name: "homelab.lan", DomainSettings: ca.DomainSettings{CA: &issuing, Approval: &open}, Who: testinstance.Console}); err != nil {
		t.Fatal(err)
	}
	handler := http.NotFoundHandler()
	var ariCalls atomic.Int32 // lego asks renewalInfo (RFC 9773)
	proxy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/renewal-info/") {
			ariCalls.Add(1)
		}
		handler.ServeHTTP(w, r)
	}))
	proxy.StartTLS()
	t.Cleanup(proxy.Close)
	s, err := New(Options{Engine: inst.Engine, BaseURL: proxy.URL + "/acme", TrustedProxies: "127.0.0.1, ::1", Clock: inst.Clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	handler = s

	// lego's challenge server, reached as 192.0.2.10:80.
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0") // a free port for lego, closed at once
	if err != nil {
		t.Fatal(err)
	}
	legoHTTP := ln.Addr().String()
	_ = ln.Close()
	s.valid.lookupIP = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.0.2.10")}, nil
	}
	s.valid.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr != "192.0.2.10:80" {
			return nil, &net.AddrError{Err: "unexpected target", Addr: addr}
		}
		var d net.Dialer
		return d.DialContext(ctx, network, legoHTTP)
	}

	dir := t.TempDir()
	caFile := filepath.Join(dir, "proxy-ca.pem")
	if werr := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: proxy.Certificate().Raw}), 0o600); werr != nil {
		t.Fatal(werr)
	}
	legoDir := filepath.Join(dir, "lego")
	run := func(args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), bin, args...) // #nosec G204 G702 -- test: LEGO_BIN is the tester's own lego binary
		cmd.Env = append(os.Environ(), "LEGO_CA_CERTIFICATES="+caFile, "LEGO_LOG_FORMAT=text")
		out, rerr := cmd.CombinedOutput() // #nosec G702 -- test: LEGO_BIN is the tester's own binary
		if rerr != nil {
			t.Fatalf("lego %s: %v\n%s", strings.Join(args, " "), rerr, out)
		}
		return string(out)
	}
	obtain := []string{"run", "--server", proxy.URL + "/acme/directory", "--path", legoDir, "--email", "admin@homelab.lan", "--accept-tos",
		"--domains", "nas.homelab.lan", "--http", "--http.address", legoHTTP, "--key-type", "EC256", "--no-random-sleep"}
	run(obtain...)

	var leafFile string
	_ = filepath.WalkDir(legoDir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, "nas.homelab.lan.crt") {
			leafFile = p
		}
		return nil
	})
	if leafFile == "" {
		t.Fatalf("lego wrote no certificate under %s", legoDir)
	}
	data, err := os.ReadFile(leafFile) // #nosec G304 -- the test's own temp dir
	if err != nil {
		t.Fatal(err)
	}
	b, rest := pem.Decode(data)
	leaf, err := x509.ParseCertificate(b.Bytes)
	if err != nil || len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "nas.homelab.lan" {
		t.Fatalf("leaf: %v %v", err, leaf)
	}
	// OpenSSL: the leaf against the bundled intermediate and the root.
	root, err := inst.Engine.CAChain(t.Context(), testinstance.Console, inst.CAIDs["root"])
	if err != nil {
		t.Fatal(err)
	}
	rootFile, interFile := filepath.Join(dir, "root.pem"), filepath.Join(dir, "inter.pem")
	_ = os.WriteFile(rootFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root[0]}), 0o600)
	_ = os.WriteFile(interFile, rest, 0o600) // #nosec G703 -- test: a file in the test's temp dir
	// #nosec G204 -- test: the openssl binary and temp files
	out, err := exec.CommandContext(t.Context(), opensslBin, "verify", "-purpose", "sslserver", "-CAfile", rootFile, "-untrusted", interFile, leafFile).CombinedOutput()
	if err != nil || !strings.Contains(string(out), ": OK") {
		t.Fatalf("openssl verify: %v\n%s", err, out)
	}

	// ARI (step 12): a second run asks renewalInfo and leaves the
	// certificate alone – its window lies in the future.
	run(obtain...)
	if ariCalls.Load() == 0 {
		t.Error("lego did not ask renewalInfo")
	}
	if again, _ := os.ReadFile(leafFile); !bytes.Equal(again, data) { // #nosec G304 -- the test's own temp dir
		t.Error("lego renewed although the window is in the future")
	}

	// Revoke (owner Q3): lego revokes with the account key, reason
	// superseded; the issuing CA's new CRL lists the certificate, and
	// OpenSSL with CRL checking refuses it.
	run("certificates", "revoke", "--server", proxy.URL+"/acme/directory", "--path", legoDir, "--email", "admin@homelab.lan",
		"--cert.name", "nas.homelab.lan", "--reason", "4", "--keep")
	crlDER, _, err := inst.Engine.LatestCRL(t.Context(), testinstance.Console, inst.CAIDs["issuing"])
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil || len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.Cmp(leaf.SerialNumber) != 0 ||
		crl.RevokedCertificateEntries[0].ReasonCode != 4 {
		t.Fatalf("CRL after lego revoke: %v %+v", err, crl)
	}
	crlFile := filepath.Join(dir, "issuing.crl")
	_ = os.WriteFile(crlFile, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER}), 0o600)
	// #nosec G204 -- test: the openssl binary and temp files
	out, err = exec.CommandContext(t.Context(), opensslBin, "verify", "-crl_check", "-CRLfile", crlFile, "-CAfile", rootFile, "-untrusted", interFile, leafFile).CombinedOutput()
	if err == nil || !strings.Contains(string(out), "certificate revoked") {
		t.Fatalf("openssl verify -crl_check after revoke: %v\n%s", err, out)
	}

	// ARI after the revocation: the window is in the past, so the next run
	// renews at once and names the old certificate in "replaces"; the new
	// certificate records it as renewal_of.
	run(obtain...)
	renewed, _ := os.ReadFile(leafFile) // #nosec G304 -- the test's own temp dir
	nb, _ := pem.Decode(renewed)
	if nb == nil || bytes.Equal(nb.Bytes, leaf.Raw) {
		t.Fatal("lego did not renew the revoked certificate")
	}
	q := pkidb.New(inst.Engine.PKI)
	fp := func(der []byte) string { s := sha256.Sum256(der); return strings.ToUpper(hex.EncodeToString(s[:])) }
	oldRow, err := q.GetCertificateByFingerprint(t.Context(), fp(leaf.Raw))
	if err != nil {
		t.Fatal(err)
	}
	newRow, err := q.GetCertificateByFingerprint(t.Context(), fp(nb.Bytes))
	if err != nil || newRow.RenewalOf.String != oldRow.ID {
		t.Errorf("renewal_of %q, want %q (%v) – lego sent no replaces?", newRow.RenewalOf.String, oldRow.ID, err)
	}
}
