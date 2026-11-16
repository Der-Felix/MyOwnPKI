package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
)

// foreignCert is a certificate of a CA that is not on this server.
func foreignCert(t *testing.T, mod func(*x509.Certificate), pub crypto.PublicKey) []byte {
	t.Helper()
	ca := newOfflineRoot(t, "Foreign Root", t0.Add(-day))
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x1234abcd), Subject: pkix.Name{CommonName: "web.example.org", Organization: []string{"Example"}},
		NotBefore: t0.Add(-time.Hour), NotAfter: t0.Add(90 * day),
	}
	if mod != nil {
		mod(tmpl)
	}
	if pub == nil {
		pub = mustKey(t, elliptic.P256()).Public()
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func (v *env) certificateCount(t *testing.T) int {
	t.Helper()
	var n int
	if err := v.pki.QueryRowContext(t.Context(), `SELECT count(*) FROM certificates`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestImportExternalRecordsTheCertificate: what is stored for a certificate
// of another CA – the facts of the certificate, its SANs once each and
// lower case, and who imported it.
func TestImportExternalRecordsTheCertificate(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	uri, err := url.Parse("spiffe://example.org/web")
	if err != nil {
		t.Fatal(err)
	}
	certPEM := foreignCert(t, func(c *x509.Certificate) {
		c.DNSNames = []string{"Web.Example.ORG", "web.example.org", "*.apps.example.org"}
		c.IPAddresses = []net.IP{net.ParseIP("192.0.2.7"), net.ParseIP("2001:db8::7"), net.ParseIP("192.0.2.7")}
		c.EmailAddresses = []string{"admin@example.org"}
		c.URIs = []*url.URL{uri}
	}, nil)
	info, err := v.e.ImportExternal(t.Context(), certPEM, tester)
	if err != nil {
		t.Fatal(err)
	}
	der := pemBytes(t, certPEM)
	sum := sha256.Sum256(der)
	if info.Source != "external" || info.CAID != "" || info.CAName != "" || info.Serial != "1234ABCD" || info.CommonName != "web.example.org" ||
		info.Fingerprint != strings.ToUpper(hex.EncodeToString(sum[:])) || info.KeyAlgorithm != AlgECDSAP256 || info.KeyStored || info.RequestedBy != "u-1" ||
		!info.NotBefore.Equal(t0.Add(-time.Hour)) || !info.NotAfter.Equal(t0.Add(90*day)) {
		t.Errorf("certificate info %+v", info)
	}
	for name, p := range map[string]struct{ got, want []string }{
		"DNS":    {info.DNSNames, []string{"*.apps.example.org", "web.example.org"}},
		"IPs":    {info.IPs, []string{"192.0.2.7", "2001:db8::7"}},
		"emails": {info.Emails, []string{"admin@example.org"}},
		"URIs":   {info.URIs, []string{"spiffe://example.org/web"}},
	} {
		got := slices.Clone(p.got)
		slices.Sort(got)
		slices.Sort(p.want)
		if !slices.Equal(got, p.want) {
			t.Errorf("%s: %v, want %v", name, got, p.want)
		}
	}
	var sans int
	if err := v.pki.QueryRowContext(t.Context(), `SELECT count(*) FROM certificate_sans WHERE certificate_id = ?`, info.ID).Scan(&sans); err != nil || sans != 6 {
		t.Errorf("%d SAN rows, want 6 (%v)", sans, err)
	}
	found := false
	for _, row := range v.auditRows(t) {
		if row.action == ActionImportExternal && row.result == "success" {
			found = true
			if row.details["serial"] != "1234ABCD" || row.details["fingerprint"] != info.Fingerprint || !strings.Contains(fmt.Sprint(row.details["issuer"]), "Foreign Root") {
				t.Errorf("audit details %v", row.details)
			}
		}
	}
	if !found {
		t.Error("no success entry in the audit log")
	}
}

// TestImportExternalRefusals: a record is not a way around anything – a CA
// certificate is a root import, a duplicate is a duplicate, and what isn't
// one clean PEM certificate is refused. Nothing is stored.
func TestImportExternalRefusals(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	_, issuing := v.chain(t, caOpts{})
	ours := v.issue(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"a.homelab.lan"}})
	before := v.certificateCount(t)
	foreign := foreignCert(t, nil, nil)
	block, _ := pem.Decode(foreign)
	if _, err := v.e.ImportExternal(t.Context(), foreign, tester); err != nil {
		t.Fatal(err)
	}
	before++
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"a root", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newOfflineRoot(t, "Some Root", t0).cert.Raw}), "this is a CA certificate – import a root with POST /cas/import"},
		{"an intermediate of this server", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuing.cert.Raw}), "this is a CA certificate"},
		{"the same certificate again", foreign, "this certificate is on the server already"},
		{"a certificate this server issued", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ours.CertDER}), "this certificate is on the server already"},
		{"nothing", nil, "no PEM block found"},
		{"a CSR", makeCSR(t, mustKey(t, elliptic.P256()), &x509.CertificateRequest{DNSNames: []string{"a.example.org"}}), `PEM block "CERTIFICATE REQUEST" is not a certificate`},
		{"with headers", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"k": "v"}, Bytes: block.Bytes}), "the PEM block has headers"},
		{"two certificates", append(slices.Clone(foreign), foreign...), "there is data after the certificate"},
		{"damaged", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes[:20]}), "the certificate can't be parsed"},
		{"more than 64 KiB", append(slices.Clone(foreign), make([]byte, MaxCertSize)...), "the certificate file is larger than 64 KiB"},
	}
	for _, tt := range tests {
		_, err := v.e.ImportExternal(t.Context(), tt.data, tester)
		if got := deniedErr(t, err); !strings.Contains(got, tt.want) {
			t.Errorf("%s: %q, want %q", tt.name, got, tt.want)
		}
	}
	if n := v.certificateCount(t); n != before {
		t.Errorf("%d certificates after the refusals, want %d", n, before)
	}
	denied := 0
	for _, row := range v.auditRows(t) {
		if row.action == ActionImportExternal && row.result == "denied" {
			denied++
		}
	}
	if denied != len(tests) {
		t.Errorf("%d denied entries in the audit log, want %d", denied, len(tests))
	}
}

// TestImportExternalWithThousandsOfSANs: the certificate is a record like any
// other – every SAN once, nothing lost – and the audit entry stays small.
func TestImportExternalWithThousandsOfSANs(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	const count = 3000
	var names []string
	for i := range count {
		names = append(names, fmt.Sprintf("h%d.ex.org", i))
	}
	names = append(names, names[:100]...) // twice
	certPEM := foreignCert(t, func(c *x509.Certificate) { c.DNSNames = names }, nil)
	if len(certPEM) > MaxCertSize {
		t.Fatalf("the test certificate is %d bytes, over the limit", len(certPEM))
	}
	info, err := v.e.ImportExternal(t.Context(), certPEM, tester)
	if err != nil {
		t.Fatal(err)
	}
	if len(info.DNSNames) != count {
		t.Errorf("%d DNS names, want %d", len(info.DNSNames), count)
	}
	var rows int
	if err = v.pki.QueryRowContext(t.Context(), `SELECT count(DISTINCT value) FROM certificate_sans WHERE certificate_id = ? AND type = 'dns'`, info.ID).Scan(&rows); err != nil || rows != count {
		t.Errorf("%d distinct SAN rows, want %d (%v)", rows, count, err)
	}
	for _, row := range v.auditRows(t) {
		if row.action == ActionImportExternal {
			if n := len(fmt.Sprint(row.details)); n > 2000 {
				t.Errorf("audit details are %d bytes", n)
			}
		}
	}
}

// TestImportExternalPermissions: tenant administrators only.
func TestImportExternalPermissions(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.chain(t, caOpts{})
	certPEM := foreignCert(t, nil, nil)
	now := v.clk.Now()
	for _, tt := range []struct {
		name string
		who  keys.Who
	}{
		{"viewer", signedIn("view", now, authz.Binding{Role: authz.Viewer})},
		{"operator", signedIn("op", now, authz.Binding{Role: authz.Operator})},
		{"admin of one CA", signedIn("cadm", now, authz.Binding{CA: "issuing", Role: authz.Admin})},
		{"nobody", keys.Who{Actor: tester.Actor}},
	} {
		if _, err := v.e.ImportExternal(t.Context(), certPEM, tt.who); !errors.Is(err, authz.ErrDenied) || !errors.Is(err, ErrDenied) {
			t.Errorf("%s: %v", tt.name, err)
		}
	}
	if n := v.certificateCount(t); n != 0 {
		t.Errorf("a refused user stored %d certificates", n)
	}
	admin := signedIn("adm", time.Time{}, authz.Binding{Role: authz.Admin})
	if _, err := v.e.ImportExternal(t.Context(), certPEM, admin); err != nil {
		t.Errorf("tenant admin: %v", err)
	}
}

// TestImportExternalIsAtomic: a failing SAN insert leaves no certificate
// without its SANs behind, and the import works once the store does.
func TestImportExternalIsAtomic(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	certPEM := foreignCert(t, func(c *x509.Certificate) { c.DNSNames = []string{"a.example.org"} }, nil)
	if _, err := v.pki.ExecContext(t.Context(), `CREATE TRIGGER fail_san BEFORE INSERT ON certificate_sans BEGIN SELECT RAISE(ABORT, 'disk full'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := v.e.ImportExternal(t.Context(), certPEM, tester); err == nil || errors.Is(err, ErrDenied) || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("import with a failing store: %v", err)
	}
	if n := v.certificateCount(t); n != 0 {
		t.Errorf("%d certificates after a failed import", n)
	}
	for _, row := range v.auditRows(t) {
		if row.action == ActionImportExternal && row.result == "success" {
			t.Errorf("a success entry for a failed import: %+v", row)
		}
	}
	if _, err := v.pki.ExecContext(t.Context(), `DROP TRIGGER fail_san`); err != nil {
		t.Fatal(err)
	}
	if _, err := v.e.ImportExternal(t.Context(), certPEM, tester); err != nil {
		t.Errorf("import after the store works again: %v", err)
	}
}

// TestDescribeKey: an imported certificate may carry a key the key policy
// wouldn't accept for a new one; it is named anyway.
func TestDescribeKey(t *testing.T) {
	t.Parallel()
	rsa1024, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // a key below the policy minimum is the case: describeKey must still name it
	if err != nil {
		t.Fatal(err)
	}
	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name string
		pub  crypto.PublicKey
		want string
	}{
		{"ECDSA P-256", mustKey(t, elliptic.P256()).Public(), "ecdsa-p256"},
		{"ECDSA P-384", mustKey(t, elliptic.P384()).Public(), "ecdsa-p384"},
		{"ECDSA P-224", p224.Public(), "ecdsa-p-224"},
		{"RSA 2048", rsa2048.Public(), "rsa-2048"},
		{"RSA 1024", rsa1024.Public(), "rsa-1024"},
		{"Ed25519", edPub, "ed25519"},
		{"something else", struct{}{}, "struct {}"},
	} {
		if got := describeKey(tt.pub); got != tt.want {
			t.Errorf("%s: %q, want %q", tt.name, got, tt.want)
		}
	}
}
