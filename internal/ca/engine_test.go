package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/ca/preset"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

var (
	oidKeyUsage    = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidBasicConstr = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidSAN         = asn1.ObjectIdentifier{2, 5, 29, 17}
)

func findExt(cert *x509.Certificate, oid asn1.ObjectIdentifier) (pkix.Extension, bool) {
	for _, e := range cert.Extensions {
		if e.Id.Equal(oid) {
			return e, true
		}
	}
	return pkix.Extension{}, false
}

func parse(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (v *env) issue(t *testing.T, req Request) *Issued {
	t.Helper()
	if req.Who.Actor.Name == "" {
		req.Who = tester
	}
	out, err := v.e.Issue(t.Context(), req)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	return out
}

// denied issues req and returns the reasons; the test fails unless denied.
func (v *env) denied(t *testing.T, req Request) string {
	t.Helper()
	if req.Who.Actor.Name == "" {
		req.Who = tester
	}
	_, err := v.e.Issue(t.Context(), req)
	var d *DeniedError
	if !errors.As(err, &d) || !errors.Is(err, ErrDenied) {
		t.Fatalf("want a denial, got %v", err)
	}
	return strings.Join(d.Reasons, "\n")
}

// presetRequests gives every built-in preset a request it accepts.
var presetRequests = map[string]Request{
	"server":        {DNSNames: []string{"nas.homelab.lan"}, IPAddresses: []string{"10.0.0.5"}},
	"wildcard":      {Subject: Subject{CommonName: "*.homelab.lan"}},
	"server-client": {DNSNames: []string{"db.homelab.lan"}},
	"client":        {Subject: Subject{CommonName: "laptop-01"}},
	"user":          {Subject: Subject{CommonName: "Felix"}, EmailAddresses: []string{"felix@homelab.lan"}},
	"smime":         {EmailAddresses: []string{"felix@homelab.lan"}},
	"vpn-server":    {DNSNames: []string{"vpn.homelab.lan"}},
	"vpn-client":    {Subject: Subject{CommonName: "vpn-user"}},
	"codesign":      {Subject: Subject{CommonName: "Homelab Code Signing", Organization: "Homelab"}},
	"ocsp":          {Subject: Subject{CommonName: "Homelab OCSP Responder"}},
	"timestamp":     {Subject: Subject{CommonName: "Homelab TSA", Country: "de"}},
	"custom":        {Subject: Subject{CommonName: "custom"}, CustomKeyUsage: []string{"digitalSignature"}, CustomExtKeyUsage: []string{"clientAuth", "1.3.6.1.4.1.311.10.3.12"}},
}

func TestIssueEveryPreset(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	root, issuing := v.chain(t, caOpts{permitDNS: []string{"homelab.lan"}, permitIP: []string{"10.0.0.0/8"}})

	for _, name := range v.e.Presets.Names() {
		p, _ := v.e.Presets.Get(name)
		req, ok := presetRequests[name]
		if !ok {
			t.Fatalf("no test request for preset %q", name)
		}
		if p.Customizable {
			var err error
			if p, err = p.Customize(req.CustomKeyUsage, req.CustomExtKeyUsage); err != nil {
				t.Fatal(err)
			}
		}
		for _, source := range []string{"csr", "server"} {
			t.Run(name+"/"+source, func(t *testing.T) {
				t.Parallel()
				req := req
				req.CA, req.Preset = "issuing", name
				leafKey := mustKey(t, elliptic.P256())
				if source == "csr" {
					req.CSR = makeCSR(t, leafKey, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored when the request has a CN"}})
				}
				out := v.issue(t, req)
				cert := parse(t, out.CertDER)
				if source == "csr" && !leafKey.PublicKey.Equal(cert.PublicKey) {
					t.Error("certificate doesn't carry the CSR's key")
				}
				if source == "server" && out.KeyID == "" {
					t.Error("server-generated key not stored")
				}
				checkLeaf(t, cert, p, issuing, out)
				opensslVerify(t, []*fixtureCA{issuing, root}, out.CertDER, p.OpenSSLPurpose)
			})
		}
	}
}

// checkLeaf checks every extension against pki-rules.md §2.
func checkLeaf(t *testing.T, cert *x509.Certificate, p *preset.Preset, issuer *fixtureCA, out *Issued) {
	t.Helper()
	if bc, ok := findExt(cert, oidBasicConstr); !ok || !bc.Critical || cert.IsCA {
		t.Error("basicConstraints must be critical CA:FALSE")
	}
	if ku, ok := findExt(cert, oidKeyUsage); !ok || !ku.Critical {
		t.Error("keyUsage must be critical")
	}
	if want := p.KeyUsageFor(cert.PublicKeyAlgorithm); cert.KeyUsage != want {
		t.Errorf("key usage %b, want %b", cert.KeyUsage, want)
	}
	eku, hasEKU := findExt(cert, oidExtKeyUsage)
	if len(p.ExtKeyUsage.Usages) == 0 {
		if hasEKU {
			t.Error("unexpected EKU")
		}
	} else {
		var got []asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(eku.Value, &got); err != nil || !slices.EqualFunc(got, p.ExtKeyUsageOIDs(), asn1.ObjectIdentifier.Equal) {
			t.Errorf("EKU %v, want %v", got, p.ExtKeyUsageOIDs())
		}
		if eku.Critical != p.ExtKeyUsage.Critical {
			t.Errorf("EKU critical = %v, want %v", eku.Critical, p.ExtKeyUsage.Critical)
		}
	}
	if _, ok := findExt(cert, oidOCSPNoCheck); ok != p.OCSPNoCheck {
		t.Errorf("ocsp-nocheck = %v, want %v", ok, p.OCSPNoCheck)
	}
	ski, _ := subjectKeyID(cert.PublicKey)
	if !slices.Equal(cert.SubjectKeyId, ski) || !slices.Equal(cert.AuthorityKeyId, issuer.cert.SubjectKeyId) {
		t.Error("SKI must be RFC 7093 method 1, AKI the issuer's SKI")
	}
	if !slices.Equal(cert.IssuingCertificateURL, []string{baseURL + "/ca/issuing/1.crt"}) ||
		!slices.Equal(cert.CRLDistributionPoints, []string{baseURL + "/crl/issuing/1.crl"}) || len(cert.OCSPServer) != 0 {
		t.Errorf("AIA %v, CDP %v, OCSP %v", cert.IssuingCertificateURL, cert.CRLDistributionPoints, cert.OCSPServer)
	}
	if cert.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Errorf("signature algorithm %v – must follow the P-256 issuer", cert.SignatureAlgorithm)
	}
	if cert.SerialNumber.Sign() <= 0 || cert.SerialNumber.BitLen() > serialBits {
		t.Errorf("serial %x: want positive, at most %d bits", cert.SerialNumber, serialBits)
	}
	days := min(p.ValidityDays, 825)
	if !cert.NotBefore.Equal(t0.Add(-Backdate)) || !cert.NotAfter.Equal(cert.NotBefore.Add(time.Duration(days)*day-time.Second)) {
		t.Errorf("validity %v – %v, want %d days from %v", cert.NotBefore, cert.NotAfter, days, t0.Add(-Backdate))
	}
	if out.SerialHex != SerialHex(cert.SerialNumber) || out.Fingerprint != fingerprint(cert.Raw) || len(out.Chain) != 2 {
		t.Errorf("result %+v", out)
	}
}

func TestIssuedCertificateIsStoredAndAudited(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.chain(t, caOpts{})
	csr := makeCSR(t, mustKey(t, elliptic.P256()), &x509.CertificateRequest{DNSNames: []string{"NAS.homelab.lan", "nas"}})
	out := v.issue(t, Request{CA: "issuing", Preset: "server", CSR: csr, IPAddresses: []string{"::ffff:10.0.0.5"}})

	q := pkidb.New(v.pki)
	row, err := q.GetCertificate(t.Context(), out.ID)
	if err != nil {
		t.Fatal(err)
	}
	if row.Source != "issued" || row.SerialHex != out.SerialHex || row.CommonName != "nas.homelab.lan" || row.CaGeneration.Int64 != 1 ||
		row.RequestedBy != "u-1" || row.KeyID.Valid || row.NotBefore != "2026-10-13T07:55:00Z" {
		t.Errorf("row %+v", row)
	}
	sans, _ := q.ListCertificateSANs(t.Context(), out.ID)
	if fmt.Sprint(sans) != "[{dns nas} {dns nas.homelab.lan} {ip 10.0.0.5}]" {
		t.Errorf("SANs %v – lower case, IPv4-mapped address as IPv4", sans)
	}

	rows := v.auditRows(t)
	if len(rows) != 1 || rows[0].action != ActionIssue || rows[0].result != "success" || rows[0].target != out.ID {
		t.Fatalf("audit %+v", rows)
	}
	d := rows[0].details
	if d["serial"] != out.SerialHex || d["key_source"] != "csr" || d["ca"] != "issuing" || d["preset"] != "server" ||
		fmt.Sprint(d["sans"]) != "[dns:nas.homelab.lan dns:nas ip:10.0.0.5]" {
		t.Errorf("audit details %v", d)
	}
	if strings.Contains(fmt.Sprint(d), "CERTIFICATE REQUEST") {
		t.Error("CSR content in the audit log")
	}
}

func TestCertificatesAreImmutable(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.chain(t, caOpts{})
	out := v.issue(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"a.homelab.lan"}})
	for _, s := range []string{
		`UPDATE certificates SET not_after = '2099-01-01T00:00:00Z'`,
		`DELETE FROM certificates`,
		`UPDATE certificate_sans SET value = 'evil.com'`,
		`DELETE FROM certificate_sans`, // the search index can't be thinned out either
		`UPDATE ca_generations SET cert_der = x'00'`,
		`UPDATE cas SET name = 'other'`,
		`UPDATE cas SET public_base_url = 'http://other.example'`,
	} {
		if _, err := v.pki.ExecContext(t.Context(), s); err == nil {
			t.Errorf("%s: allowed", s)
		}
	}
	// The same serial can't be stored twice for one CA – not even by a bug.
	row, _ := pkidb.New(v.pki).GetCertificate(t.Context(), out.ID)
	row.ID, row.FingerprintSha256 = "crt_other", "00"
	if err := pkidb.New(v.pki).InsertCertificate(t.Context(), pkidb.InsertCertificateParams{
		ID: row.ID, CaID: row.CaID, CaGeneration: row.CaGeneration, Source: row.Source, SerialHex: row.SerialHex,
		SubjectDn: row.SubjectDn, NotBefore: row.NotBefore, NotAfter: row.NotAfter, KeyAlgorithm: row.KeyAlgorithm,
		CertDer: row.CertDer, FingerprintSha256: row.FingerprintSha256, RequestedBy: row.RequestedBy, CreatedAt: row.CreatedAt,
	}); err == nil || !strings.Contains(err.Error(), "UNIQUE") {
		t.Errorf("duplicate serial: %v", err)
	}
	var n int
	if err := v.pki.QueryRowContext(t.Context(), `SELECT count(*) FROM certificate_sans WHERE certificate_id = ?`, out.ID).Scan(&n); err != nil || n != 1 {
		t.Errorf("SANs after the attempts: %d, %v", n, err)
	}

	// An external certificate (only tracked, not issued here) can be removed,
	// and its names go with it.
	q := pkidb.New(v.pki)
	if err := q.InsertCertificate(t.Context(), pkidb.InsertCertificateParams{
		ID: "crt_external", Source: "external", SerialHex: "01", SubjectDn: "CN=ext", NotBefore: row.NotBefore, NotAfter: row.NotAfter,
		KeyAlgorithm: AlgECDSAP256, CertDer: []byte{1}, FingerprintSha256: "EXT", RequestedBy: "u-1", CreatedAt: row.CreatedAt,
	}); err != nil {
		t.Fatal(err)
	}
	if err := q.InsertCertificateSAN(t.Context(), pkidb.InsertCertificateSANParams{CertificateID: "crt_external", Type: "dns", Value: "ext.example"}); err != nil {
		t.Fatal(err)
	}
	if _, err := v.pki.ExecContext(t.Context(), `DELETE FROM certificates WHERE id = 'crt_external'`); err != nil {
		t.Errorf("delete external certificate: %v", err)
	}
	if err := v.pki.QueryRowContext(t.Context(), `SELECT count(*) FROM certificate_sans`).Scan(&n); err != nil || n != 1 {
		t.Errorf("SANs after deleting the external certificate: %d, %v", n, err)
	}
}

func TestSignatureFollowsTheIssuerKey(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	root := v.addCA(t, "root", caOpts{})
	out := v.issue(t, Request{CA: "root", Preset: "server", DNSNames: []string{"nas.homelab.lan"}})
	cert := parse(t, out.CertDER)
	if cert.SignatureAlgorithm != x509.ECDSAWithSHA384 {
		t.Errorf("P-384 root signed with %v", cert.SignatureAlgorithm)
	}
	if len(out.Chain) != 1 || cert.CheckSignatureFrom(root.cert) != nil {
		t.Error("leaf issued by the root doesn't verify")
	}
	opensslVerify(t, []*fixtureCA{root}, out.CertDER, "sslserver")
}

func TestMaliciousCSRGetsNoCAPowers(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	root, issuing := v.chain(t, caOpts{})
	bc, _ := asn1.Marshal(struct {
		IsCA       bool `asn1:"optional"`
		MaxPathLen int  `asn1:"optional,default:-1"`
	}{IsCA: true, MaxPathLen: 5})
	ku, _ := asn1.Marshal(asn1.BitString{Bytes: []byte{0x06}, BitLength: 7}) // keyCertSign, cRLSign
	csr := makeCSR(t, mustKey(t, elliptic.P256()), &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "rogue.homelab.lan"},
		DNSNames: []string{"rogue.homelab.lan"},
		ExtraExtensions: []pkix.Extension{
			{Id: oidBasicConstr, Critical: true, Value: bc},
			{Id: oidKeyUsage, Critical: true, Value: ku},
			{Id: oidExtKeyUsage, Value: mustMarshal(t, []asn1.ObjectIdentifier{{2, 5, 29, 37, 0}})}, // anyExtendedKeyUsage
		},
	})
	cert := parse(t, v.issue(t, Request{CA: "issuing", Preset: "server", CSR: csr}).CertDER)
	if cert.IsCA || cert.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != 0 || slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageAny) {
		t.Errorf("CSR extensions were copied: CA=%v KU=%b EKU=%v", cert.IsCA, cert.KeyUsage, cert.ExtKeyUsage)
	}
	// OpenSSL agrees the leaf can't act as a CA.
	opensslVerify(t, []*fixtureCA{issuing, root}, cert.Raw, "sslserver")
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCSRChecks(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.chain(t, caOpts{})
	key := mustKey(t, elliptic.P256())
	good := makeCSR(t, key, &x509.CertificateRequest{DNSNames: []string{"a.homelab.lan"}})

	block, _ := pem.Decode(good)
	forged := slices.Clone(block.Bytes)
	forged[len(forged)-1] ^= 0x01                      // a changed signature
	rsa1024, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // deliberately weak: the key policy must reject it
	if err != nil {
		t.Fatal(err)
	}
	p224 := mustKey(t, elliptic.P224())

	tests := []struct {
		name string
		csr  []byte
		want string
	}{
		{"forged signature", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: forged}), "signature is invalid"},
		{"two CSRs", append(slices.Clone(good), good...), "data after the CSR"},
		{"certificate instead", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes}), "not a certificate request"},
		{"not PEM", []byte("hello"), "no PEM block"},
		{"too large", append(slices.Clone(good), make([]byte, MaxCSRSize)...), "larger than"},
		{"PEM headers", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: block.Bytes}), "headers"},
		{"RSA 1024", makeCSR(t, rsa1024, &x509.CertificateRequest{DNSNames: []string{"a.homelab.lan"}}), "1024 bits is not allowed"},
		{"P-224", makeCSR(t, p224, &x509.CertificateRequest{DNSNames: []string{"a.homelab.lan"}}), "P-224 is not allowed"},
	}
	for _, tt := range tests {
		if got := v.denied(t, Request{CA: "issuing", Preset: "server", CSR: tt.csr}); !strings.Contains(got, tt.want) {
			t.Errorf("%s: %q, want %q", tt.name, got, tt.want)
		}
	}
	if got := v.denied(t, Request{CA: "issuing", Preset: "server", CSR: good, KeyAlgorithm: AlgRSA4096}); !strings.Contains(got, "brings its own key") {
		t.Errorf("CSR with key algorithm: %q", got)
	}
	// Windows certreq writes "NEW CERTIFICATE REQUEST".
	v.issue(t, Request{CA: "issuing", Preset: "server", CSR: pem.EncodeToMemory(&pem.Block{Type: "NEW CERTIFICATE REQUEST", Bytes: block.Bytes})})
}

func TestKeyPolicyAndWarnings(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.chain(t, caOpts{})
	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	tests := []struct {
		key    crypto.Signer
		preset string
		alg    string
		warn   string
	}{
		{rsa2048, "server", AlgRSA2048, "compatibility only"},
		{ed, "server", AlgEd25519, "rejected by browsers"},
		{ed, "client", AlgEd25519, ""},
		{mustKey(t, elliptic.P521()), "server", AlgECDSAP521, "rejected by Chrome"},
		{mustKey(t, elliptic.P521()), "client", AlgECDSAP521, ""},
		{mustKey(t, elliptic.P384()), "server", AlgECDSAP384, ""},
	}
	for _, tt := range tests {
		csr := makeCSR(t, tt.key, &x509.CertificateRequest{DNSNames: []string{"a.homelab.lan"}, Subject: pkix.Name{CommonName: "a"}})
		out := v.issue(t, Request{CA: "issuing", Preset: tt.preset, CSR: csr})
		w := strings.Join(out.Warnings, "|")
		if out.KeyAlgorithm != tt.alg || (tt.warn == "") != (w == "") || !strings.Contains(w, tt.warn) {
			t.Errorf("%s/%s: alg %s, warnings %q", tt.alg, tt.preset, out.KeyAlgorithm, w)
		}
	}

	// Exponent 3 and oversized keys are refused by the policy itself.
	n := new(big.Int).Lsh(big.NewInt(1), 2047)
	if _, err := keyAlgorithm(&rsa.PublicKey{N: n, E: 3}); err == nil || !strings.Contains(err.Error(), "exponent 3") {
		t.Errorf("e=3: %v", err)
	}
	if _, err := keyAlgorithm(&rsa.PublicKey{N: new(big.Int).Lsh(n, 8192), E: 65537}); err == nil {
		t.Error("RSA with more than 8192 bits accepted")
	}
}

func TestServerSideKeyGeneration(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.chain(t, caOpts{})
	out := v.issue(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"a.homelab.lan"}})
	if out.KeyAlgorithm != AlgECDSAP256 || out.KeyID == "" {
		t.Fatalf("default key: %+v", out)
	}
	stored, err := keys.LoadKey(t.Context(), v.pki, out.KeyID)
	if err != nil || stored.Purpose != keys.PurposeLeaf {
		t.Fatal(stored, err)
	}
	cert := parse(t, out.CertDER)
	if err := unsealed.WithSigner(stored.ID, stored.Purpose, stored.Algorithm, stored.Envelope, func(s crypto.Signer) error {
		if k, ok := s.Public().(*ecdsa.PublicKey); !ok || !k.Equal(cert.PublicKey) {
			return errors.New("stored key doesn't match the certificate")
		}
		return nil
	}); err != nil {
		t.Error(err)
	}
	if rows := v.auditRows(t); rows[0].details["key_source"] != "server" {
		t.Errorf("audit %v", rows[0].details)
	}

	if out := v.issue(t, Request{CA: "issuing", Preset: "client", Subject: Subject{CommonName: "x"}, KeyAlgorithm: AlgEd25519}); out.KeyAlgorithm != AlgEd25519 {
		t.Errorf("ed25519: %s", out.KeyAlgorithm)
	}
	if got := v.denied(t, Request{CA: "issuing", Preset: "client", Subject: Subject{CommonName: "x"}, KeyAlgorithm: "dsa-1024"}); !strings.Contains(got, "can't be generated") {
		t.Errorf("unknown algorithm: %q", got)
	}
	v.keygen = false
	if got := v.denied(t, Request{CA: "issuing", Preset: "client", Subject: Subject{CommonName: "x"}}); !strings.Contains(got, "switched off") {
		t.Errorf("keygen off: %q", got)
	}
	// A CSR is always allowed.
	v.issue(t, Request{CA: "issuing", Preset: "client", CSR: makeCSR(t, mustKey(t, elliptic.P256()), &x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}})})
}

func TestNameConstraintsBeforeSigning(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.chain(t, caOpts{permitDNS: []string{"homelab.lan"}, excludeDNS: []string{"secret.homelab.lan"}, permitIP: []string{"10.0.0.0/8"}})
	tests := []struct {
		req  Request
		want string
	}{
		{Request{Preset: "server", DNSNames: []string{"evil.com"}}, `dns "evil.com" is outside the name constraints of CA "issuing" (permitted: homelab.lan)`},
		{Request{Preset: "server", DNSNames: []string{"x.secret.homelab.lan"}}, "is excluded"},
		{Request{Preset: "server", IPAddresses: []string{"192.168.1.1"}}, `ip "192.168.1.1" is outside`},
		{Request{Preset: "wildcard", DNSNames: []string{"*.homelab.lan"}}, `dns "*.homelab.lan" is excluded`}, // covers secret.homelab.lan
		{Request{Preset: "client", Subject: Subject{CommonName: "www.evil.com"}}, `common name "www.evil.com" is outside`},
		{Request{Preset: "client", Subject: Subject{CommonName: "max.mustermann"}}, `instead of "max.mustermann"), or add a DNS SAN`},
	}
	for _, tt := range tests {
		tt.req.CA = "issuing"
		if got := v.denied(t, tt.req); !strings.Contains(got, tt.want) {
			t.Errorf("%v: %q, want %q", tt.req.DNSNames, got, tt.want)
		}
	}
	v.issue(t, Request{CA: "issuing", Preset: "wildcard", DNSNames: []string{"*.apps.homelab.lan"}})
	// With a DNS SAN, clients ignore the CN (RFC 6125) – the fix the message names.
	v.issue(t, Request{CA: "issuing", Preset: "client", Subject: Subject{CommonName: "max.mustermann"}, DNSNames: []string{"laptop.homelab.lan"}})

	// Denials are audited with their reasons.
	rows := v.auditRows(t)
	if rows[0].result != "denied" || rows[0].target != "issuing" || !strings.Contains(fmt.Sprint(rows[0].details["reasons"]), "evil.com") {
		t.Errorf("audit %+v", rows[0])
	}
}

func TestNameConstraintsOfTheRootApplyToo(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	root := v.addCA(t, "root", caOpts{permitDNS: []string{"homelab.lan"}})
	v.addCA(t, "issuing", caOpts{parent: root, key: mustKey(t, elliptic.P256())})
	if got := v.denied(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"evil.com"}}); !strings.Contains(got, `CA "root"`) {
		t.Errorf("%q", got)
	}
}

// Each layer works alone: the database constraints stop a request before
// signing even if the CA certificate has none, and crypto/x509 stops a
// certificate the database check missed – then nothing is stored.
func TestNameConstraintLayers(t *testing.T) {
	t.Parallel()
	dbOnly := newEnv(t)
	dbOnly.chain(t, caOpts{dbOnlyPermitDNS: []string{"homelab.lan"}})
	dbOnly.denied(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"evil.com"}})

	certOnly := newEnv(t)
	certOnly.chain(t, caOpts{certOnlyPermitDNS: []string{"homelab.lan"}})
	_, err := certOnly.e.Issue(t.Context(), Request{CA: "issuing", Preset: "server", DNSNames: []string{"evil.com"}, Who: tester})
	if err == nil || errors.Is(err, ErrDenied) || !strings.Contains(err.Error(), "doesn't verify against its CA chain") {
		t.Fatalf("cert-only constraint: %v", err)
	}
	var n int
	if err := certOnly.pki.QueryRowContext(t.Context(), `SELECT count(*) FROM certificates`).Scan(&n); err != nil || n != 0 {
		t.Errorf("%d certificates stored after a failed check", n)
	}
	if rows := certOnly.auditRows(t); len(rows) != 1 || rows[0].result != "failure" {
		t.Errorf("audit %+v", rows)
	}
}

func TestEKULimit(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	root, issuing := v.chain(t, caOpts{ekuLimit: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	out := v.issue(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"a.homelab.lan"}})
	opensslVerify(t, []*fixtureCA{issuing, root}, out.CertDER, "sslserver")
	if got := v.denied(t, Request{CA: "issuing", Preset: "server-client", DNSNames: []string{"a.homelab.lan"}}); !strings.Contains(got, "1.3.6.1.5.5.7.3.2 is not allowed") {
		t.Errorf("clientAuth: %q", got)
	}
	if got := v.denied(t, Request{CA: "issuing", Preset: "custom", Subject: Subject{CommonName: "x"}}); !strings.Contains(got, "without EKU") {
		t.Errorf("no EKU: %q", got)
	}
}

func TestValidityRules(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.chain(t, caOpts{maxValidity: 90})
	req := Request{CA: "issuing", Preset: "server", DNSNames: []string{"a.homelab.lan"}}

	out := v.issue(t, req) // preset default 397 > 90: adapts
	if days := out.NotAfter.Sub(out.NotBefore) + time.Second; days != 90*day || !strings.Contains(strings.Join(out.Notes, "|"), "capped at the CA maximum of 90 days") {
		t.Errorf("default: %v, notes %v", days, out.Notes)
	}
	req.ValidityDays = 91 // explicit: never changed
	if got := v.denied(t, req); !strings.Contains(got, "exceeds the maximum of this CA (90 days)") {
		t.Errorf("explicit: %q", got)
	}
	req.ValidityDays = 30
	if out := v.issue(t, req); out.NotAfter.Sub(out.NotBefore)+time.Second != 30*day || len(out.Notes) != 0 {
		t.Errorf("30 days: %v %v", out.NotAfter.Sub(out.NotBefore), out.Notes)
	}

	ending := newEnv(t)
	ending.chain(t, caOpts{notAfter: t0.Add(100 * day)})
	req.ValidityDays = 200
	if got := ending.denied(t, req); !strings.Contains(got, "would end after the CA certificate") {
		t.Errorf("explicit beyond CA: %q", got)
	}
	req.ValidityDays = 0
	if out := ending.issue(t, req); !out.NotAfter.Equal(t0.Add(100*day).Truncate(time.Second)) || !strings.Contains(strings.Join(out.Notes, "|"), "shortened") {
		t.Errorf("default beyond CA: %v %v", out.NotAfter, out.Notes)
	}
}

func TestRefusedCAs(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	root := v.addCA(t, "root", caOpts{notAfter: t0.Add(10 * day)})
	v.addCA(t, "offline", caOpts{parent: root, keyMode: KeyModeOffline})
	v.addCA(t, "retired", caOpts{parent: root, status: StatusRetired})
	req := Request{Preset: "server", DNSNames: []string{"a.homelab.lan"}}
	for ca, want := range map[string]string{
		"offline": "is offline", "retired": "is retired", "nope": "no CA named", "root": "",
	} {
		req.CA = ca
		if want == "" {
			continue
		}
		if got := v.denied(t, req); !strings.Contains(got, want) {
			t.Errorf("%s: %q", ca, got)
		}
	}
	req.CA, req.Preset = "root", "nope"
	if got := v.denied(t, req); !strings.Contains(got, "no preset named") {
		t.Errorf("preset: %q", got)
	}
	req.Preset = "server"
	v.clk.Advance(11 * day)
	if got := v.denied(t, req); !strings.Contains(got, "is not valid now") {
		t.Errorf("expired CA: %q", got)
	}
}

func TestSealedServerFailsAndIsAudited(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.chain(t, caOpts{})
	v.e.Keys = keys.New(nil, nil, v.clk) // never unsealed
	_, err := v.e.Issue(t.Context(), Request{CA: "issuing", Preset: "server", DNSNames: []string{"a.homelab.lan"}, Who: tester})
	if !errors.Is(err, keys.ErrSealed) {
		t.Fatalf("sealed: %v", err)
	}
	rows := v.auditRows(t)
	if len(rows) != 1 || rows[0].result != "failure" || !strings.Contains(fmt.Sprint(rows[0].details["error"]), "sealed") {
		t.Errorf("audit %+v", rows)
	}
}

func TestSubjectRules(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.chain(t, caOpts{})
	long := strings.Repeat("a", 60) + ".homelab.lan" // 72 characters
	tests := []struct {
		req  Request
		want string
	}{
		{Request{Preset: "client", Subject: Subject{CommonName: strings.Repeat("x", 65)}}, "longer than 64"},
		{Request{Preset: "client", Subject: Subject{CommonName: "a", Organization: "Evil\nCorp"}}, "U+000A"},
		{Request{Preset: "client", Subject: Subject{CommonName: "admin" + string(rune(0x202e)) + "gnp.exe"}}, "U+202E"},
		{Request{Preset: "client", Subject: Subject{CommonName: "a", Country: "DEU"}}, "two-letter"},
		{Request{Preset: "codesign"}, "needs a common name or at least one subject alternative name"},
		{Request{Preset: "server", DNSNames: []string{"a.homelab.lan"}, EmailAddresses: []string{"a@homelab.lan"}}, "doesn't take email names"},
		{Request{Preset: "smime", Subject: Subject{CommonName: "Felix"}}, "needs at least one name of type email"},
	}
	for _, tt := range tests {
		tt.req.CA = "issuing"
		if got := v.denied(t, tt.req); !strings.Contains(got, tt.want) {
			t.Errorf("%+v: %q, want %q", tt.req.Subject, got, tt.want)
		}
	}

	// A derived CN that is too long is left out, not cut; the SAN carries
	// the name, and with an empty subject the SAN extension is critical.
	out := v.issue(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{long}})
	cert := parse(t, out.CertDER)
	san, _ := findExt(cert, oidSAN)
	if cert.Subject.CommonName != "" || len(cert.Subject.Names) != 0 || !san.Critical || !strings.Contains(strings.Join(out.Notes, "|"), "no common name") {
		t.Errorf("CN %q, subject %v, SAN critical %v, notes %v", cert.Subject.CommonName, cert.Subject, san.Critical, out.Notes)
	}
	out = v.issue(t, Request{CA: "issuing", Preset: "client", Subject: Subject{CommonName: " Felix ", Country: "de", Organization: "Homelab"}})
	if s := parse(t, out.CertDER).Subject.String(); s != "CN=Felix,O=Homelab,C=DE" {
		t.Errorf("subject %s", s)
	}
}

func TestWildcardRules(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.chain(t, caOpts{})
	for req, want := range map[string]Request{
		"needs the wildcard preset": {Preset: "server", DNSNames: []string{"*.homelab.lan"}},
		"too broad":                 {Preset: "wildcard", DNSNames: []string{"*.lan"}},
		"needs a wildcard name":     {Preset: "wildcard", DNSNames: []string{"homelab.lan"}},
		"only allowed as the whole": {Preset: "wildcard", DNSNames: []string{"*.*.homelab.lan"}},
	} {
		want.CA = "issuing"
		if got := v.denied(t, want); !strings.Contains(got, req) {
			t.Errorf("%v: %q, want %q", want.DNSNames, got, req)
		}
	}
	out := v.issue(t, Request{CA: "issuing", Preset: "wildcard", Subject: Subject{CommonName: "*.homelab.lan"}})
	if cert := parse(t, out.CertDER); !slices.Equal(cert.DNSNames, []string{"*.homelab.lan", "homelab.lan"}) || cert.Subject.CommonName != "*.homelab.lan" {
		t.Errorf("DNS %v CN %q", cert.DNSNames, cert.Subject.CommonName)
	}
}

func TestCSRNamesAreAWishList(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.chain(t, caOpts{permitDNS: []string{"homelab.lan"}})
	csr := makeCSR(t, mustKey(t, elliptic.P256()), &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: "laptop", Organization: []string{"CSR Org"}, SerialNumber: "123"},
		IPAddresses: []net.IP{net.ParseIP("10.0.0.1")},
		DNSNames:    []string{"evil.com"},
	})
	// client takes dns and email: the CSR's IP is dropped with a note, its
	// DNS name is checked like any other – and violates the constraints.
	if got := v.denied(t, Request{CA: "issuing", Preset: "client", CSR: csr}); !strings.Contains(got, "evil.com") {
		t.Errorf("%q", got)
	}
	// The dropped IP is reported in the audit entry of the denial, too.
	if rows := v.auditRows(t); fmt.Sprint(rows[0].details["dropped_csr_names"]) != "[ip:10.0.0.1]" {
		t.Errorf("denied audit %v", rows[0].details)
	}
	out := v.issue(t, Request{CA: "issuing", Preset: "client", CSR: csr, IgnoreCSRNames: true, Subject: Subject{CommonName: "laptop-02"}})
	cert := parse(t, out.CertDER)
	if cert.Subject.String() != "CN=laptop-02" || len(cert.DNSNames)+len(cert.IPAddresses) != 0 {
		t.Errorf("IgnoreCSRNames: subject %s, names %v %v", cert.Subject, cert.DNSNames, cert.IPAddresses)
	}
	csr = makeCSR(t, mustKey(t, elliptic.P256()), &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "laptop", Organization: []string{"CSR Org"}, SerialNumber: "123"}, IPAddresses: []net.IP{net.ParseIP("10.0.0.1")},
	})
	out = v.issue(t, Request{CA: "issuing", Preset: "client", CSR: csr})
	cert = parse(t, out.CertDER)
	if cert.Subject.String() != "CN=laptop,O=CSR Org" || len(cert.IPAddresses) != 0 || !strings.Contains(strings.Join(out.Notes, "|"), "ignored 1 ip name(s)") {
		t.Errorf("subject %s (serialNumber must be dropped), IPs %v, notes %v", cert.Subject, cert.IPAddresses, out.Notes)
	}
	if !slices.Equal(out.DroppedCSRNames, []string{"ip:10.0.0.1"}) {
		t.Errorf("dropped names in the result: %v", out.DroppedCSRNames)
	}
	rows := v.auditRows(t)
	if last := rows[len(rows)-1]; last.result != "success" || fmt.Sprint(last.details["dropped_csr_names"]) != "[ip:10.0.0.1]" {
		t.Errorf("success audit %v", last.details)
	}
}

func TestCustomUsages(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.chain(t, caOpts{})
	out := v.issue(t, Request{CA: "issuing", Preset: "custom", Subject: Subject{CommonName: "tsa"}, CustomKeyUsage: []string{"digitalSignature", "nonRepudiation"}, CustomExtKeyUsage: []string{"timeStamping"}})
	cert := parse(t, out.CertDER)
	if eku, _ := findExt(cert, oidExtKeyUsage); !eku.Critical {
		t.Error("custom timeStamping EKU must be critical")
	}
	row, _ := pkidb.New(v.pki).GetCertificate(t.Context(), out.ID)
	if row.CustomKu.String != "digitalSignature,nonRepudiation" || row.CustomEku.String != "timeStamping" {
		t.Errorf("stored custom usages %q %q", row.CustomKu.String, row.CustomEku.String)
	}
	for want, req := range map[string]Request{
		"fixed key usages":    {Preset: "server", DNSNames: []string{"a.homelab.lan"}, CustomExtKeyUsage: []string{"clientAuth"}},
		"needs an RSA key":    {Preset: "custom", Subject: Subject{CommonName: "x"}, CustomKeyUsage: []string{"keyEncipherment"}},
		"reserved for CA":     {Preset: "custom", Subject: Subject{CommonName: "x"}, CustomKeyUsage: []string{"keyCertSign"}},
		"anyExtendedKeyUsage": {Preset: "custom", Subject: Subject{CommonName: "x"}, CustomKeyUsage: []string{"digitalSignature"}, CustomExtKeyUsage: []string{"2.5.29.37.0"}},
	} {
		req.CA = "issuing"
		if got := v.denied(t, req); !strings.Contains(got, want) {
			t.Errorf("%q, want %q", got, want)
		}
	}
}

func TestRefusalAuditStaysSmall(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.chain(t, caOpts{permitDNS: []string{"homelab.lan"}})
	var names []string
	for i := range 80 {
		names = append(names, fmt.Sprintf("host-%02d-%s.example.com", i, strings.Repeat("x", 40)))
	}
	v.denied(t, Request{CA: "issuing", Preset: "server", DNSNames: names})
	rows := v.auditRows(t)
	if r, ok := rows[0].details["reasons"].([]any); !ok || len(r) != 11 || !strings.Contains(fmt.Sprint(r[10]), "and 70 more") {
		t.Errorf("reasons %v", r)
	}
	if rows[0].result != string(audit.ResultDenied) {
		t.Error(rows[0])
	}
}

// TestRefusedNameHasNoEcho: once a name is refused, "needs at least one
// name" would only repeat it (owner 2026-10-17); without any name it stays.
func TestRefusedNameHasNoEcho(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.chain(t, caOpts{})
	got := v.denied(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"*.lan"}})
	if strings.Contains(got, "needs at least one name") || got == "" {
		t.Errorf("refused wildcard: %q", got)
	}
	got = v.denied(t, Request{CA: "issuing", Preset: "wildcard", DNSNames: []string{"*.*.homelab.lan"}})
	if strings.Contains(got, "needs a wildcard name") {
		t.Errorf("refused wildcard name: %q", got)
	}
	if got := v.denied(t, Request{CA: "issuing", Preset: "server", Subject: Subject{CommonName: "not a host name"}}); !strings.Contains(got, "needs at least one name of type dns or ip") {
		t.Errorf("no name at all: %q", got)
	}
}
