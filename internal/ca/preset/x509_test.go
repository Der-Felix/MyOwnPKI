package preset

import (
	"bytes"
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
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/testutil"
)

// These tests issue throw-away certificates with the extensions of every
// built-in preset and check them twice: by parsing with crypto/x509, and –
// when OpenSSL is on the PATH – with `openssl verify -purpose`, the same check
// legacy `pki verify` runs. They prove that the preset data means to OpenSSL
// what we think it means. This is test code only; the CA engine comes in phase 1.

var (
	oidExtKeyUsage    = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidKeyUsage       = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidBasicConstr    = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidOCSPNoCheck    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}
	testRSAKeyOnce    sync.Once
	testRSAKey        *rsa.PrivateKey
	errTestRSAKeyInit error
)

// rsaTestKey is generated once: RSA key generation is slow.
func rsaTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	testRSAKeyOnce.Do(func() { testRSAKey, errTestRSAKeyInit = rsa.GenerateKey(rand.Reader, 2048) })
	if errTestRSAKeyInit != nil {
		t.Fatal(errTestRSAKeyInit)
	}
	return testRSAKey
}

type testCA struct {
	cert *x509.Certificate
	key  crypto.Signer
	pem  []byte
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "MyOwnPKI Test Root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// issue builds a leaf the way a CA engine following the preset would.
func (ca *testCA) issue(t *testing.T, p *Preset, pub crypto.PublicKey, alg x509.PublicKeyAlgorithm) (*x509.Certificate, []byte) {
	t.Helper()
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "test " + p.Name},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  false,
		KeyUsage:              p.KeyUsageFor(alg),
	}
	for _, san := range p.SubjectAltNames.Offered {
		switch san {
		case SANDNS:
			tmpl.DNSNames = []string{"test.example"}
		case SANIP:
			tmpl.IPAddresses = []net.IP{net.ParseIP("192.0.2.10")}
		case SANEmail:
			tmpl.EmailAddresses = []string{"user@example.com"}
		case SANURI: // not needed for these checks
		}
	}
	if p.ExtKeyUsage.Critical {
		// crypto/x509 always writes EKU as non-critical, so build it by hand.
		value, err := asn1.Marshal(p.ExtKeyUsageOIDs())
		if err != nil {
			t.Fatal(err)
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{Id: oidExtKeyUsage, Critical: true, Value: value})
	} else {
		tmpl.ExtKeyUsage, tmpl.UnknownExtKeyUsage = p.ExtKeyUsages()
	}
	if p.OCSPNoCheck {
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{Id: oidOCSPNoCheck, Value: asn1.NullBytes})
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

type testKey struct {
	name string
	alg  x509.PublicKeyAlgorithm
	pub  func(t *testing.T) crypto.PublicKey
}

var testKeys = []testKey{
	{"rsa2048", x509.RSA, func(t *testing.T) crypto.PublicKey {
		t.Helper()
		return rsaTestKey(t).Public()
	}},
	{"ecdsa-p256", x509.ECDSA, func(t *testing.T) crypto.PublicKey {
		t.Helper()
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k.Public()
	}},
	{"ed25519", x509.Ed25519, func(t *testing.T) crypto.PublicKey {
		t.Helper()
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return pub
	}},
}

func findExt(cert *x509.Certificate, oid asn1.ObjectIdentifier) (pkix.Extension, bool) {
	for _, e := range cert.Extensions {
		if e.Id.Equal(oid) {
			return e, true
		}
	}
	return pkix.Extension{}, false
}

func TestPresetCertificates(t *testing.T) {
	t.Parallel()
	set, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	ca := newTestCA(t)

	for _, name := range set.Names() {
		p, _ := set.Get(name)
		for _, k := range testKeys {
			t.Run(name+"/"+k.name, func(t *testing.T) {
				t.Parallel()
				cert, certPEM := ca.issue(t, p, k.pub(t), k.alg)

				if cert.KeyUsage != p.KeyUsageFor(k.alg) {
					t.Errorf("KeyUsage = %b, want %b", cert.KeyUsage, p.KeyUsageFor(k.alg))
				}
				if ku, ok := findExt(cert, oidKeyUsage); !ok || !ku.Critical {
					t.Error("keyUsage must be present and critical (RFC 5280 §4.2.1.3)")
				}
				if bc, ok := findExt(cert, oidBasicConstr); !ok || !bc.Critical || cert.IsCA {
					t.Error("basicConstraints must be critical CA:FALSE")
				}
				if k.alg != x509.RSA && cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
					t.Error("non-RSA key must not have keyEncipherment")
				}

				eku, hasEKU := findExt(cert, oidExtKeyUsage)
				if len(p.ExtKeyUsage.Usages) == 0 {
					if hasEKU {
						t.Error("unexpected extendedKeyUsage extension")
					}
				} else {
					if !hasEKU || eku.Critical != p.ExtKeyUsage.Critical {
						t.Errorf("extendedKeyUsage present=%v critical=%v, want critical=%v", hasEKU, eku.Critical, p.ExtKeyUsage.Critical)
					}
					var got []asn1.ObjectIdentifier
					if _, err := asn1.Unmarshal(eku.Value, &got); err != nil {
						t.Fatal(err)
					}
					want := p.ExtKeyUsageOIDs()
					if !slices.EqualFunc(got, want, asn1.ObjectIdentifier.Equal) {
						t.Errorf("EKU OIDs = %v, want %v", got, want)
					}
				}
				if _, ok := findExt(cert, oidOCSPNoCheck); ok != p.OCSPNoCheck {
					t.Errorf("ocsp-nocheck present = %v, want %v", ok, p.OCSPNoCheck)
				}

				opensslVerify(t, ca.pem, certPEM, p.OpenSSLPurpose, true)
			})
		}
	}
}

// TestPresetCertificatesWrongPurpose makes sure the OpenSSL check is not a
// rubber stamp: a certificate must fail purposes its preset is not made for.
func TestPresetCertificatesWrongPurpose(t *testing.T) {
	t.Parallel()
	set, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	ca := newTestCA(t)
	tests := []struct{ preset, purpose string }{
		{"client", "sslserver"},
		{"server", "sslclient"},
		{"server", "smimesign"},
		{"codesign", "sslserver"},
		{"smime", "sslclient"},
		{"vpn-client", "sslserver"},
	}
	for _, tt := range tests {
		t.Run(tt.preset+"/"+tt.purpose, func(t *testing.T) {
			t.Parallel()
			p, _ := set.Get(tt.preset)
			_, certPEM := ca.issue(t, p, testKeys[1].pub(t), x509.ECDSA)
			opensslVerify(t, ca.pem, certPEM, tt.purpose, false)
		})
	}
}

// opensslVerify runs `openssl verify -purpose` and checks the outcome.
// Skipped locally when OpenSSL 3 is not installed, fatal in CI.
func opensslVerify(t *testing.T, caPEM, certPEM []byte, purpose string, wantOK bool) {
	t.Helper()
	bin := testutil.OpenSSL(t)
	var err error
	dir := t.TempDir()
	caFile, certFile := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "leaf.pem")
	if err = os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"verify", "-CAfile", caFile}
	if purpose != "any" {
		args = append(args, "-purpose", purpose)
	}
	args = append(args, certFile)
	out, err := exec.CommandContext(t.Context(), bin, args...).CombinedOutput()
	ok := err == nil && bytes.Contains(out, []byte(": OK"))
	if ok != wantOK {
		t.Errorf("openssl verify -purpose %s: ok=%v, want %v\n%s", purpose, ok, wantOK, out)
	}
}
