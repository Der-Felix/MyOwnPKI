// Package legacytest writes a small directory in the format of
// legacy/pki.sh with Go only – for tests that must run without bash and
// OpenSSL (Windows, macOS). The real pki.sh fixture is in internal/ca.
package legacytest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// BaseURL is AIA_BASE_URL of the fixture.
const BaseURL = "http://pki.homelab.example"

// Fixture describes what Write made.
type Fixture struct {
	Dir string
	// Serials of the leaves under "issuing": nas (valid, with key) and old
	// (revoked as superseded at RevokedAt).
	NAS, Old  string
	RevokedAt time.Time
	// NextCRL is crlnumber of "issuing" (the CRL there has NextCRL-1).
	NextCRL int64
}

type ca struct {
	cert *x509.Certificate
	key  crypto.Signer
	dir  string
}

// Write builds root + intermediate "issuing" + two leaves at now.
func Write(t *testing.T, dir string, now time.Time) Fixture {
	t.Helper()
	now = now.UTC().Truncate(time.Second)
	f := Fixture{Dir: dir, NextCRL: 0x1003, RevokedAt: now.Add(-time.Hour)}
	write := func(name string, data []byte) {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	certPEM := func(c *x509.Certificate) []byte {
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	keyPEM := func(k crypto.Signer) []byte {
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	}
	newKey := func(c elliptic.Curve) crypto.Signer {
		k, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	serial := func() *big.Int {
		n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 159))
		if err != nil {
			t.Fatal(err)
		}
		return n.Add(n, big.NewInt(1))
	}
	sign := func(tmpl *x509.Certificate, parent *ca, pub crypto.PublicKey, key crypto.Signer) *x509.Certificate {
		p, signer := tmpl, key
		if parent != nil {
			p, signer = parent.cert, parent.key
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, p, pub, signer)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	hexSerial := func(n *big.Int) string {
		s := fmt.Sprintf("%X", n)
		if len(s)%2 == 1 {
			s = "0" + s
		}
		return s
	}
	asn1Time := func(t time.Time) string { return t.UTC().Format("060102150405Z") }
	indexLine := func(c *x509.Certificate, revoked string) string {
		status := "V"
		if revoked != "" {
			status = "R"
		}
		return strings.Join([]string{status, asn1Time(c.NotAfter), revoked, hexSerial(c.SerialNumber), "unknown", "/CN=" + c.Subject.CommonName}, "\t") + "\n"
	}

	write("pki.conf", []byte("PKI_ORG=\"Homelab\"\nCRL_DAYS=\"30\"\nAIA_BASE_URL=\""+BaseURL+"\"\n"))

	// Root.
	rk := newKey(elliptic.P384())
	root := &ca{key: rk, dir: "root"}
	root.cert = sign(&x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: "Fixture Legacy Root", Organization: []string{"Homelab"}},
		NotBefore: now.Add(-48 * time.Hour), NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, nil, rk.Public(), rk)

	// Intermediate, signed by the root.
	ik := newKey(elliptic.P384())
	inter := &ca{key: ik, dir: "intermediate/issuing"}
	inter.cert = sign(&x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: "Fixture Legacy Issuing", Organization: []string{"Homelab"}},
		NotBefore: now.Add(-47 * time.Hour), NotAfter: now.AddDate(5, 0, 0), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature, PermittedDNSDomains: []string{"homelab.example"},
		CRLDistributionPoints: []string{BaseURL + "/root.crl"}, IssuingCertificateURL: []string{BaseURL + "/root.crt"},
	}, root, ik.Public(), nil)

	leaf := func(cn string, ip string) (*x509.Certificate, crypto.Signer) {
		k := newKey(elliptic.P256())
		tmpl := &x509.Certificate{
			SerialNumber: serial(), Subject: pkix.Name{CommonName: cn, Organization: []string{"Homelab"}},
			NotBefore: now.Add(-24 * time.Hour), NotAfter: now.AddDate(0, 0, 300), DNSNames: []string{cn},
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			CRLDistributionPoints: []string{BaseURL + "/issuing.crl"}, IssuingCertificateURL: []string{BaseURL + "/issuing.crt"},
		}
		if ip != "" {
			tmpl.IPAddresses = []net.IP{net.ParseIP(ip)}
		}
		return sign(tmpl, inter, k.Public(), nil), k
	}
	nas, nasKey := leaf("nas.homelab.example", "192.0.2.10")
	old, _ := leaf("old.homelab.example", "")
	f.NAS, f.Old = hexSerial(nas.SerialNumber), hexSerial(old.SerialNumber)

	crl := func(c *ca, number int64, revoked []x509.RevocationListEntry) []byte {
		der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
			Number: big.NewInt(number), ThisUpdate: now.Add(-30 * time.Minute), NextUpdate: now.AddDate(0, 0, 30),
			RevokedCertificateEntries: revoked,
		}, c.cert, c.key)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
	}

	for _, c := range []*ca{root, inter} {
		write(c.dir+"/certs/ca.crt", certPEM(c.cert))
		write(c.dir+"/private/ca.key", keyPEM(c.key))
		write(c.dir+"/ca.meta", []byte(fmt.Sprintf("NAME=%q\nCN=%q\n", filepath.Base(c.dir), c.cert.Subject.CommonName)))
	}
	write("root/index.txt", []byte(indexLine(inter.cert, "")))
	write("root/newcerts/"+hexSerial(inter.cert.SerialNumber)+".pem", certPEM(inter.cert))
	write("root/crlnumber", []byte("1001\n"))
	write("root/crl/ca.crl", crl(root, 0x1000, nil))

	write("intermediate/issuing/index.txt", []byte(indexLine(nas, "")+indexLine(old, asn1Time(f.RevokedAt)+",superseded")))
	for _, c := range []*x509.Certificate{nas, old} {
		write("intermediate/issuing/newcerts/"+hexSerial(c.SerialNumber)+".pem", certPEM(c))
	}
	write("intermediate/issuing/crlnumber", []byte(fmt.Sprintf("%X\n", f.NextCRL)))
	write("intermediate/issuing/crl/ca.crl", crl(inter, f.NextCRL-1, []x509.RevocationListEntry{
		{SerialNumber: old.SerialNumber, RevocationTime: f.RevokedAt, ReasonCode: 4},
	}))

	write("issued/nas.homelab.example/cert.pem", certPEM(nas))
	write("issued/nas.homelab.example/key.pem", keyPEM(nasKey))
	write("issued/nas.homelab.example/cert.meta", []byte("PRESET=\"server\"\nNAME=\"nas.homelab.example\"\nCA=\"issuing\"\nSERIAL=\""+f.NAS+"\"\n"))
	return f
}
