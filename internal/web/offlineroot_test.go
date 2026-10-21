package web

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
)

// offlineRoot plays legacy/pki.sh as the offline root in UI tests.
type offlineRoot struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
}

func newOfflineRoot(t *testing.T, now time.Time) *offlineRoot {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "Homelab Offline Root", Organization: []string{"Homelab"}},
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(10, 0, 0)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &offlineRoot{cert: cert, key: key, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

// sign signs the bundle's CSR with what its extension file orders.
func (o *offlineRoot) sign(t *testing.T, b *ca.OfflineBundle, now time.Time) string {
	t.Helper()
	block, _ := pem.Decode(b.CSRPEM)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := new(big.Int).SetString(b.Serial, 16)
	var aia, cdp string
	for _, l := range strings.Split(b.ExtConfig, "\n") {
		if v, ok := strings.CutPrefix(l, "authorityInfoAccess    = caIssuers;URI:"); ok {
			aia = v
		}
		if v, ok := strings.CutPrefix(l, "crlDistributionPoints  = URI:"); ok {
			cdp = v
		}
	}
	tmpl := &x509.Certificate{SerialNumber: serial, RawSubject: csr.RawSubject, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Duration(b.Days) * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IssuingCertificateURL: []string{aia}, CRLDistributionPoints: []string{cdp}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, o.cert, csr.PublicKey, o.key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// crl is the root's first CRL.
func (o *offlineRoot) crl(t *testing.T, now time.Time) string {
	t.Helper()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.AddDate(0, 0, 30)}, o.cert, o.key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}))
}
