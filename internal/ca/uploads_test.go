package ca

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// testCRL creates a signed CRL (DER) of a fresh CA.
func testCRL(t *testing.T) []byte {
	t.Helper()
	key := mustKey(t, elliptic.P256())
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		NotBefore: t0.Add(-time.Hour), NotAfter: t0.AddDate(1, 0, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: t0, NextUpdate: t0.AddDate(0, 0, 7),
		RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: big.NewInt(77), RevocationTime: t0}},
	}, issuer, key)
	if err != nil {
		t.Fatal(err)
	}
	return crl
}

// Found by fuzzing: pem.Decode skips a block it can't decode and returns the next one, so a broken block in
// front of a good one was accepted although the upload holds two blocks.
func TestUploadWithABrokenFirstBlock(t *testing.T) {
	t.Parallel()
	key := mustKey(t, elliptic.P256())
	csr := makeCSR(t, key, &x509.CertificateRequest{DNSNames: []string{"a.homelab.lan"}})
	certDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(5), NotBefore: t0, NotAfter: t0.AddDate(1, 0, 0), DNSNames: []string{"a.homelab.lan"}},
		&x509.Certificate{Subject: pkix.Name{CommonName: "issuer"}}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	crl := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: testCRL(t)})

	broken := func(typ string) []byte {
		return []byte("-----BEGIN " + typ + "-----\n!!!!\n-----END " + typ + "-----\n")
	}
	if _, err := parseCSR(csr); err != nil {
		t.Fatalf("the plain CSR: %v", err)
	}
	if _, err := parseOneCertificate(cert); err != nil {
		t.Fatalf("the plain certificate: %v", err)
	}
	if _, err := crlDER(crl); err != nil {
		t.Fatalf("the plain CRL: %v", err)
	}
	if _, err := parseCSR(append(broken("CERTIFICATE REQUEST"), csr...)); err == nil || !strings.Contains(err.Error(), "more than one PEM block") {
		t.Errorf("CSR: %v", err)
	}
	if _, err := parseOneCertificate(append(broken("CERTIFICATE"), cert...)); err == nil || !strings.Contains(err.Error(), "more than one PEM block") {
		t.Errorf("certificate: %v", err)
	}
	if _, err := crlDER(append(broken("X509 CRL"), crl...)); err == nil || !strings.Contains(err.Error(), "more than one PEM block") {
		t.Errorf("CRL: %v", err)
	}
	// Text in front of the block stays fine: `openssl req -text` writes it.
	if _, err := parseCSR(append([]byte("Certificate Request:\n  Data:\n"), csr...)); err != nil {
		t.Errorf("CSR with text in front: %v", err)
	}
}
