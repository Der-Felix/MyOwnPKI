package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/ca/preset"
)

var (
	oidExtKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
	// id-pkix-ocsp-nocheck (RFC 6960 §4.2.2.2.1): clients don't check the
	// revocation of a delegated OCSP responder certificate.
	oidOCSPNoCheck = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}
)

// serialBits: 159 random bits give a positive serial of at most 20 bytes in
// DER (RFC 5280 §4.1.2.2) with far more than the 64 bits of entropy the CA/B
// Forum requires – a serial can't be predicted, which defeats chosen-prefix
// collision attacks on the signature.
const serialBits = 159

func newSerial(rnd io.Reader) (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), serialBits)
	for {
		n, err := rand.Int(rnd, limit)
		if err != nil {
			return nil, fmt.Errorf("serial: %w", err)
		}
		if n.Sign() > 0 {
			return n, nil
		}
	}
}

// SerialHex is the stored form of a serial: upper-case hex, even length
// (like OpenSSL's index.txt).
func SerialHex(n *big.Int) string {
	s := fmt.Sprintf("%X", n)
	if len(s)%2 == 1 {
		s = "0" + s
	}
	return s
}

// subjectKeyID is RFC 7093 §2 method 1: the leftmost 160 bits of the SHA-256
// hash of the subjectPublicKey bits.
func subjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(spki.PublicKey.Bytes)
	return sum[:20], nil
}

// leaf is everything a certificate is built from – all of it checked.
type leaf struct {
	preset  *preset.Preset
	alg     string
	subject pkix.Name
	names   Names
	v       validity
	pub     crypto.PublicKey
}

// buildTemplate assembles the certificate. The extensions come only from the
// preset and the CA – never from the CSR (pki-rules.md §6).
func buildTemplate(is *issuer, l leaf, rnd io.Reader) (*x509.Certificate, error) {
	serial, err := newSerial(rnd)
	if err != nil {
		return nil, err
	}
	ski, err := subjectKeyID(l.pub)
	if err != nil {
		return nil, fmt.Errorf("subject key identifier: %w", err)
	}
	sigAlg, err := signatureAlgorithm(is.certs[0].PublicKey)
	if err != nil {
		return nil, err
	}
	gen := is.gen.Generation
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               l.subject,
		NotBefore:             l.v.notBefore,
		NotAfter:              l.v.notAfter,
		BasicConstraintsValid: true, // crypto/x509 writes it critical: CA:FALSE
		IsCA:                  false,
		KeyUsage:              l.preset.KeyUsageFor(x509Algorithm(l.alg)), // always critical
		SubjectKeyId:          ski,
		DNSNames:              l.names.DNS,
		EmailAddresses:        l.names.Emails,
		IssuingCertificateURL: []string{CertURL(is.ca.PublicBaseUrl, is.ca.Name, gen)},
		CRLDistributionPoints: []string{CRLURL(is.ca.PublicBaseUrl, is.ca.Name, gen)},
		SignatureAlgorithm:    sigAlg,
	}
	for _, ip := range l.names.IPs {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.IP(ip.AsSlice()))
	}
	for _, s := range l.names.URIs {
		u, err := url.Parse(s)
		if err != nil {
			return nil, err
		}
		tmpl.URIs = append(tmpl.URIs, u)
	}
	if l.preset.ExtKeyUsage.Critical {
		// crypto/x509 always writes EKU non-critical, so build it by hand.
		value, err := asn1.Marshal(l.preset.ExtKeyUsageOIDs())
		if err != nil {
			return nil, err
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{Id: oidExtKeyUsage, Critical: true, Value: value})
	} else {
		tmpl.ExtKeyUsage, tmpl.UnknownExtKeyUsage = l.preset.ExtKeyUsages()
	}
	if l.preset.OCSPNoCheck {
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{Id: oidOCSPNoCheck, Value: asn1.NullBytes})
	}
	return tmpl, nil
}

// checkIssued looks at the signed certificate before anything is stored or
// handed out: it must parse, be a leaf for the requested key and verify
// against the CA chain – including the name constraints and EKU limits in
// the CA certificates. A failure here is a bug, never the requester's fault.
func checkIssued(der []byte, l leaf, is *issuer, now time.Time) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("issued certificate doesn't parse: %w", err)
	}
	type equaler interface{ Equal(crypto.PublicKey) bool }
	pub, ok := l.pub.(equaler)
	switch {
	case cert.IsCA || !cert.BasicConstraintsValid:
		return nil, errors.New("issued certificate is not marked CA:FALSE")
	case !ok || !pub.Equal(cert.PublicKey):
		return nil, errors.New("issued certificate has another public key than requested")
	}
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(is.certs[len(is.certs)-1])
	for _, c := range is.certs[:len(is.certs)-1] {
		inter.AddCert(c)
	}
	usages := cert.ExtKeyUsage
	if len(usages) == 0 {
		usages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now, KeyUsages: usages}); err != nil {
		return nil, fmt.Errorf("issued certificate doesn't verify against its CA chain: %w", err)
	}
	return cert, nil
}

// sanStrings lists the names as "dns:host" etc. for the audit log, cut to a
// budget so a certificate with many long names can't exceed the entry limit.
func sanStrings(n Names, budget int) []string {
	var out []string
	used := 0
	list := n.list()
	for i, kv := range list {
		s := kv[0] + ":" + kv[1]
		if used+len(s) > budget {
			out = append(out, fmt.Sprintf("… and %d more", len(list)-i))
			break
		}
		out = append(out, s)
		used += len(s) + 3
	}
	return out
}

// joinNonEmpty is for the comma lists of custom usages (legacy cert.meta form).
func joinNonEmpty(v []string) string { return strings.Join(v, ",") }
