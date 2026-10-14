package ca

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
)

// MaxCSRSize limits an uploaded CSR. Real CSRs are a few KiB; the limit keeps
// a hostile upload from costing memory and parse time.
const MaxCSRSize = 64 << 10

// parseCSR reads exactly one PEM CSR and verifies its signature before
// anything else is looked at (pki-rules.md §6): the signature proves the
// requester holds the private key. Its extensions are never used.
func parseCSR(data []byte) (*x509.CertificateRequest, error) {
	if len(data) > MaxCSRSize {
		return nil, deny("the CSR is larger than %d KiB", MaxCSRSize>>10)
	}
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, deny("no PEM block found – expected -----BEGIN CERTIFICATE REQUEST-----")
	}
	// "NEW CERTIFICATE REQUEST" is what Windows certreq writes.
	if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
		return nil, deny("PEM block %q is not a certificate request", short(block.Type))
	}
	if len(block.Headers) > 0 {
		return nil, deny("the CSR's PEM block has headers – send a plain PEM CSR")
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, deny("there is data after the CSR – send exactly one CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, deny("the CSR can't be parsed: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, deny("the CSR's signature is invalid – it was changed after signing or not signed with its key")
	}
	return csr, nil
}

// csrSubject takes the first value of each supported field from the CSR
// subject; other attributes (emailAddress, serialNumber, …) are dropped.
func csrSubject(n pkix.Name) Subject {
	first := func(v []string) string {
		if len(v) == 0 {
			return ""
		}
		return v[0]
	}
	return Subject{
		CommonName:         n.CommonName,
		Organization:       first(n.Organization),
		OrganizationalUnit: first(n.OrganizationalUnit),
		Locality:           first(n.Locality),
		Province:           first(n.Province),
		Country:            first(n.Country),
	}
}

// mergeSubject: fields given in the request win over the CSR's.
func mergeSubject(req, csr Subject) Subject {
	pick := func(a, b string) string {
		if a != "" {
			return a
		}
		return b
	}
	return Subject{
		CommonName:         pick(req.CommonName, csr.CommonName),
		Organization:       pick(req.Organization, csr.Organization),
		OrganizationalUnit: pick(req.OrganizationalUnit, csr.OrganizationalUnit),
		Locality:           pick(req.Locality, csr.Locality),
		Province:           pick(req.Province, csr.Province),
		Country:            pick(req.Country, csr.Country),
	}
}
