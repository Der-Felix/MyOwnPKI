package ca

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/ca/preset"
)

// Names of the checks of a plan, in the order they run. The first six are
// gates: they end the plan at their first problem, exactly as they end an
// issuance. The last five are collected: each one reports every problem it
// finds, and all of them run before the request is refused.
const (
	CheckACMEOrder   = "acme-order"       // gate (ACME orders only): the order and its domains
	CheckPreset      = "preset"           // gate: the preset exists
	CheckCA          = "ca"               // gate: the CA exists, is active, online and not a root
	CheckCAValidity  = "ca-validity"      // gate: every CA certificate up to the root is valid now
	CheckKey         = "key"              // gate: key policy, CSR, blocked keys, server-side generation
	CheckUsages      = "usages"           // gate: custom key usages
	CheckNames       = "names"            // collected: subject and names, the preset's name rules
	CheckConstraints = "name-constraints" // collected: the name constraints of every CA up to the root
	CheckEKULimit    = "eku-limit"        // collected: the EKU limits of every CA up to the root
	CheckValidity    = "validity"         // collected: the requested or default lifetime
	CheckRenewal     = "renewal"          // collected: the certificate to renew exists
)

var checkTitles = map[string]string{
	CheckACMEOrder:   "ACME order and domains",
	CheckPreset:      "Preset",
	CheckCA:          "Issuing CA",
	CheckCAValidity:  "CA certificates valid now",
	CheckKey:         "Key",
	CheckUsages:      "Key usages",
	CheckNames:       "Subject and names",
	CheckConstraints: "Name constraints",
	CheckEKULimit:    "Extended key usage limits",
	CheckValidity:    "Validity",
	CheckRenewal:     "Certificate to renew",
}

// Check is one step of the policy and what it found. The refusal reasons of an
// issuance are the problems of its checks, concatenated in order: a preview
// shows the very list that a refused issuance returns.
type Check struct {
	Name string // one of the Check… constants
	// Problems are the reasons this check refuses the request; empty = passed.
	// They may contain requested names – escape them on output.
	Problems []string
	// Collected: the check gathers every problem it finds in one pass, so
	// Problems is complete. A check that is not collected is a gate: it ended
	// the plan at its first problem, as it ends an issuance, and the checks
	// after it did not run.
	Collected bool
}

// Title is a short human name for the check.
func (c Check) Title() string {
	if t, ok := checkTitles[c.Name]; ok {
		return t
	}
	return c.Name
}

// reasons concatenates the problems of all checks: the reasons of a refusal.
func (p *planned) reasons() []string {
	var out []string
	for _, c := range p.checks {
		out = append(out, c.Problems...)
	}
	return out
}

// Plan is what issuing a request would produce, decided by the same code that
// issues (Engine.plan) and without writing, signing or drawing any randomness.
// It is a forecast, not a promise: the checks run again when the certificate is
// issued, and the clock and the CA may have changed by then.
//
// A refused plan carries the reasons; the fields that describe the certificate
// are filled as far as the plan got (Names, Subject, CA and Chain as soon as
// they are known; validity, usages, extensions and URLs only for an allowed
// plan).
type Plan struct {
	// GeneratedAt is the engine clock when the plan was made, UTC. NotBefore of
	// an issuance a moment later is this time minus the backdate (5 minutes).
	GeneratedAt time.Time
	// Allowed: the policy would issue. A sealed keyring does not change it; see Sealed.
	Allowed bool
	// Reasons are the refusal reasons, in the order issuance gives them: the
	// problems of Checks, concatenated.
	Reasons []string
	// Checks are the checks that ran, in order. Each one says whether it is
	// Collected (every problem found) or a gate (the first problem only).
	Checks []Check
	// StoppedAt names the gate that ended the plan early ("" = every check ran).
	// A refusal at a gate can hide problems of later checks until it is fixed.
	StoppedAt string
	// Sealed: the key ring is sealed, so issuing fails until an admin unseals
	// it. Issuance returns keys.ErrSealed; a plan records it and goes on.
	Sealed bool

	CA              string // name of the CA that would sign
	Generation      int64  // its current generation (the CA key)
	MaxValidityDays int    // the CA's maximum validity
	// Domains are the domains an ACME order's names lie in (the rule that
	// applied); empty for every other path.
	Domains           []string
	Preset            string
	PresetDescription string

	Subject         Subject
	SubjectDN       string // as stored in certificates.subject_dn
	Names           []PlanName
	DroppedCSRNames []string // "type:value" names of the CSR the preset doesn't take
	KeyAlgorithm    string
	KeySource       string // "csr" or "server"

	NotBefore, NotAfter time.Time
	Days                int

	KeyUsage            []string // names, e.g. digitalSignature
	ExtKeyUsage         []string // names or dotted OIDs
	ExtKeyUsageCritical bool
	Extensions          []ExtensionInfo
	AIAURL, CDPURL      string // baked into the certificate, never changeable
	// Chain lists the issuing CA first and the root last.
	Chain []ChainLink

	Notes    []string
	Warnings []string
}

// PlanName is one subject alternative name.
type PlanName struct{ Type, Value string }

// ExtensionInfo describes one extension of the certificate to be issued.
type ExtensionInfo struct {
	OID      string
	Name     string
	Critical bool
	Detail   string
}

// ChainLink is one CA certificate on the way to the root.
type ChainLink struct {
	CA       string // CA name
	Subject  string
	SHA256   string // upper-case hex of the DER certificate
	NotAfter time.Time
	Root     bool
}

// Plan decides what Issue would do with req, without doing it: no row, no
// audit entry (not even a denied one), no key, no serial, no randomness. A
// policy refusal is a Plan with Allowed false and every reason. An error means
// the plan could not be made – the requester may not issue on that CA (a
// *DeniedError with a Cause, as Issue returns it) or something failed. A
// sealed key ring is no error: it is recorded in Plan.Sealed.
func (e *Engine) Plan(ctx context.Context, req Request) (*Plan, error) {
	now := e.Clock.Now().UTC().Truncate(time.Second)
	p, err := e.plan(ctx, req, now, false)
	if err != nil {
		var d *DeniedError
		if !errors.As(err, &d) || d.Cause != nil {
			return nil, err
		}
	}
	return describePlan(p, now, err == nil)
}

func describePlan(p *planned, now time.Time, allowed bool) (*Plan, error) {
	out := &Plan{
		GeneratedAt: now, Allowed: allowed, Reasons: p.reasons(), Checks: cloneChecks(p.checks),
		StoppedAt: p.stopped, Sealed: p.sealed, Domains: append([]string(nil), p.req.acmeDomains...),
		Notes: append([]string(nil), p.notes...), DroppedCSRNames: append([]string(nil), p.dropped...),
	}
	l := p.l
	if is := p.is; is != nil {
		out.CA, out.Generation, out.MaxValidityDays = is.ca.Name, is.gen.Generation, int(is.ca.MaxValidityDays)
		for i, c := range is.certs {
			sum := sha256.Sum256(c.Raw)
			out.Chain = append(out.Chain, ChainLink{
				CA: is.constraints[i].ca, Subject: c.Subject.String(), SHA256: strings.ToUpper(hex.EncodeToString(sum[:])),
				NotAfter: c.NotAfter, Root: i == len(is.certs)-1,
			})
		}
	}
	if l.preset != nil {
		out.Preset, out.PresetDescription = l.preset.Name, l.preset.Description
	}
	if l.alg != "" {
		out.KeyAlgorithm, out.KeySource = l.alg, "server"
		if p.csr != nil {
			out.KeySource = "csr"
		}
	}
	if l.preset != nil {
		for _, kv := range l.names.list() {
			out.Names = append(out.Names, PlanName{Type: kv[0], Value: kv[1]})
		}
		out.Subject = Subject{
			CommonName: l.subject.CommonName, Organization: first(l.subject.Organization),
			OrganizationalUnit: first(l.subject.OrganizationalUnit), Locality: first(l.subject.Locality),
			Province: first(l.subject.Province), Country: first(l.subject.Country),
		}
		out.SubjectDN = l.subject.ToRDNSequence().String()
	}
	if !allowed {
		return out, nil
	}

	out.NotBefore, out.NotAfter, out.Days = l.v.notBefore, l.v.notAfter, l.v.days
	out.Warnings = keyWarnings(l.alg, l.preset)
	tmpl, err := buildTemplate(p.is, l)
	if err != nil {
		return nil, err
	}
	out.KeyUsage = keyUsageNames(tmpl.KeyUsage)
	oids, critical := extKeyUsages(tmpl)
	for _, oid := range oids {
		out.ExtKeyUsage = append(out.ExtKeyUsage, ekuName(oid))
	}
	out.ExtKeyUsageCritical = critical
	out.Extensions = describeExtensions(tmpl, p.is)
	out.AIAURL = strings.Join(tmpl.IssuingCertificateURL, ", ")
	out.CDPURL = strings.Join(tmpl.CRLDistributionPoints, ", ")
	return out, nil
}

func cloneChecks(in []Check) []Check {
	out := make([]Check, len(in))
	for i, c := range in {
		out[i] = Check{Name: c.Name, Problems: append([]string(nil), c.Problems...), Collected: c.Collected}
	}
	return out
}

func first(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

var (
	oidSubjectKeyIDExt    = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidAuthorityKeyIDExt  = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidSubjectAltNameExt  = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidAuthorityInfoExt   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
	oidCRLDistributionExt = asn1.ObjectIdentifier{2, 5, 29, 31}
)

// keyUsageBits lists the key usage names in bit order (RFC 5280 §4.2.1.3).
var keyUsageBits = []struct {
	bit  x509.KeyUsage
	name string
}{
	{x509.KeyUsageDigitalSignature, "digitalSignature"},
	{x509.KeyUsageContentCommitment, "nonRepudiation"},
	{x509.KeyUsageKeyEncipherment, "keyEncipherment"},
	{x509.KeyUsageDataEncipherment, "dataEncipherment"},
	{x509.KeyUsageKeyAgreement, "keyAgreement"},
	{x509.KeyUsageCertSign, "keyCertSign"},
	{x509.KeyUsageCRLSign, "cRLSign"},
	{x509.KeyUsageEncipherOnly, "encipherOnly"},
	{x509.KeyUsageDecipherOnly, "decipherOnly"},
}

func keyUsageNames(ku x509.KeyUsage) []string {
	var out []string
	for _, b := range keyUsageBits {
		if ku&b.bit != 0 {
			out = append(out, b.name)
		}
	}
	return out
}

// extKeyUsages returns the EKU OIDs of the template in the order crypto/x509
// writes them (the known ones, then the others) and whether the extension is
// critical (only where the preset says so; crypto/x509 can't write it, so the
// template carries it as an extra extension).
func extKeyUsages(tmpl *x509.Certificate) ([]asn1.ObjectIdentifier, bool) {
	for _, ext := range tmpl.ExtraExtensions {
		if ext.Id.Equal(oidExtKeyUsage) {
			var oids []asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(ext.Value, &oids); err != nil {
				return nil, ext.Critical
			}
			return oids, ext.Critical
		}
	}
	var oids []asn1.ObjectIdentifier
	for _, u := range tmpl.ExtKeyUsage {
		oids = append(oids, stdExtKeyUsageOID(u))
	}
	return append(oids, tmpl.UnknownExtKeyUsage...), false
}

// stdExtKeyUsageOID maps a crypto/x509 constant back to its OID with the
// preset package's own tables; nil for a usage no preset can ask for.
func stdExtKeyUsageOID(u x509.ExtKeyUsage) asn1.ObjectIdentifier {
	for _, name := range []string{"serverAuth", "clientAuth", "codeSigning", "emailProtection", "timeStamping", "OCSPSigning"} {
		if oid, err := preset.LookupExtKeyUsage(name); err == nil {
			if s, ok := preset.StdExtKeyUsage(oid); ok && s == u {
				return oid
			}
		}
	}
	return nil
}

// ekuName is the name of a well-known EKU, else the dotted OID.
func ekuName(oid asn1.ObjectIdentifier) string {
	if oid == nil {
		return "unknown"
	}
	if n := preset.ExtKeyUsageName(oid); n != "" {
		return n
	}
	return oid.String()
}

// describeExtensions lists the extensions the certificate built from tmpl will
// carry: it formats the template that commit signs and invents nothing, so the
// preview can't promise an extension the engine doesn't write. A test compares
// the list with the extensions of a really issued certificate. The serial
// number is not an extension and not known yet.
func describeExtensions(tmpl *x509.Certificate, is *issuer) []ExtensionInfo {
	var out []ExtensionInfo
	add := func(oid asn1.ObjectIdentifier, name string, critical bool, detail string) {
		out = append(out, ExtensionInfo{OID: oid.String(), Name: name, Critical: critical, Detail: detail})
	}
	if tmpl.BasicConstraintsValid {
		detail := "CA:FALSE"
		if tmpl.IsCA {
			detail = "CA:TRUE"
		}
		add(oidBasicConstraints, "basicConstraints", true, detail) // crypto/x509 writes it critical
	}
	if tmpl.KeyUsage != 0 {
		add(oidKeyUsageExt, "keyUsage", true, strings.Join(keyUsageNames(tmpl.KeyUsage), ", ")) // always critical
	}
	if oids, critical := extKeyUsages(tmpl); len(oids) > 0 {
		names := make([]string, len(oids))
		for i, oid := range oids {
			names[i] = ekuName(oid)
		}
		add(oidExtKeyUsage, "extKeyUsage", critical, strings.Join(names, ", "))
	}
	if len(tmpl.SubjectKeyId) > 0 {
		add(oidSubjectKeyIDExt, "subjectKeyIdentifier", false, strings.ToUpper(hex.EncodeToString(tmpl.SubjectKeyId)))
	} else {
		add(oidSubjectKeyIDExt, "subjectKeyIdentifier", false, "derived from the new key (RFC 7093)")
	}
	if ski := is.certs[0].SubjectKeyId; len(ski) > 0 {
		add(oidAuthorityKeyIDExt, "authorityKeyIdentifier", false, strings.ToUpper(hex.EncodeToString(ski)))
	}
	if n := len(tmpl.DNSNames) + len(tmpl.IPAddresses) + len(tmpl.EmailAddresses) + len(tmpl.URIs); n > 0 {
		// crypto/x509 marks the extension critical when the subject is empty (RFC 5280 §4.2.1.6).
		add(oidSubjectAltNameExt, "subjectAltName", len(tmpl.Subject.ToRDNSequence()) == 0, fmt.Sprintf("%d name(s)", n))
	}
	if len(tmpl.IssuingCertificateURL)+len(tmpl.OCSPServer) > 0 {
		add(oidAuthorityInfoExt, "authorityInfoAccess", false, "caIssuers "+strings.Join(tmpl.IssuingCertificateURL, ", "))
	}
	if len(tmpl.CRLDistributionPoints) > 0 {
		add(oidCRLDistributionExt, "cRLDistributionPoints", false, strings.Join(tmpl.CRLDistributionPoints, ", "))
	}
	for _, ext := range tmpl.ExtraExtensions {
		switch {
		case ext.Id.Equal(oidExtKeyUsage): // listed above
		case ext.Id.Equal(oidOCSPNoCheck):
			add(oidOCSPNoCheck, "id-pkix-ocsp-nocheck", ext.Critical, "clients don't check the revocation of this responder certificate")
		default:
			add(ext.Id, "other", ext.Critical, "")
		}
	}
	return out
}
