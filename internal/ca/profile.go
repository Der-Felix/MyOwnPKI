package ca

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/Der-Felix/MyOwnPKI/internal/ca/preset"
)

// Defaults for new CAs (owner decisions 2026-10-14, step 8 e).
const (
	DefaultCAKeyAlgorithm      = AlgECDSAP384
	DefaultRootDays            = 7300 // like legacy ROOT_DAYS
	DefaultIntermediateDays    = 3650 // like legacy INTERMEDIATE_DAYS
	DefaultCRLDaysOfflineRoot  = 180  // re-signed offline
	DefaultCRLDaysOnlineRoot   = 30
	DefaultCRLDaysIntermediate = 7 // renewed by the server
	DefaultMaxValidityDays     = 397
	maxCADays                  = 10950 // 30 years: a sanity bound, not a policy
)

// CAAlgorithms are the key algorithms for CAs MyOwnPKI creates. RSA 2048 and
// P-521 are only accepted (with a warning) for imported CAs; Ed25519 chains
// aren't accepted by browsers and Windows, so never for a CA.
var CAAlgorithms = []string{AlgECDSAP384, AlgECDSAP256, AlgRSA3072, AlgRSA4096}

var caNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// checkCAName: the name is part of every AIA/CRL URL and never changes.
func checkCAName(name string) error {
	if !caNamePattern.MatchString(name) {
		return fmt.Errorf("CA name %q: want 1-63 characters a-z, 0-9, '.', '_', '-', starting with a letter or digit – it becomes part of every certificate URL and can never change", short(name))
	}
	return nil
}

// checkBaseURL normalizes the public base URL (no trailing slash) and warns
// about choices that stay in every certificate (PHASE1 notes, step 7/8).
func checkBaseURL(s string) (string, []string, error) {
	s = strings.TrimRight(strings.TrimSpace(s), "/")
	u, err := url.Parse(s)
	switch {
	case s == "":
		return "", nil, fmt.Errorf("the public base URL is required – CRL and CA certificate URLs are built from it")
	case err != nil || !isASCII(s) || strings.ContainsAny(s, " \t"):
		return "", nil, fmt.Errorf("public base URL %q is not a valid URL", short(s))
	case u.Scheme != "http" && u.Scheme != "https":
		return "", nil, fmt.Errorf("public base URL %q: want http:// (recommended) or https://", short(s))
	case u.Host == "" || u.Hostname() == "":
		return "", nil, fmt.Errorf("public base URL %q has no host name", short(s))
	case u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery:
		return "", nil, fmt.Errorf("public base URL %q must not contain a user name, query or fragment", short(s))
	}
	var warnings []string
	if port := u.Port(); port != "" && (u.Scheme != "http" || port != "80") && (u.Scheme != "https" || port != "443") {
		warnings = append(warnings, fmt.Sprintf("the base URL uses port %s – it stays in every certificate until it expires; publish CRLs on the standard port (80) instead, e.g. behind a reverse proxy", port))
	}
	if u.Scheme == "https" {
		warnings = append(warnings, "the base URL uses https – RFC 5280 recommends http for CRL and AIA: a client that needs the CRL to check the TLS certificate of the CRL server is stuck")
	}
	return s, warnings, nil
}

// checkCASubject: a CA needs a CN; the other rules are those of leaves.
func checkCASubject(s Subject) (Subject, []string) {
	out, problems := checkSubject(s)
	switch {
	case out.CommonName == "":
		problems = append(problems, "a CA needs a common name")
	case utf8.RuneCountInString(out.CommonName) > maxCommonName:
		problems = append(problems, fmt.Sprintf("the common name is longer than %d characters (RFC 5280)", maxCommonName))
	}
	return out, problems
}

func (s Subject) pkix() (n pkix.Name) {
	n.CommonName = s.CommonName
	set := func(dst *[]string, v string) {
		if v != "" {
			*dst = []string{v}
		}
	}
	set(&n.Organization, s.Organization)
	set(&n.OrganizationalUnit, s.OrganizationalUnit)
	set(&n.Locality, s.Locality)
	set(&n.Province, s.Province)
	set(&n.Country, s.Country)
	return n
}

// caKeyWarnings applies the CA key policy to an imported CA key.
func importedCAKey(alg string) ([]string, error) {
	switch alg {
	case AlgEd25519:
		return nil, fmt.Errorf("an Ed25519 CA is not accepted – browsers and Windows don't verify Ed25519 chains")
	case AlgRSA2048:
		return []string{"RSA 2048 is weak for a CA that lives for years – plan its replacement (BSI TR-02102 recommends at least 3000 bits)"}, nil
	case AlgECDSAP521:
		return []string{"P-521 is rejected by Chrome in TLS chains – certificates below this CA may not work in browsers"}, nil
	}
	return nil, nil
}

// NameConstraints limit the names a CA may issue for (RFC 5280 §4.2.1.10).
// DNS and URI values: "example.com" covers the domain and everything below
// it, ".example.com" only what is below. IP values are CIDR prefixes (IPv4
// and IPv6). E-mail values: a mailbox, a host or ".domain".
type NameConstraints struct {
	PermittedDNS, ExcludedDNS     []string
	PermittedIP, ExcludedIP       []string
	PermittedEmail, ExcludedEmail []string
	PermittedURI, ExcludedURI     []string
	// NotCritical writes the extension non-critical – a compatibility switch
	// for old clients; RFC 5280 requires critical.
	NotCritical bool
}

// checkedNC are validated constraints in canonical form.
type checkedNC struct {
	rows     []constraint // for ca_name_constraints
	critical bool
}

func checkNameConstraints(nc NameConstraints) (checkedNC, []string) {
	out := checkedNC{critical: !nc.NotCritical}
	var problems []string
	add := func(kind string, values []string, permitted bool, check func(string) (string, error)) {
		for _, v := range values {
			c, err := check(strings.TrimSpace(v))
			if err != nil {
				problems = append(problems, fmt.Sprintf("name constraint %s %q: %v", kind, short(v), err))
				continue
			}
			row := constraint{kind: kind, value: c, permitted: permitted}
			if !slices.Contains(out.rows, row) {
				out.rows = append(out.rows, row)
			}
		}
	}
	add("dns", nc.PermittedDNS, true, ncDomain)
	add("dns", nc.ExcludedDNS, false, ncDomain)
	add("ip", nc.PermittedIP, true, ncPrefix)
	add("ip", nc.ExcludedIP, false, ncPrefix)
	add("email", nc.PermittedEmail, true, ncEmail)
	add("email", nc.ExcludedEmail, false, ncEmail)
	add("uri", nc.PermittedURI, true, ncDomain)
	add("uri", nc.ExcludedURI, false, ncDomain)
	return out, problems
}

func ncDomain(v string) (string, error) {
	base := strings.TrimPrefix(v, ".")
	d, err := checkDNSName(base, false)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(v, ".") {
		return "." + d, nil
	}
	return d, nil
}

func ncPrefix(v string) (string, error) {
	p, err := netip.ParsePrefix(v)
	if err != nil {
		return "", fmt.Errorf("want a CIDR prefix like 10.0.0.0/8 or fd00::/8")
	}
	if p.Masked() != p {
		return "", fmt.Errorf("host bits are set – did you mean %s?", p.Masked())
	}
	return p.String(), nil
}

func ncEmail(v string) (string, error) {
	if strings.Contains(v, "@") {
		return checkEmail(v)
	}
	return ncDomain(v)
}

// apply writes the constraints into a CA certificate template.
func (c checkedNC) apply(tmpl *x509.Certificate) {
	for _, r := range c.rows {
		switch r.kind {
		case "dns":
			appendTo(&tmpl.PermittedDNSDomains, &tmpl.ExcludedDNSDomains, r)
		case "email":
			appendTo(&tmpl.PermittedEmailAddresses, &tmpl.ExcludedEmailAddresses, r)
		case "uri":
			appendTo(&tmpl.PermittedURIDomains, &tmpl.ExcludedURIDomains, r)
		case "ip":
			p := netip.MustParsePrefix(r.value)
			n := &net.IPNet{IP: net.IP(p.Addr().AsSlice()), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
			if r.permitted {
				tmpl.PermittedIPRanges = append(tmpl.PermittedIPRanges, n)
			} else {
				tmpl.ExcludedIPRanges = append(tmpl.ExcludedIPRanges, n)
			}
		}
	}
	tmpl.PermittedDNSDomainsCritical = c.critical && len(c.rows) > 0
}

func appendTo(permitted, excluded *[]string, r constraint) {
	if r.permitted {
		*permitted = append(*permitted, r.value)
	} else {
		*excluded = append(*excluded, r.value)
	}
}

// fromCert reads the constraints of a CA certificate in the same canonical
// form – to compare an offline-signed certificate with the order.
func ncFromCert(cert *x509.Certificate) checkedNC {
	var c checkedNC
	add := func(kind string, values []string, permitted bool) {
		for _, v := range values {
			c.rows = append(c.rows, constraint{kind: kind, value: strings.ToLower(v), permitted: permitted})
		}
	}
	add("dns", cert.PermittedDNSDomains, true)
	add("dns", cert.ExcludedDNSDomains, false)
	add("email", cert.PermittedEmailAddresses, true)
	add("email", cert.ExcludedEmailAddresses, false)
	add("uri", cert.PermittedURIDomains, true)
	add("uri", cert.ExcludedURIDomains, false)
	for _, n := range cert.PermittedIPRanges {
		c.rows = append(c.rows, constraint{kind: "ip", value: ipNetString(n), permitted: true})
	}
	for _, n := range cert.ExcludedIPRanges {
		c.rows = append(c.rows, constraint{kind: "ip", value: ipNetString(n), permitted: false})
	}
	c.critical = cert.PermittedDNSDomainsCritical
	return c
}

func ipNetString(n *net.IPNet) string {
	addr, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return n.String()
	}
	ones, _ := n.Mask.Size()
	return netip.PrefixFrom(addr.Unmap(), ones).String()
}

// sameConstraints compares two constraint sets regardless of order.
func sameConstraints(a, b checkedNC) bool {
	if len(a.rows) != len(b.rows) || (len(a.rows) > 0 && a.critical != b.critical) {
		return false
	}
	for _, r := range a.rows {
		if !slices.Contains(b.rows, r) {
			return false
		}
	}
	return true
}

// checkEKULimit resolves the EKU limit of a new CA (names or OIDs).
func resolveEKULimit(tokens []string) ([]asn1.ObjectIdentifier, []string) {
	var oids []asn1.ObjectIdentifier
	var problems []string
	for _, t := range tokens {
		oid, err := preset.LookupExtKeyUsage(strings.TrimSpace(t))
		if err != nil {
			problems = append(problems, "EKU limit: "+err.Error())
			continue
		}
		if !slices.ContainsFunc(oids, oid.Equal) {
			oids = append(oids, oid)
		}
	}
	return oids, problems
}

// applyEKU writes the EKU limit into a CA certificate template.
func applyEKU(tmpl *x509.Certificate, oids []asn1.ObjectIdentifier) {
	for _, oid := range oids {
		if std, ok := preset.StdExtKeyUsage(oid); ok {
			tmpl.ExtKeyUsage = append(tmpl.ExtKeyUsage, std)
		} else {
			tmpl.UnknownExtKeyUsage = append(tmpl.UnknownExtKeyUsage, oid)
		}
	}
}

// certEKUs returns every EKU of a certificate as OIDs.
func certEKUs(cert *x509.Certificate) ([]asn1.ObjectIdentifier, bool) {
	var oids []asn1.ObjectIdentifier
	for _, e := range cert.Extensions {
		if e.Id.Equal(oidExtKeyUsage) {
			if _, err := asn1.Unmarshal(e.Value, &oids); err != nil {
				return nil, false
			}
		}
	}
	return oids, true
}

func sameOIDs(a, b []asn1.ObjectIdentifier) bool {
	if len(a) != len(b) {
		return false
	}
	for _, o := range a {
		if !slices.ContainsFunc(b, o.Equal) {
			return false
		}
	}
	return true
}

func oidStrings(oids []asn1.ObjectIdentifier) []string {
	out := make([]string, len(oids))
	for i, o := range oids {
		out[i] = o.String()
	}
	return out
}

// acceptedSignature lists the signature algorithms a CA certificate may
// carry: SHA-2 with RSA (PKCS #1 v1.5 or PSS) or ECDSA, and Ed25519. SHA-1
// and MD5 are forgeable (SHAttered, 2017); DSA and anything unknown are
// refused as well.
func acceptedSignature(a x509.SignatureAlgorithm) bool {
	switch a {
	case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
		x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS,
		x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512, x509.PureEd25519:
		return true
	default:
		return false
	}
}
