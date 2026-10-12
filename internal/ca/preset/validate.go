package preset

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
)

// Limits for validity_days. The upper bound is a sanity check, not a policy:
// the longest built-in preset (timestamp) uses 1825 days.
const (
	minValidityDays = 1
	maxValidityDays = 3650
)

var namePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

var families = []Family{
	FamilyServer, FamilyVPNServer, FamilyClient, FamilyCodeSign,
	FamilyOCSP, FamilyTimestamp, FamilyCustom,
}

var sanTypes = []SANType{SANDNS, SANIP, SANEmail, SANURI}

// validate checks the preset and fills the resolved fields. It returns one
// human-readable line per problem, so an admin sees everything at once.
func (p *Preset) validate() []string {
	var problems []string
	fail := func(field, format string, args ...any) {
		problems = append(problems, field+": "+fmt.Sprintf(format, args...))
	}

	if !namePattern.MatchString(p.Name) {
		fail("name", "%q must be lower-case letters, digits and '-', starting with a letter", p.Name)
	}
	if strings.TrimSpace(p.Description) == "" {
		fail("description", "must not be empty")
	}
	if !slices.Contains(families, p.Family) {
		fail("family", "%q is not one of %s", p.Family, joinQuoted(families))
	}
	if p.ValidityDays < minValidityDays || p.ValidityDays > maxValidityDays {
		fail("validity_days", "must be between %d and %d, got %d", minValidityDays, maxValidityDays, p.ValidityDays)
	}
	if p.Customizable && p.Family != FamilyCustom {
		fail("customizable", "only allowed for family %q", FamilyCustom)
	}

	p.keyUsageRSA = resolveKeyUsages("key_usage.rsa", p.KeyUsage.RSA, true, fail)
	p.keyUsageOther = resolveKeyUsages("key_usage.other", p.KeyUsage.Other, false, fail)
	p.resolveExtKeyUsages(fail)
	p.validateSANs(fail)
	p.validateCrossRules(fail)
	return problems
}

type failFunc func(field, format string, args ...any)

func resolveKeyUsages(field string, names []string, rsa bool, fail failFunc) x509.KeyUsage {
	if len(names) == 0 {
		fail(field, "must list at least one key usage")
		return 0
	}
	var ku x509.KeyUsage
	seen := map[string]bool{}
	for _, name := range names {
		switch {
		case seen[name]:
			fail(field, "%q is listed twice", name)
		case caKeyUsages[name]:
			fail(field, "%q is reserved for CA certificates; presets describe end-entity certificates", name)
		case unsupportedKeyUsages[name] != "":
			fail(field, "%q is not supported: %s", name, unsupportedKeyUsages[name])
		case keyUsageByName[name] == 0:
			fail(field, "unknown key usage %q (known: %s)", name, joinQuoted(slices.Sorted(maps.Keys(keyUsageByName))))
		case !rsa && rsaOnlyKeyUsages[name]:
			fail(field, "%q needs an RSA key – ECDSA and Ed25519 keys can only sign, not encrypt", name)
		default:
			ku |= keyUsageByName[name]
		}
		seen[name] = true
	}
	return ku
}

func (p *Preset) resolveExtKeyUsages(fail failFunc) {
	const field = "ext_key_usage.usages"
	usages := p.ExtKeyUsage.Usages
	if len(usages) == 0 && !p.Customizable {
		fail(field, "must list at least one extended key usage (only customizable presets may leave it empty)")
	}
	seen := map[string]bool{}
	for _, token := range usages {
		oid, err := lookupExtKeyUsage(token)
		if err != nil {
			fail(field, "%v", err)
			continue
		}
		if seen[oid.String()] {
			fail(field, "%q is listed twice", token)
			continue
		}
		seen[oid.String()] = true
		p.extKeyUsageAll = append(p.extKeyUsageAll, oid)
		if std, ok := extKeyUsageStd[token]; ok {
			p.extKeyUsageStd = append(p.extKeyUsageStd, std)
		} else {
			p.extKeyUsageRest = append(p.extKeyUsageRest, oid)
		}
	}
}

// lookupExtKeyUsage resolves an EKU name or dotted OID. Well-known EKUs must be
// written by name, so the same usage can't appear in two spellings.
func lookupExtKeyUsage(token string) (asn1.ObjectIdentifier, error) {
	if oid, ok := extKeyUsageOID[token]; ok {
		return oid, nil
	}
	oid, ok := parseOID(token)
	if !ok {
		return nil, fmt.Errorf("unknown extended key usage %q (known: %s, or a dotted OID)",
			token, joinQuoted(slices.Sorted(maps.Keys(extKeyUsageOID))))
	}
	if oid.Equal(oidAnyExtendedKeyUsage) {
		return nil, fmt.Errorf("anyExtendedKeyUsage (%s) is not allowed: it would make the certificate valid for every purpose", token)
	}
	for name, known := range extKeyUsageOID {
		if oid.Equal(known) {
			return nil, fmt.Errorf("write %q instead of the OID %s", name, token)
		}
	}
	return oid, nil
}

func (p *Preset) validateSANs(fail failFunc) {
	r := p.SubjectAltNames
	checkList := func(field string, list []SANType) {
		seen := map[SANType]bool{}
		for _, t := range list {
			if !slices.Contains(sanTypes, t) {
				fail(field, "unknown SAN type %q (known: %s)", t, joinQuoted(sanTypes))
			} else if seen[t] {
				fail(field, "%q is listed twice", t)
			}
			seen[t] = true
		}
	}
	checkList("subject_alt_names.required_any_of", r.RequiredAnyOf)
	checkList("subject_alt_names.offered", r.Offered)

	for _, t := range r.RequiredAnyOf {
		if !slices.Contains(r.Offered, t) {
			fail("subject_alt_names.required_any_of", "%q is required but not in offered", t)
		}
	}
	switch p.CommonNameFrom {
	case "":
	case SANDNS, SANEmail:
		if !slices.Contains(r.Offered, p.CommonNameFrom) {
			fail("common_name_from", "%q is not in subject_alt_names.offered", p.CommonNameFrom)
		}
	default:
		fail("common_name_from", "must be \"\", %q or %q, got %q", SANDNS, SANEmail, p.CommonNameFrom)
	}
}

// validateCrossRules checks rules that span several fields – each one encodes a
// PKI requirement, not a style preference.
func (p *Preset) validateCrossRules(fail failFunc) {
	has := func(name string) bool { return slices.Contains(p.ExtKeyUsage.Usages, name) }
	requires := func(t SANType) bool { return slices.Contains(p.SubjectAltNames.RequiredAnyOf, t) }

	// TLS clients match host names only against SANs (RFC 6125, CA/B Forum BR).
	if has("serverAuth") && !requires(SANDNS) && !requires(SANIP) {
		fail("subject_alt_names.required_any_of", "serverAuth certificates need a DNS or IP SAN – clients ignore the CN")
	}
	// S/MIME: mail clients find and check the address in the SAN (RFC 8550).
	if has("emailProtection") && !requires(SANEmail) {
		fail("subject_alt_names.required_any_of", "emailProtection certificates need an e-mail SAN")
	}
	// RFC 3161 §2.3: a TSA certificate has exactly one EKU, timeStamping, marked critical.
	if has("timeStamping") && (len(p.ExtKeyUsage.Usages) != 1 || !p.ExtKeyUsage.Critical) {
		fail("ext_key_usage", "timeStamping must be the only extended key usage and critical: true (RFC 3161)")
	}
	// id-pkix-ocsp-nocheck only makes sense on a delegated OCSP responder certificate.
	if p.OCSPNoCheck && !has("OCSPSigning") {
		fail("ocsp_no_check", "only allowed together with the OCSPSigning extended key usage")
	}
	if want, ok := opensslPurposeEKU[p.OpenSSLPurpose]; !ok {
		fail("openssl_purpose", "unknown purpose %q (known: %s)", p.OpenSSLPurpose,
			joinQuoted(slices.Sorted(maps.Keys(opensslPurposeEKU))))
	} else if want != "" && !has(want) {
		fail("openssl_purpose", "%q needs the %s extended key usage", p.OpenSSLPurpose, want)
	}
}

func joinQuoted[T ~string](list []T) string {
	quoted := make([]string, len(list))
	for i, s := range list {
		quoted[i] = fmt.Sprintf("%q", s)
	}
	return strings.Join(quoted, ", ")
}
