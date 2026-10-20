package web

import (
	"crypto/x509"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/Der-Felix/MyOwnPKI/internal/ca/preset"
	"github.com/Der-Felix/MyOwnPKI/internal/web/pages/certificates"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

// Extensions as the certificate carries them, in their order – read from the
// signed certificate, not from the preset.

var extNames = map[string]string{
	"2.5.29.19":            "Basic constraints",
	"2.5.29.15":            "Key usage",
	"2.5.29.37":            "Extended key usage",
	"2.5.29.17":            "Subject alternative name",
	"2.5.29.14":            "Subject key identifier",
	"2.5.29.35":            "Authority key identifier",
	"1.3.6.1.5.5.7.1.1":    "Authority information access",
	"2.5.29.31":            "CRL distribution points",
	"2.5.29.30":            "Name constraints",
	"2.5.29.32":            "Certificate policies",
	"1.3.6.1.5.5.7.48.1.5": "OCSP no check",
}

var keyUsageNames = []struct {
	bit  x509.KeyUsage
	name string
}{
	{x509.KeyUsageDigitalSignature, "digitalSignature"}, {x509.KeyUsageContentCommitment, "contentCommitment"},
	{x509.KeyUsageKeyEncipherment, "keyEncipherment"}, {x509.KeyUsageDataEncipherment, "dataEncipherment"},
	{x509.KeyUsageKeyAgreement, "keyAgreement"}, {x509.KeyUsageCertSign, "keyCertSign"}, {x509.KeyUsageCRLSign, "cRLSign"},
	{x509.KeyUsageEncipherOnly, "encipherOnly"}, {x509.KeyUsageDecipherOnly, "decipherOnly"},
}

var extKeyUsageNames = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny: "any", x509.ExtKeyUsageServerAuth: "serverAuth", x509.ExtKeyUsageClientAuth: "clientAuth",
	x509.ExtKeyUsageCodeSigning: "codeSigning", x509.ExtKeyUsageEmailProtection: "emailProtection",
	x509.ExtKeyUsageTimeStamping: "timeStamping", x509.ExtKeyUsageOCSPSigning: "OCSPSigning",
	x509.ExtKeyUsageIPSECEndSystem: "ipsecEndSystem", x509.ExtKeyUsageIPSECTunnel: "ipsecTunnel", x509.ExtKeyUsageIPSECUser: "ipsecUser",
}

func extensionRows(c *x509.Certificate) []certificates.ExtRow {
	rows := make([]certificates.ExtRow, 0, len(c.Extensions))
	for _, e := range c.Extensions {
		oid := e.Id.String()
		name, ok := extNames[oid]
		if !ok {
			name = "Other extension"
		}
		rows = append(rows, certificates.ExtRow{Name: name, OID: oid, Critical: e.Critical, Value: extensionValue(c, oid, len(e.Value))})
	}
	return rows
}

func extensionValue(c *x509.Certificate, oid string, size int) string {
	switch oid {
	case "2.5.29.19":
		if !c.IsCA {
			return "CA:FALSE"
		}
		if c.MaxPathLen >= 0 && (c.MaxPathLen > 0 || c.MaxPathLenZero) {
			return "CA:TRUE, pathlen:" + strconv.Itoa(c.MaxPathLen)
		}
		return "CA:TRUE"
	case "2.5.29.15":
		var out []string
		for _, k := range keyUsageNames {
			if c.KeyUsage&k.bit != 0 {
				out = append(out, k.name)
			}
		}
		return strings.Join(out, ", ")
	case "2.5.29.37":
		var out []string
		for _, u := range c.ExtKeyUsage {
			out = append(out, extKeyUsageNames[u])
		}
		for _, o := range c.UnknownExtKeyUsage {
			if n := preset.ExtKeyUsageName(o); n != "" {
				out = append(out, n)
			} else {
				out = append(out, o.String())
			}
		}
		return strings.Join(out, ", ")
	case "2.5.29.17":
		var out []string
		for _, n := range c.DNSNames {
			out = append(out, "DNS:"+n)
		}
		for _, ip := range c.IPAddresses {
			out = append(out, "IP:"+ip.String())
		}
		for _, m := range c.EmailAddresses {
			out = append(out, "email:"+m)
		}
		for _, u := range c.URIs {
			out = append(out, "URI:"+u.String())
		}
		return strings.Join(out, ", ")
	case "2.5.29.14":
		return view.ColonHex(hex.EncodeToString(c.SubjectKeyId))
	case "2.5.29.35":
		return view.ColonHex(hex.EncodeToString(c.AuthorityKeyId))
	case "1.3.6.1.5.5.7.1.1":
		var out []string
		for _, u := range c.IssuingCertificateURL {
			out = append(out, "CA issuers: "+u)
		}
		for _, u := range c.OCSPServer {
			out = append(out, "OCSP: "+u)
		}
		return strings.Join(out, ", ")
	case "2.5.29.31":
		return strings.Join(c.CRLDistributionPoints, ", ")
	case "2.5.29.30":
		var out []string
		for _, d := range c.PermittedDNSDomains {
			out = append(out, "permitted DNS:"+d)
		}
		for _, n := range c.PermittedIPRanges {
			out = append(out, "permitted IP:"+n.String())
		}
		for _, d := range c.ExcludedDNSDomains {
			out = append(out, "excluded DNS:"+d)
		}
		for _, n := range c.ExcludedIPRanges {
			out = append(out, "excluded IP:"+n.String())
		}
		return strings.Join(out, ", ")
	case "2.5.29.32":
		var out []string
		for _, p := range c.Policies {
			out = append(out, p.String())
		}
		return strings.Join(out, ", ")
	case "1.3.6.1.5.5.7.48.1.5":
		return "NULL – clients don't check this responder certificate's revocation"
	}
	return strconv.Itoa(size) + " bytes"
}
