package preset

import (
	"crypto/x509"
	"encoding/asn1"
	"strconv"
	"strings"
)

// keyUsageByName maps the RFC 5280 / OpenSSL key usage names used in preset
// files to crypto/x509 bits. Only end-entity usages are listed: presets never
// describe CA certificates.
var keyUsageByName = map[string]x509.KeyUsage{
	"digitalSignature": x509.KeyUsageDigitalSignature,
	"nonRepudiation":   x509.KeyUsageContentCommitment, // RFC 5280 renamed it contentCommitment
	"keyEncipherment":  x509.KeyUsageKeyEncipherment,
	"dataEncipherment": x509.KeyUsageDataEncipherment,
}

// caKeyUsages may only appear in CA certificates. A leaf with keyCertSign could
// sign certificates itself (most clients would still reject it without
// basicConstraints CA:TRUE, but the intent alone is a policy violation).
var caKeyUsages = map[string]bool{
	"keyCertSign": true,
	"cRLSign":     true,
}

// rsaOnlyKeyUsages describe encryption with the subject's public key, which
// only RSA can do. ECDSA and Ed25519 keys can only sign.
var rsaOnlyKeyUsages = map[string]bool{
	"keyEncipherment":  true,
	"dataEncipherment": true,
}

// unsupportedKeyUsages are valid in RFC 5280 but not offered by presets.
// keyAgreement needs a static (EC)DH key: RSA can't do it, and the "other"
// column also covers Ed25519 keys, which can't either.
var unsupportedKeyUsages = map[string]string{
	"keyAgreement": "needs a static (EC)DH key – RSA and Ed25519 keys cannot do key agreement",
	"encipherOnly": "only meaningful together with keyAgreement",
	"decipherOnly": "only meaningful together with keyAgreement",
}

// extKeyUsageOID holds the named extended key usages accepted in preset files
// (RFC 5280 §4.2.1.12, RFC 4945 for ipsecIKE).
var extKeyUsageOID = map[string]asn1.ObjectIdentifier{
	"serverAuth":      {1, 3, 6, 1, 5, 5, 7, 3, 1},
	"clientAuth":      {1, 3, 6, 1, 5, 5, 7, 3, 2},
	"codeSigning":     {1, 3, 6, 1, 5, 5, 7, 3, 3},
	"emailProtection": {1, 3, 6, 1, 5, 5, 7, 3, 4},
	"timeStamping":    {1, 3, 6, 1, 5, 5, 7, 3, 8},
	"OCSPSigning":     {1, 3, 6, 1, 5, 5, 7, 3, 9},
	"ipsecIKE":        {1, 3, 6, 1, 5, 5, 7, 3, 17},
}

// extKeyUsageStd maps names to the crypto/x509 constants where one exists.
// Names without an entry (ipsecIKE) go into UnknownExtKeyUsage as OIDs.
var extKeyUsageStd = map[string]x509.ExtKeyUsage{
	"serverAuth":      x509.ExtKeyUsageServerAuth,
	"clientAuth":      x509.ExtKeyUsageClientAuth,
	"codeSigning":     x509.ExtKeyUsageCodeSigning,
	"emailProtection": x509.ExtKeyUsageEmailProtection,
	"timeStamping":    x509.ExtKeyUsageTimeStamping,
	"OCSPSigning":     x509.ExtKeyUsageOCSPSigning,
}

// oidAnyExtendedKeyUsage would make a certificate valid for every purpose.
var oidAnyExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37, 0}

// opensslPurposeEKU maps the purposes of `openssl verify -purpose` to the EKU
// a preset must contain for that check to pass ("" = no requirement).
var opensslPurposeEKU = map[string]string{
	"any":           "",
	"sslserver":     "serverAuth",
	"nssslserver":   "serverAuth",
	"sslclient":     "clientAuth",
	"smimesign":     "emailProtection",
	"smimeencrypt":  "emailProtection",
	"codesign":      "codeSigning",
	"ocsphelper":    "OCSPSigning",
	"timestampsign": "timeStamping",
}

// parseOID parses a dotted object identifier such as "1.3.6.1.5.5.8.2.2".
func parseOID(s string) (asn1.ObjectIdentifier, bool) {
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return nil, false
	}
	oid := make(asn1.ObjectIdentifier, 0, len(parts))
	for _, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return nil, false
		}
		n, err := strconv.ParseUint(part, 10, 31)
		if err != nil {
			return nil, false
		}
		oid = append(oid, int(n))
	}
	// X.660: the first arc is 0, 1 or 2; below 0 and 1 the second arc is at most 39.
	if oid[0] > 2 || (oid[0] < 2 && oid[1] > 39) {
		return nil, false
	}
	return oid, true
}
