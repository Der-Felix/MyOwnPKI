package trustkit

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Fixed texts of the profile. Nothing here depends on the root.
const (
	profileDescription = "Adds the root certificate of this PKI to the trusted certificates of this device. " +
		"This profile is not signed: check the SHA-256 fingerprint of the certificate against a value you got another way before you install it."
	certDescription = "Root certificate of this PKI."

	// maxDisplayName bounds the profile's display name (characters).
	maxDisplayName = 64

	// uuidDomain separates these UUIDs from any other use of SHA-256.
	uuidDomain = "myownpki trustkit configuration profile v1"
)

// MobileConfig returns the unsigned Apple configuration profile for a root:
// one Configuration dict with a single com.apple.security.root payload that
// carries the certificate. iOS, iPadOS and macOS install it from a download.
//
// The output is a pure function of the root's DER, name, generation and
// common name: no date, no host name, no serial, no private data. The
// identifiers and UUIDs derive from the certificate's SHA-256, so the same
// root always gives the same bytes and installing it again replaces the
// profile instead of adding one, while a renewed root (another certificate)
// gets other identifiers and can be installed next to the old one.
// PayloadRemovalDisallowed is false: the user can always remove it.
func MobileConfig(r Root) ([]byte, error) {
	if !ValidName(r.Name) || r.Generation < 1 {
		return nil, errors.New("trustkit: the CA name or generation is not valid for a profile")
	}
	if !validCert(r.DER) {
		return nil, errors.New("trustkit: the root certificate does not parse")
	}
	sum := sha256.Sum256(r.DER)
	fp32 := hex.EncodeToString(sum[:])[:32]
	profileID := "local.myownpki.root." + fp32
	name := displayName(r.CommonName, r.Name)

	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	b.WriteString(`<plist version="1.0">` + "\n<dict>\n")
	b.WriteString("\t<key>PayloadContent</key>\n\t<array>\n\t\t<dict>\n")
	entry := func(key, value string) {
		fmt.Fprintf(&b, "\t\t\t<key>%s</key>\n\t\t\t<string>%s</string>\n", key, xmlText(value))
	}
	entry("PayloadCertificateFileName", r.File()+".crt")
	b.WriteString("\t\t\t<key>PayloadContent</key>\n\t\t\t<data>\n")
	b.WriteString(wrapBase64(r.DER, "\t\t\t"))
	b.WriteString("\t\t\t</data>\n")
	entry("PayloadDescription", certDescription)
	entry("PayloadDisplayName", name)
	entry("PayloadIdentifier", profileID+".cert")
	entry("PayloadType", "com.apple.security.root")
	entry("PayloadUUID", uuid(sum, "certificate"))
	b.WriteString("\t\t\t<key>PayloadVersion</key>\n\t\t\t<integer>1</integer>\n")
	b.WriteString("\t\t</dict>\n\t</array>\n")
	top := func(key, value string) {
		fmt.Fprintf(&b, "\t<key>%s</key>\n\t<string>%s</string>\n", key, xmlText(value))
	}
	top("PayloadDescription", profileDescription)
	top("PayloadDisplayName", name)
	top("PayloadIdentifier", profileID)
	b.WriteString("\t<key>PayloadRemovalDisallowed</key>\n\t<false/>\n")
	top("PayloadType", "Configuration")
	top("PayloadUUID", uuid(sum, "profile"))
	b.WriteString("\t<key>PayloadVersion</key>\n\t<integer>1</integer>\n")
	b.WriteString("</dict>\n</plist>\n")
	return []byte(b.String()), nil
}

// uuid derives a UUID from the certificate's SHA-256: the first 16 bytes of
// SHA-256(domain, 0, label, 0, fingerprint), with version 8 (RFC 9562,
// custom) and the RFC 4122 variant bits set, in upper case.
func uuid(fingerprint [sha256.Size]byte, label string) string {
	h := sha256.New()
	h.Write([]byte(uuidDomain))
	h.Write([]byte{0})
	h.Write([]byte(label))
	h.Write([]byte{0})
	h.Write(fingerprint[:])
	u := h.Sum(nil)[:16]
	u[6] = u[6]&0x0f | 0x80
	u[8] = u[8]&0x3f | 0x80
	x := strings.ToUpper(hex.EncodeToString(u))
	return x[0:8] + "-" + x[8:12] + "-" + x[12:16] + "-" + x[16:20] + "-" + x[20:32]
}

// displayName cleans a common name for the profile's title: no control,
// format (bidi) or line characters, at most 64 characters, and the CA's name
// when nothing is left.
func displayName(cn, fallback string) string {
	var out []rune
	for _, c := range cn {
		if c == utf8.RuneError || unicode.IsControl(c) || unicode.Is(unicode.Cf, c) ||
			unicode.Is(unicode.Zl, c) || unicode.Is(unicode.Zp, c) || unicode.Is(unicode.Co, c) {
			continue
		}
		out = append(out, c)
		if len(out) == maxDisplayName {
			break
		}
	}
	s := strings.TrimSpace(string(out))
	if s == "" {
		return fallback
	}
	return s
}

// xmlText escapes text for an XML element (encoding/xml replaces characters
// XML 1.0 cannot carry). displayName has already removed control characters.
func xmlText(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// wrapBase64 encodes der as base64 in lines of 64 characters, each indented.
func wrapBase64(der []byte, indent string) string {
	enc := base64.StdEncoding.EncodeToString(der)
	var b strings.Builder
	for len(enc) > 0 {
		n := min(64, len(enc))
		b.WriteString(indent + enc[:n] + "\n")
		enc = enc[n:]
	}
	return b.String()
}
