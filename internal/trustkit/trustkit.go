// Package trustkit builds what the public trust portal hands to a person who
// wants to trust a root of this PKI: the configuration profile for iPhone,
// iPad and Mac and the per-platform steps and commands (v0.3.9).
//
// Everything here is a pure function of data from the database: the root's
// DER, its name, its common name and the CA's public base URL. Nothing comes
// from a request (not the User-Agent, not a query value), and nothing here
// does I/O. The package uses the standard library only and is imported by
// internal/publish; the agent does not import it.
//
// Safety rule for generated text: every variable part of a command is a hash,
// a CA name that matched [ValidName], a generation number, or a base URL
// that passed [ValidBaseURL]. Anything else removes the command instead of
// being escaped, so there is never a half-quoted command.
package trustkit

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"strconv"
	"strings"
)

// Platform names a family of devices; the page shows one block of steps per
// platform. The values are also the allow-list of the ?os= query value.
type Platform string

// The platforms with steps. [Linux] is a detection result only: both Linux
// families are shown, and it is not accepted from the query.
const (
	Windows Platform = "windows"
	MacOS   Platform = "macos"
	IOS     Platform = "ios"
	Android Platform = "android"
	Debian  Platform = "debian"
	Fedora  Platform = "fedora"
	Firefox Platform = "firefox"
	Java    Platform = "java"
	Linux   Platform = "linux"
)

// Platforms lists every platform with steps, in the order the page shows
// them.
func Platforms() []Platform {
	return []Platform{Windows, MacOS, IOS, Android, Debian, Fedora, Firefox, Java}
}

// Label is the name of the platform for people, from a fixed table.
func (p Platform) Label() string {
	switch p {
	case Windows:
		return "Windows"
	case MacOS:
		return "macOS"
	case IOS:
		return "iPhone and iPad"
	case Android:
		return "Android"
	case Debian:
		return "Debian and Ubuntu"
	case Fedora:
		return "Fedora, RHEL, Rocky and Alma"
	case Firefox:
		return "Firefox"
	case Java:
		return "Java"
	case Linux:
		return "Linux"
	}
	return ""
}

// ParsePlatform maps a query value to a platform of [Platforms]. It is a
// lookup in the allow-list: the result is never the input, and anything else
// (unknown, empty, longer than 16 bytes) gives false.
func ParsePlatform(s string) (Platform, bool) {
	if len(s) > 16 {
		return "", false
	}
	for _, p := range Platforms() {
		if string(p) == s {
			return p, true
		}
	}
	return "", false
}

// Root is one generation of a root CA as the portal knows it. All fields come
// from the database.
type Root struct {
	Name       string // the CA's name: part of every URL, [ValidName]
	Generation int64  // from 1
	Current    bool   // the current generation; older ones get a suffix in file names
	DER        []byte // the certificate
	BaseURL    string // the CA's public base URL, the one inside its certificates
	CommonName string // the certificate's common name; only ever shown as escaped text
}

// File is the base name the page uses for downloads and the commands for the
// files they create: the CA's name, with the generation appended for an older
// generation, and always the first 8 hex digits of the certificate's SHA-256.
// The suffix keeps two certificates apart that would share a base name
// otherwise: the CA "root-2" at generation 1 and the CA "root" at an older
// generation 2 are both "root-2" without it. A name that passes [ValidName]
// stays valid, so the result holds letters, digits, '.', '_' and '-' only.
func (r Root) File() string {
	base := r.Name
	if !r.Current {
		base += "-" + strconv.FormatInt(r.Generation, 10)
	}
	return base + "-" + r.SHA256()[:8]
}

// SHA256 is the lower-case hex SHA-256 of the certificate.
func (r Root) SHA256() string { return SHA256Hex(r.DER) }

// CertURL is the DER download URL of the root (the AIA caIssuers URL of its
// certificates), or false when the CA's name or base URL does not pass the
// pattern checks. Commands are only generated when it is true.
func (r Root) CertURL() (string, bool) {
	base, ok := ValidBaseURL(r.BaseURL)
	if !ok || !ValidName(r.Name) || r.Generation < 1 {
		return "", false
	}
	return base + "/ca/" + r.Name + "/" + strconv.FormatInt(r.Generation, 10) + ".crt", true
}

// SHA256Hex is the lower-case hex SHA-256 of der.
func SHA256Hex(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// ColonHex formats a hex string the way certificate dialogs show a
// fingerprint: upper case, pairs separated by colons ("AB:CD:…"). A trailing
// odd digit stays a pair of its own.
func ColonHex(hexText string) string {
	h := strings.ToUpper(hexText)
	var b strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(h[i:min(i+2, len(h))])
	}
	return b.String()
}

// ValidName reports whether s is a CA name as the CA engine accepts it:
// 1 to 63 characters of a-z, 0-9, '.', '_' and '-', starting with a letter or
// a digit. Names are part of every certificate URL, so this is also the check
// before a name enters a command or a file name.
func ValidName(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case i > 0 && (c == '.' || c == '_' || c == '-'):
		default:
			return false
		}
	}
	return true
}

// maxBaseURL bounds the length of an accepted base URL.
const maxBaseURL = 253

// ValidBaseURL applies the conservative pattern of the portal to a public
// base URL and returns it without a trailing slash: the scheme is http or
// https, the host consists of letters, digits, dots and hyphens, an optional
// port follows, and an optional path of letters, digits and "._~/-". There is
// no user name, query, fragment, space, quote, percent sign or non-ASCII
// character. Anything else gives false and the page shows no command.
func ValidBaseURL(s string) (string, bool) {
	s = strings.TrimRight(s, "/")
	if s == "" || len(s) > maxBaseURL {
		return "", false
	}
	rest, ok := strings.CutPrefix(s, "https://")
	if !ok {
		rest, ok = strings.CutPrefix(s, "http://")
	}
	if !ok || rest == "" {
		return "", false
	}
	authority, path, _ := strings.Cut(rest, "/")
	host, port, hasPort := strings.Cut(authority, ":")
	if host == "" || host[0] == '.' || host[0] == '-' || strings.Contains(host, "..") {
		return "", false
	}
	for i := range len(host) {
		c := host[i]
		if !alnum(c) && c != '.' && c != '-' {
			return "", false
		}
	}
	if hasPort {
		n, err := strconv.Atoi(port)
		if err != nil || port == "" || len(port) > 5 || n < 1 || n > 65535 {
			return "", false
		}
		for i := range len(port) {
			if port[i] < '0' || port[i] > '9' {
				return "", false // no sign or space that Atoi would accept
			}
		}
	}
	for i := range len(path) {
		c := path[i]
		if !alnum(c) && !strings.ContainsRune("._~/-", rune(c)) {
			return "", false
		}
	}
	if strings.Contains(path, "..") {
		return "", false
	}
	return s, true
}

// alnum reports whether c is an ASCII letter or digit.
func alnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// validCert reports whether der parses as a certificate.
func validCert(der []byte) bool {
	_, err := x509.ParseCertificate(der)
	return err == nil
}
