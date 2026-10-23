package ca

import (
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Der-Felix/MyOwnPKI/internal/ca/preset"
)

// Every name in a request is attacker input (CSR, API, ACME). These checks
// accept only what a certificate should contain, in one canonical spelling,
// and say exactly what is wrong otherwise.

const (
	maxDNSName = 253 // RFC 1035
	maxLabel   = 63
	maxEmail   = 254 // RFC 5321 path limit
	maxLocal   = 64
	maxURI     = 2048
	maxSANs    = 100
)

// checkDNSName returns the canonical (lower-case) form of a DNS SAN. A
// wildcard is only allowed as the whole leftmost label and needs at least two
// labels behind it.
func checkDNSName(s string, allowWildcard bool) (string, error) {
	if s == "" {
		return "", fmt.Errorf("empty DNS name")
	}
	if !isASCII(s) {
		return "", fmt.Errorf("DNS name %q contains non-ASCII characters – write internationalized names in their xn-- (punycode) form", short(s))
	}
	name := strings.ToLower(s)
	if len(name) > maxDNSName {
		return "", fmt.Errorf("DNS name %q is longer than %d characters", short(s), maxDNSName)
	}
	if strings.HasSuffix(name, ".") {
		return "", fmt.Errorf("DNS name %q must not end with a dot", short(s))
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return "", fmt.Errorf("%q is an IP address – request it as an IP SAN, not as a DNS name", name)
	}
	labels := strings.Split(name, ".")
	if labels[0] == "*" {
		if !allowWildcard {
			return "", fmt.Errorf("wildcard name %q needs the wildcard preset", name)
		}
		if len(labels) < 3 {
			return "", fmt.Errorf("wildcard %q is too broad – it needs at least two labels after \"*.\" (like *.homelab.lan)", name)
		}
		labels = labels[1:]
	}
	for _, label := range labels {
		if err := checkLabel(label); err != nil {
			return "", fmt.Errorf("DNS name %q: %w", name, err)
		}
	}
	if isDigits(labels[len(labels)-1]) {
		return "", fmt.Errorf("DNS name %q: the last label is all digits, which looks like an IP address", name)
	}
	return name, nil
}

var ldh = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// checkLabel applies the LDH rule (letters, digits, hyphen; RFC 1123/5890).
func checkLabel(label string) error {
	switch {
	case label == "":
		return fmt.Errorf("empty label (two dots in a row?)")
	case strings.Contains(label, "*"):
		return fmt.Errorf("\"*\" is only allowed as the whole leftmost label")
	case len(label) > maxLabel:
		return fmt.Errorf("label %q is longer than %d characters", label, maxLabel)
	case !ldh.MatchString(label):
		return fmt.Errorf("label %q may only contain a-z, 0-9 and '-' (not at the start or end)", label)
	case len(label) >= 4 && label[2:4] == "--" && !strings.HasPrefix(label, "xn--"):
		return fmt.Errorf("label %q: '--' at positions 3-4 is reserved (RFC 5891)", label)
	}
	return nil
}

// checkIP returns the canonical form of an IP SAN; IPv4-mapped IPv6
// addresses become IPv4.
func checkIP(s string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%q is not an IP address", short(s))
	}
	if ip.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("IP address %q: a zone (%%%s) can't go into a certificate", s, ip.Zone())
	}
	ip = ip.Unmap()
	if ip.IsUnspecified() {
		return netip.Addr{}, fmt.Errorf("IP address %q is the unspecified address", s)
	}
	return ip, nil
}

// atext: the characters RFC 5322 allows unquoted in the local part.
var atext = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+$")

// checkEmail returns the canonical form of an e-mail SAN: the domain is lower
// case, the local part stays as written (it may be case sensitive). Only the
// plain ASCII form (rfc822Name) is supported.
func checkEmail(s string) (string, error) {
	if !isASCII(s) {
		return "", fmt.Errorf("e-mail address %q contains non-ASCII characters – only ASCII addresses are supported", short(s))
	}
	if len(s) > maxEmail {
		return "", fmt.Errorf("e-mail address %q is longer than %d characters", short(s), maxEmail)
	}
	at := strings.LastIndexByte(s, '@')
	if at <= 0 || at == len(s)-1 {
		return "", fmt.Errorf("%q is not an e-mail address (want local@domain)", s)
	}
	local, domain := s[:at], s[at+1:]
	if len(local) > maxLocal {
		return "", fmt.Errorf("e-mail address %q: the part before @ is longer than %d characters", s, maxLocal)
	}
	for _, part := range strings.Split(local, ".") {
		if !atext.MatchString(part) {
			return "", fmt.Errorf("e-mail address %q: the part before @ is not a plain address (no quotes, spaces or double dots)", s)
		}
	}
	d, err := checkDNSName(domain, false)
	if err != nil {
		return "", fmt.Errorf("e-mail address %q: %w", s, err)
	}
	return local + "@" + d, nil
}

var schemePattern = regexp.MustCompile(`^[a-z][a-z0-9+.-]*$`)

// checkURI checks a URI SAN: absolute, printable ASCII, no user info.
func checkURI(s string) (string, error) {
	if len(s) > maxURI {
		return "", fmt.Errorf("URI is longer than %d characters", maxURI)
	}
	for _, r := range s {
		if r <= ' ' || r >= 0x7f {
			return "", fmt.Errorf("URI %q may only contain printable ASCII without spaces", short(s))
		}
	}
	u, err := url.Parse(s)
	if err != nil || !u.IsAbs() || !schemePattern.MatchString(u.Scheme) {
		return "", fmt.Errorf("%q is not an absolute URI (like https://host/path or spiffe://domain/workload)", s)
	}
	if u.User != nil {
		return "", fmt.Errorf("URI %q must not contain a user name or password", s)
	}
	return s, nil
}

// Names are the checked subject alternative names of one certificate.
type Names struct {
	DNS    []string
	IPs    []netip.Addr
	Emails []string
	URIs   []string
}

func (n *Names) count() int { return len(n.DNS) + len(n.IPs) + len(n.Emails) + len(n.URIs) }

func (n *Names) has(t preset.SANType) bool {
	switch t {
	case preset.SANDNS:
		return len(n.DNS) > 0
	case preset.SANIP:
		return len(n.IPs) > 0
	case preset.SANEmail:
		return len(n.Emails) > 0
	case preset.SANURI:
		return len(n.URIs) > 0
	}
	return false
}

// list returns every name as "type:value", for the audit log and the database.
func (n *Names) list() [][2]string {
	var out [][2]string
	for _, v := range n.DNS {
		out = append(out, [2]string{string(preset.SANDNS), v})
	}
	for _, v := range n.IPs {
		out = append(out, [2]string{string(preset.SANIP), v.String()})
	}
	for _, v := range n.Emails {
		out = append(out, [2]string{string(preset.SANEmail), v})
	}
	for _, v := range n.URIs {
		out = append(out, [2]string{string(preset.SANURI), v})
	}
	return out
}

// nameInput are names as requested, before checking.
type nameInput struct {
	DNS, IPs, Emails, URIs []string
}

// checkNames checks and de-duplicates every requested name and returns one
// problem per bad name, so the requester sees them all at once.
func checkNames(in nameInput, allowWildcard bool) (Names, []string) {
	var n Names
	var problems []string
	seen := map[string]bool{}
	add := func(kind, v string) bool {
		key := kind + ":" + v
		if seen[key] {
			return false
		}
		seen[key] = true
		return true
	}
	for _, s := range in.DNS {
		if v, err := checkDNSName(s, allowWildcard); err != nil {
			problems = append(problems, err.Error())
		} else if add("dns", v) {
			n.DNS = append(n.DNS, v)
		}
	}
	for _, s := range in.IPs {
		if v, err := checkIP(s); err != nil {
			problems = append(problems, err.Error())
		} else if add("ip", v.String()) {
			n.IPs = append(n.IPs, v)
		}
	}
	for _, s := range in.Emails {
		if v, err := checkEmail(s); err != nil {
			problems = append(problems, err.Error())
		} else if add("email", v) {
			n.Emails = append(n.Emails, v)
		}
	}
	for _, s := range in.URIs {
		if v, err := checkURI(s); err != nil {
			problems = append(problems, err.Error())
		} else if add("uri", v) {
			n.URIs = append(n.URIs, v)
		}
	}
	if n.count() > maxSANs {
		problems = append(problems, fmt.Sprintf("%d names – at most %d per certificate", n.count(), maxSANs))
	}
	return n, problems
}

// Subject holds the distinguished name fields a request may set. Everything
// else in a CSR's subject is ignored.
type Subject struct {
	CommonName         string
	Organization       string
	OrganizationalUnit string
	Locality           string
	Province           string
	Country            string
}

// Upper bounds from RFC 5280 appendix A (ub-common-name etc.), in characters.
const (
	maxCommonName = 64
	maxOrg        = 64
	maxLocality   = 128
)

// checkSubject checks the fields except the CN, whose length rule depends on
// where it came from (see Engine.subject). Surrounding spaces are removed;
// control and invisible formatting characters are rejected – they can make a
// name look like another one in a UI or a log.
func checkSubject(s Subject) (Subject, []string) {
	var problems []string
	field := func(name, v string, limit int) string {
		v = strings.TrimSpace(v)
		if err := checkDNText(v); err != nil {
			problems = append(problems, name+": "+err.Error())
			return v
		}
		if limit > 0 && utf8.RuneCountInString(v) > limit {
			problems = append(problems, fmt.Sprintf("%s is longer than %d characters", name, limit))
		}
		return v
	}
	out := Subject{
		CommonName:         field("common name", s.CommonName, 0),
		Organization:       field("organization", s.Organization, maxOrg),
		OrganizationalUnit: field("organizational unit", s.OrganizationalUnit, maxOrg),
		Locality:           field("locality", s.Locality, maxLocality),
		Province:           field("state or province", s.Province, maxLocality),
		Country:            strings.ToUpper(strings.TrimSpace(s.Country)),
	}
	if out.Country != "" && (len(out.Country) != 2 || out.Country[0] < 'A' || out.Country[0] > 'Z' || out.Country[1] < 'A' || out.Country[1] > 'Z') {
		problems = append(problems, fmt.Sprintf("country %q: want a two-letter ISO 3166 code like DE", short(s.Country)))
	}
	return out, problems
}

// checkDNText rejects invalid UTF-8, control characters (including newlines
// and tabs) and invisible formatting characters such as bidi overrides.
func checkDNText(v string) error {
	if !utf8.ValidString(v) {
		return fmt.Errorf("invalid UTF-8")
	}
	for _, r := range v {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return fmt.Errorf("contains the control or formatting character U+%04X", r)
		}
	}
	return nil
}

func isASCII(s string) bool {
	for i := range len(s) {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

func isDigits(s string) bool {
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// short cuts attacker input to 80 bytes for an error message. Messages print
// it with %q, which escapes control characters.
func short(s string) string {
	if len(s) > 80 {
		return s[:77] + "..."
	}
	return s
}

// NormalizeDNSName checks a DNS name like a SAN and returns its canonical
// (lower-case) form – for ACME identifiers, which follow the same rules.
func NormalizeDNSName(s string, allowWildcard bool) (string, error) {
	return checkDNSName(s, allowWildcard)
}
