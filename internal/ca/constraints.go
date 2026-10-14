package ca

import (
	"encoding/asn1"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strings"
)

// Name constraints (RFC 5280 §4.2.1.10) are checked here before signing –
// clients are not relied on to reject (pki-rules.md §3). Every CA in the
// chain counts: an intermediate can't issue what its root doesn't permit.
// After signing, crypto/x509 checks the constraints in the CA certificates a
// second time.

// constraint is a row of ca_name_constraints.
type constraint struct {
	kind      string // dns, ip, email, uri
	value     string
	permitted bool
}

// caConstraints are the constraints and the EKU limit of one CA in the chain.
type caConstraints struct {
	ca       string
	names    []constraint
	ekuLimit []asn1.ObjectIdentifier // empty = no limit
}

// checkConstraints returns one problem per name that a CA in the chain
// doesn't permit. cnHost is the CN when clients could take it for a host
// name (see cnHost in engine.go): then it must satisfy the DNS constraints
// too, and the message says how to fix the request.
func checkConstraints(chain []caConstraints, n Names, cnHost string) []string {
	var problems []string
	for _, c := range chain {
		byKind := map[string][]constraint{}
		for _, nc := range c.names {
			byKind[nc.kind] = append(byKind[nc.kind], nc)
		}
		check := func(kind, label, name string, match func(name, value string) bool, wildcard bool, hint string) {
			cs := byKind[kind]
			if len(cs) == 0 {
				return
			}
			permittedSome, permitted := false, false
			for _, nc := range cs {
				switch {
				case nc.permitted:
					permittedSome = true
					permitted = permitted || match(name, nc.value)
				case match(name, nc.value) || (wildcard && wildcardCovers(name, nc.value)):
					problems = append(problems, fmt.Sprintf("%s %q is excluded by the name constraints of CA %q (%s)", label, name, c.ca, nc.value)+hint)
					return
				}
			}
			if permittedSome && !permitted {
				problems = append(problems, fmt.Sprintf("%s %q is outside the name constraints of CA %q (permitted: %s)", label, name, c.ca, permittedList(cs))+hint)
			}
		}
		for _, d := range n.DNS {
			check("dns", "dns", d, matchDNS, strings.HasPrefix(d, "*."), "")
		}
		if cnHost != "" {
			check("dns", "common name", cnHost, matchDNS, false, cnHint)
		}
		for _, ip := range n.IPs {
			check("ip", "ip", ip.String(), matchIP, false, "")
		}
		for _, e := range n.Emails {
			check("email", "email", e, matchEmail, false, "")
		}
		for _, u := range n.URIs {
			check("uri", "uri", u, matchURI, false, "")
		}
	}
	return problems
}

// cnHint names the two ways out when a CN that looks like a host name is
// outside the constraints (owner 2026-10-13).
const cnHint = " – clients without a DNS SAN read a CN with dots as a host name. Use a display name " +
	"without dots as CN (e.g. \"Max Mustermann\" instead of \"max.mustermann\"), or add a DNS SAN " +
	"within the permitted names (clients then ignore the CN)"

func permittedList(cs []constraint) string {
	var out []string
	for _, c := range cs {
		if c.permitted {
			out = append(out, c.value)
		}
	}
	return strings.Join(out, ", ")
}

// matchDNS: "example.com" covers the name itself and every name below it;
// ".example.com" only the names below it (the crypto/x509 and legacy reading).
// A wildcard name is compared as written, so *.example.com is inside
// "example.com" but not inside "a.example.com".
func matchDNS(name, value string) bool {
	value = strings.ToLower(value)
	if strings.HasPrefix(value, ".") {
		return strings.HasSuffix(name, value)
	}
	return name == value || strings.HasSuffix(name, "."+value)
}

// wildcardCovers reports whether *.D covers a name the excluded constraint
// value names: *.example.com covers a.example.com, so a wildcard must not be
// issued when "a.example.com" is excluded.
func wildcardCovers(wildcard, value string) bool {
	base := strings.TrimPrefix(wildcard, "*.")
	value = strings.ToLower(value)
	if strings.HasPrefix(value, ".") {
		return false // only names below value are excluded; *.D covers exactly one label
	}
	_, parent, ok := strings.Cut(value, ".")
	return ok && parent == base
}

func matchIP(name, value string) bool {
	ip, err := netip.ParseAddr(name)
	if err != nil {
		return false
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return false
	}
	return prefix.Contains(ip)
}

// matchEmail: "user@host" is one mailbox, "host" every mailbox at that host,
// ".example.com" every mailbox at a host below example.com (RFC 5280).
func matchEmail(name, value string) bool {
	at := strings.LastIndexByte(name, '@')
	domain := name[at+1:]
	value = strings.ToLower(value)
	switch {
	case strings.Contains(value, "@"):
		v := strings.LastIndexByte(value, '@')
		return name[:at] == value[:v] && domain == value[v+1:]
	case strings.HasPrefix(value, "."):
		return strings.HasSuffix(domain, value)
	}
	return domain == value
}

// matchURI compares the host of the URI: "host" exactly, ".example.com" every
// host below. A URI without a host name can't satisfy a URI constraint.
func matchURI(name, value string) bool {
	u, err := url.Parse(name)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}
	value = strings.ToLower(value)
	if strings.HasPrefix(value, ".") {
		return strings.HasSuffix(host, value)
	}
	return host == value
}

// checkEKULimit: every EKU of the leaf must be allowed by every CA in the
// chain that has a limit. A leaf without EKU is valid for every purpose, so a
// limited CA can't issue one.
func checkEKULimit(chain []caConstraints, leaf []asn1.ObjectIdentifier) []string {
	var problems []string
	for _, c := range chain {
		if len(c.ekuLimit) == 0 {
			continue
		}
		if len(leaf) == 0 {
			problems = append(problems, fmt.Sprintf("CA %q may only issue certificates with the extended key usages %s – a certificate without EKU would be valid for every purpose", c.ca, oidList(c.ekuLimit)))
			continue
		}
		for _, oid := range leaf {
			if !slices.ContainsFunc(c.ekuLimit, oid.Equal) {
				problems = append(problems, fmt.Sprintf("extended key usage %s is not allowed by CA %q (allowed: %s)", oid, c.ca, oidList(c.ekuLimit)))
			}
		}
	}
	return problems
}

func oidList(oids []asn1.ObjectIdentifier) string {
	s := make([]string, len(oids))
	for i, o := range oids {
		s[i] = o.String()
	}
	return strings.Join(s, ", ")
}
