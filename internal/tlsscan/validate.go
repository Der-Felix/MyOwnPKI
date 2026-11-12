package tlsscan

import (
	"fmt"
	"net/netip"
	"strings"
	"unicode"

	"github.com/Der-Felix/MyOwnPKI/internal/agents"
	"github.com/Der-Felix/MyOwnPKI/internal/netguard"
)

// Request is what an admin enters. Every field is untrusted input.
type Request struct {
	Host string
	Port int
	SNI  string // optional
}

// checked is a Request after the syntax checks: the canonical forms.
type checked struct {
	Host string
	IP   netip.Addr // valid when the host is an IP literal
	Port int
	SNI  string // "" = none
}

// maxInput bounds what is looked at before the real rules run.
const maxInput = 512

// check applies the rules that need no database: the syntax of host and SNI,
// the port list and the ranges that are never scanned (docs/PHASE3.md §10.2).
func (s Settings) check(r Request) (checked, error) {
	var c checked
	host, ip, rule := checkHost(r.Host)
	if rule != "" {
		return c, &InvalidError{"host", rule}
	}
	c.Host, c.IP = host, ip
	if !s.portAllowed(r.Port) {
		return c, &InvalidError{"port", fmt.Sprintf("port %d is not in the list of scannable ports (monitor.scan_ports: %s)", r.Port, joinInts(s.Ports))}
	}
	c.Port = r.Port
	if sni := strings.TrimSpace(r.SNI); sni != "" {
		name, nip, rule := checkHost(sni)
		if rule != "" {
			return c, &InvalidError{"sni", rule}
		}
		if nip.IsValid() {
			return c, &InvalidError{"sni", "a DNS name, not an IP address (an IP literal is never sent as SNI)"}
		}
		if name != host {
			c.SNI = name
		}
	}
	if ip.IsValid() {
		if err := netguard.Allowed(ip, netguard.PolicyInternal); err != nil {
			return c, &InvalidError{"host", "this address range is never scanned (unspecified, loopback, link-local, multicast and reserved addresses)"}
		}
	}
	return c, nil
}

// checkHost returns the canonical host: a lower-case fully qualified DNS name
// without the trailing dot, or an IP literal (IPv4-mapped unmapped).
func checkHost(raw string) (string, netip.Addr, string) {
	h := strings.TrimSpace(raw)
	switch {
	case h == "":
		return "", netip.Addr{}, "must not be empty"
	case len(h) > maxInput:
		return "", netip.Addr{}, "is far too long (a DNS name has at most 253 characters)"
	}
	for _, r := range h {
		if unicode.IsSpace(r) || unicode.IsControl(r) || r > unicode.MaxASCII {
			return "", netip.Addr{}, "may only contain ASCII letters, digits, '-', '.' (or an IP address) – no spaces or special characters"
		}
	}
	if ip, err := netip.ParseAddr(h); err == nil {
		if ip.Zone() != "" {
			return "", netip.Addr{}, "an IP address has no zone (no %eth0 suffix)"
		}
		return ip.Unmap().String(), ip.Unmap(), ""
	}
	if strings.ContainsAny(h, ":/@?#[]\\") {
		return "", netip.Addr{}, "a host name or IP address only – no scheme, path, port or brackets (IPv6 is written without brackets; the port is its own field)"
	}
	name := strings.ToLower(strings.TrimSuffix(h, "."))
	if err := agents.CheckDNSName(name); err != nil {
		return "", netip.Addr{}, err.Error()
	}
	for label := range strings.SplitSeq(name, ".") {
		if rest, ok := strings.CutPrefix(label, "xn--"); ok && !validPunycode(rest) {
			return "", netip.Addr{}, "a label starting with xn-- must be valid punycode"
		}
	}
	return name, netip.Addr{}, ""
}

func joinInts(v []int) string {
	parts := make([]string, len(v))
	for i, n := range v {
		parts[i] = fmt.Sprint(n)
	}
	return strings.Join(parts, ", ")
}

// validPunycode reports whether s (the label without "xn--") decodes as
// punycode (RFC 3492) to at least one non-ASCII character. A label that
// does not is not an internationalized name but junk that looks like one.
func validPunycode(s string) bool {
	const (
		base, tmin, tmax, skew, damp = 36, 1, 26, 38, 700
		initialBias, initialN        = 72, 128
	)
	if s == "" || len(s) > 59 {
		return false
	}
	basic, digits := "", s
	if i := strings.LastIndexByte(s, '-'); i >= 0 {
		basic, digits = s[:i], s[i+1:]
	}
	if digits == "" {
		return false // no encoded part: the label would be plain ASCII
	}
	count := len(basic) // code points so far
	n, bias, pos := initialN, initialBias, 0
	adapt := func(delta, points int, first bool) int {
		if first {
			delta /= damp
		} else {
			delta /= 2
		}
		delta += delta / points
		k := 0
		for delta > ((base-tmin)*tmax)/2 {
			delta /= base - tmin
			k += base
		}
		return k + (base-tmin+1)*delta/(delta+skew)
	}
	first := true
	for i := 0; i < len(digits); {
		oldPos, w := pos, 1
		for k := base; ; k += base {
			if i >= len(digits) {
				return false
			}
			var d int
			switch c := digits[i]; {
			case c >= 'a' && c <= 'z':
				d = int(c - 'a')
			case c >= '0' && c <= '9':
				d = int(c-'0') + 26
			default:
				return false
			}
			i++
			if d > (1<<31-1-pos)/w {
				return false
			}
			pos += d * w
			t := k - bias
			switch {
			case t < tmin:
				t = tmin
			case t > tmax:
				t = tmax
			}
			if d < t {
				break
			}
			if w > (1<<31-1)/(base-t) {
				return false
			}
			w *= base - t
		}
		count++
		bias = adapt(pos-oldPos, count, first)
		first = false
		if pos/count > 1<<31-1-n {
			return false
		}
		n += pos / count
		pos %= count
		if n > unicode.MaxRune || (n >= 0xD800 && n <= 0xDFFF) {
			return false
		}
		pos++
	}
	return n >= initialN
}
