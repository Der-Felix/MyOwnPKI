package auth

import (
	"net/http"
	"net/netip"
	"strings"
)

// ClientIP returns the address of the client behind r. Without trusted
// proxies it is the direct peer. When the peer is a trusted proxy, the
// X-Forwarded-For list is read from the right: the first address that is not
// a trusted proxy is the client. Everything left of it was written by the
// client itself and is never believed.
func ClientIP(r *http.Request, trusted []netip.Prefix) netip.Addr {
	addr, ok := parseHop(r.RemoteAddr)
	if !ok || !isTrusted(addr, trusted) {
		return addr
	}
	var hops []string
	for _, h := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(h, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		hop, ok := parseHop(strings.TrimSpace(hops[i]))
		if !ok {
			break // garbage: stop at the last address we could check
		}
		addr = hop
		if !isTrusted(hop, trusted) {
			return hop
		}
	}
	return addr
}

// parseHop accepts an IP or IP:port, as in RemoteAddr.
func parseHop(s string) (netip.Addr, bool) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap(), true
	}
	if a, err := netip.ParseAddr(s); err == nil && a.Zone() == "" {
		return a.Unmap(), true
	}
	return netip.Addr{}, false
}

func isTrusted(a netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
