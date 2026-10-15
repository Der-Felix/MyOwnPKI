package server

import (
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/clock"
)

// allowListener accepts only peers inside allowed (admin.allowed_networks,
// ADR-08). It checks the direct peer before the TLS handshake: a refused
// client sees neither certificate nor server, and costs no handshake. An
// empty list allows everybody.
type allowListener struct {
	net.Listener
	allowed []netip.Prefix
	refused *refusalLog
}

func (l *allowListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil || len(l.allowed) == 0 {
			return c, err
		}
		ip := peerIP(c.RemoteAddr())
		if ip.IsValid() && slices.ContainsFunc(l.allowed, func(p netip.Prefix) bool { return p.Contains(ip) }) {
			return c, nil
		}
		_ = c.Close()
		l.refused.add(ip)
	}
}

// peerIP is the address of the direct peer; IPv4-mapped IPv6 counts as IPv4.
func peerIP(a net.Addr) netip.Addr {
	if tcp, ok := a.(*net.TCPAddr); ok {
		if ip, ok := netip.AddrFromSlice(tcp.IP); ok {
			return ip.Unmap()
		}
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

// refusalLog sums refused connections up and logs at most once a minute, so
// a scanner can't flood the log (owner 2026-10-16).
type refusalLog struct {
	log   *slog.Logger
	clk   clock.Clock
	every time.Duration

	mu       sync.Mutex
	count    int
	addrs    map[netip.Addr]int
	lastEmit time.Time
}

const maxRefusedAddrs = 1000

func newRefusalLog(log *slog.Logger, clk clock.Clock) *refusalLog {
	return &refusalLog{log: log, clk: clk, every: time.Minute, addrs: map[netip.Addr]int{}}
}

func (r *refusalLog) add(ip netip.Addr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.count++
	if len(r.addrs) < maxRefusedAddrs || r.addrs[ip] > 0 {
		r.addrs[ip]++
	}
	r.emitLocked(false)
}

// flush logs what was summed up, if the minute is over (a job calls it, so
// the last refusals of a burst are reported too).
func (r *refusalLog) flush() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.emitLocked(false)
}

func (r *refusalLog) emitLocked(force bool) {
	now := r.clk.Now()
	if r.count == 0 || (!force && now.Sub(r.lastEmit) < r.every) {
		return
	}
	top := make([]netip.Addr, 0, len(r.addrs))
	for a := range r.addrs {
		top = append(top, a)
	}
	slices.SortFunc(top, func(a, b netip.Addr) int { return r.addrs[b] - r.addrs[a] })
	samples := make([]string, 0, 5)
	for _, a := range top[:min(5, len(top))] {
		samples = append(samples, a.String())
	}
	r.log.Warn("admin connections refused (not in admin.allowed_networks)",
		slog.Int("count", r.count), slog.Int("addresses", len(r.addrs)), slog.Any("top", samples))
	r.count, r.addrs, r.lastEmit = 0, map[netip.Addr]int{}, now
}
