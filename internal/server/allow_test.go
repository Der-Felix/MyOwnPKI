package server

import (
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/config"
)

// oddAddr is a net.Addr that is not one of the standard library's types.
type oddAddr struct{ network, text string }

func (a oddAddr) Network() string { return a.network }
func (a oddAddr) String() string  { return a.text }

// fakeConn is a connection from a made-up peer.
type fakeConn struct {
	net.Conn // nil: only RemoteAddr and Close are used
	peer     net.Addr
	closed   atomic.Bool
}

func (c *fakeConn) RemoteAddr() net.Addr { return c.peer }
func (c *fakeConn) Close() error         { c.closed.Store(true); return nil }

// fakeListener hands out the queued connections, then fails with err.
type fakeListener struct {
	net.Listener
	queue []net.Conn
	err   error
}

func (l *fakeListener) Accept() (net.Conn, error) {
	if len(l.queue) == 0 {
		return nil, l.err
	}
	c := l.queue[0]
	l.queue = l.queue[1:]
	return c, nil
}

func tcp(ip string, port int) net.Addr { return &net.TCPAddr{IP: net.ParseIP(ip), Port: port} }

// TestPeerIP: what the allow-list sees of a peer. Anything that is not
// clearly an IP address of a TCP peer is "invalid", which no network contains.
func TestPeerIP(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		addr net.Addr
		want string // "" = invalid
	}{
		{"IPv4", tcp("10.1.2.3", 1), "10.1.2.3"},
		{"IPv4 as 4 bytes", &net.TCPAddr{IP: net.IP{10, 1, 2, 3}, Port: 1}, "10.1.2.3"},
		{"IPv4-mapped IPv6", tcp("::ffff:10.1.2.3", 1), "10.1.2.3"},
		{"IPv4-mapped IPv6 in hex", tcp("::ffff:a01:203", 1), "10.1.2.3"},
		{"IPv6", tcp("2001:db8::1", 1), "2001:db8::1"},
		{"IPv6 loopback", tcp("::1", 1), "::1"},
		{"IPv6 with a zone", &net.TCPAddr{IP: net.ParseIP("fe80::1"), Zone: "eth0", Port: 1}, "fe80::1"},
		{"NAT64 is not unmapped", tcp("64:ff9b::a01:203", 1), "64:ff9b::a01:203"},
		{"TCP without IP", &net.TCPAddr{Port: 1}, ""},
		{"TCP with a broken IP", &net.TCPAddr{IP: net.IP{10, 1, 2}, Port: 1}, ""},
		{"nil address", nil, ""},
		{"typed nil TCP address", (*net.TCPAddr)(nil), ""},
		{"Unix socket", &net.UnixAddr{Name: "/run/myownpki/admin.sock", Net: "unix"}, ""},
		{"unnamed Unix peer", &net.UnixAddr{Net: "unix"}, ""},
		{"abstract Unix socket", &net.UnixAddr{Name: "@admin", Net: "unix"}, ""},
		{"Unix socket named like a TCP peer", &net.UnixAddr{Name: "10.1.2.3:80", Net: "unix"}, ""},
		{"Unix datagram named like a TCP peer", &net.UnixAddr{Name: "10.1.2.3:80", Net: "unixgram"}, ""},
		{"IP address without a port", &net.IPAddr{IP: net.ParseIP("10.1.2.3")}, ""},
		{"UDP", &net.UDPAddr{IP: net.ParseIP("10.1.2.3"), Port: 9}, "10.1.2.3"},
		{"other TCP implementation", oddAddr{"tcp", "10.1.2.3:4444"}, "10.1.2.3"},
		{"other TCP implementation, IPv6", oddAddr{"tcp", "[2001:db8::5]:4444"}, "2001:db8::5"},
		{"other TCP implementation, mapped", oddAddr{"tcp6", "[::ffff:10.1.2.3]:4444"}, "10.1.2.3"},
		{"other implementation without a port", oddAddr{"tcp", "10.1.2.3"}, ""},
		{"other implementation with a host name", oddAddr{"tcp", "localhost:80"}, ""},
		{"other implementation with a name that is not an address", oddAddr{"pipe", "pipe"}, ""},
		{"other implementation of an unknown network", oddAddr{"quic", "10.1.2.3:4444"}, ""},
		{"empty text", oddAddr{"tcp", ""}, ""},
		{"text with a path", oddAddr{"tcp", "10.1.2.3:80/x"}, ""},
		{"two addresses", oddAddr{"tcp", "10.1.2.3:80,192.0.2.1:80"}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := peerIP(tc.addr)
			if tc.want == "" {
				if got.IsValid() {
					t.Errorf("peerIP = %s, want an invalid address", got)
				}
				return
			}
			if !got.IsValid() || got.String() != tc.want || got.Is4In6() {
				t.Errorf("peerIP = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestAllowListenerDecides: the same decision for every kind of peer address.
func TestAllowListenerDecides(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		allowed string
		peer    net.Addr
		want    bool
	}{
		{"inside a network", "10.0.0.0/8", tcp("10.1.2.3", 1), true},
		{"first address of a network", "10.0.0.0/8", tcp("10.0.0.0", 1), true},
		{"last address of a network", "10.0.0.0/8", tcp("10.255.255.255", 1), true},
		{"just below a network", "10.0.0.0/8", tcp("9.255.255.255", 1), false},
		{"just above a network", "10.0.0.0/8", tcp("11.0.0.0", 1), false},
		{"mapped IPv4 inside an IPv4 network", "10.0.0.0/8", tcp("::ffff:10.1.2.3", 1), true},
		{"mapped IPv4 outside an IPv4 network", "10.0.0.0/8", tcp("::ffff:192.0.2.1", 1), false},
		{"IPv6 against an IPv4 network", "10.0.0.0/8", tcp("2001:db8::1", 1), false},
		{"a single address", "192.0.2.7", tcp("192.0.2.7", 1), true},
		{"the next address of a single address", "192.0.2.7", tcp("192.0.2.8", 1), false},
		{"a single address written mapped", "::ffff:192.0.2.7", tcp("192.0.2.7", 1), true},
		{"IPv6 network, inside", "2001:db8::/32", tcp("2001:db8:1::1", 1), true},
		{"IPv6 network, outside", "2001:db8::/32", tcp("2001:db9::1", 1), false},
		{"IPv6 loopback only", "::1", tcp("::1", 1), true},
		{"IPv6 loopback only, IPv4 loopback", "::1", tcp("127.0.0.1", 1), false},
		{"IPv6 peer with a zone in a link-local network", "fe80::/10", &net.TCPAddr{IP: net.ParseIP("fe80::1"), Zone: "eth0"}, true},
		{"everything IPv4", "0.0.0.0/0", tcp("203.0.113.9", 1), true},
		{"everything IPv4, an IPv6 peer", "0.0.0.0/0", tcp("2001:db8::1", 1), false},
		{"everything IPv6, a mapped IPv4 peer is IPv4", "::/0", tcp("::ffff:203.0.113.9", 1), false},
		{"second entry of a list", "10.0.0.0/8, 192.0.2.0/24", tcp("192.0.2.9", 1), true},
		{"Unix socket", "10.0.0.0/8", &net.UnixAddr{Name: "/run/x.sock", Net: "unix"}, false},
		{"Unix socket, everything allowed", "0.0.0.0/0, ::/0", &net.UnixAddr{Name: "/run/x.sock", Net: "unix"}, false},
		{"Unix socket named like an allowed peer", "10.0.0.0/8", &net.UnixAddr{Name: "10.1.2.3:80", Net: "unix"}, false},
		{"no address at all", "10.0.0.0/8", nil, false},
		{"typed nil address", "10.0.0.0/8", (*net.TCPAddr)(nil), false},
		{"other implementation, inside", "10.0.0.0/8", oddAddr{"tcp", "10.1.2.3:9"}, true},
		{"other implementation, outside", "10.0.0.0/8", oddAddr{"tcp", "192.0.2.1:9"}, false},
		{"other implementation, no port", "10.0.0.0/8", oddAddr{"tcp", "10.1.2.3"}, false},
		{"other implementation, a name", "10.0.0.0/8", oddAddr{"tcp", "intranet.example:9"}, false},
		{"empty list, any IP", "", tcp("203.0.113.9", 1), true},
		{"empty list, Unix socket", "", &net.UnixAddr{Name: "/run/x.sock", Net: "unix"}, true},
		{"empty list, no address", "", nil, true},
		{"blanks and commas only mean an empty list", " , ,", tcp("203.0.113.9", 1), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			nets, err := config.ParseNetworks(tc.allowed)
			if err != nil {
				t.Fatal(err)
			}
			conn := &fakeConn{peer: tc.peer}
			stop := errors.New("no more connections")
			ln := &allowListener{
				Listener: &fakeListener{queue: []net.Conn{conn}, err: stop}, allowed: nets,
				refused: newRefusalLog(slog.New(slog.DiscardHandler), clock.NewFake(t0)),
			}
			got, err := ln.Accept()
			if tc.want {
				if err != nil || got != net.Conn(conn) || conn.closed.Load() {
					t.Errorf("Accept = %v, %v (closed %v), want the connection", got, err, conn.closed.Load())
				}
				return
			}
			if !errors.Is(err, stop) || got != nil {
				t.Errorf("Accept = %v, %v, want to skip the refused peer and reach the end", got, err)
			}
			if !conn.closed.Load() {
				t.Error("a refused connection was left open")
			}
		})
	}
}

// TestAllowListenerSkipsRefusedPeers: a refused peer does not end the loop,
// it is closed, counted and logged; errors of the real listener pass through.
func TestAllowListenerSkipsRefusedPeers(t *testing.T) {
	t.Parallel()
	nets, err := config.ParseNetworks("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	var logs logBuf
	clk := clock.NewFake(t0)
	refused := newRefusalLog(slog.New(slog.NewJSONHandler(&logs, nil)), clk)
	bad1 := &fakeConn{peer: tcp("203.0.113.1", 1)}
	bad2 := &fakeConn{peer: &net.UnixAddr{Name: "/x", Net: "unix"}}
	good := &fakeConn{peer: tcp("10.9.8.7", 1)}
	bad3 := &fakeConn{peer: tcp("203.0.113.2", 1)}
	boom := errors.New("accept failed")
	ln := &allowListener{Listener: &fakeListener{queue: []net.Conn{bad1, bad2, good, bad3}, err: boom}, allowed: nets, refused: refused}

	c, err := ln.Accept()
	if err != nil || c != net.Conn(good) {
		t.Fatalf("Accept = %v, %v, want the allowed peer behind two refused ones", c, err)
	}
	if !bad1.closed.Load() || !bad2.closed.Load() || good.closed.Load() {
		t.Errorf("closed: %v %v, allowed one: %v", bad1.closed.Load(), bad2.closed.Load(), good.closed.Load())
	}
	if _, err := ln.Accept(); !errors.Is(err, boom) {
		t.Errorf("a refused peer hid the listener error: %v", err)
	}
	if !bad3.closed.Load() {
		t.Error("the third refused connection was left open")
	}
	clk.Advance(2 * refused.every)
	refused.flush()
	out := logs.String()
	if n := strings.Count(out, "admin connections refused"); n < 2 {
		t.Errorf("%d log lines:\n%s", n, out)
	}
	if !strings.Contains(out, "203.0.113.1") || strings.Contains(out, "10.9.8.7") {
		t.Errorf("the log names the wrong peers:\n%s", out)
	}
}
