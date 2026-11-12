package netguard

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestAllowed(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		addr     string
		internal bool // allowed under "internal"
		public   bool // allowed under "public"
	}{
		// Never allowed, under any policy.
		{"127.0.0.1", false, false},
		{"127.255.255.254", false, false},
		{"::1", false, false},
		{"0.0.0.0", false, false},
		{"::", false, false},
		{"0.1.2.3", false, false}, // 0.0.0.0/8
		{"169.254.169.254", false, false},
		{"169.254.0.1", false, false},
		{"fe80::1", false, false},
		{"fe80::1%eth0", false, false},
		{"224.0.0.1", false, false},
		{"239.255.255.250", false, false},
		{"ff02::1", false, false},
		{"ff01::1", false, false},
		{"ff05::2", false, false},
		{"240.0.0.1", false, false}, // 240.0.0.0/4
		{"255.255.255.255", false, false},
		{"::ffff:127.0.0.1", false, false}, // IPv4-mapped IPv6 is unmapped first
		{"::ffff:169.254.169.254", false, false},
		{"::ffff:0.0.0.0", false, false},
		{"2001:db8::1%eth0", false, false}, // a zone is never a target
		// IPv6 forms that embed an IPv4 address are refused as a whole range.
		{"::7f00:1", false, false},                             // IPv4-compatible 127.0.0.1
		{"::a00:1", false, false},                              // IPv4-compatible 10.0.0.1
		{"::c000:20a", false, false},                           // IPv4-compatible 192.0.2.10: the range goes, not only bad contents
		{"64:ff9b::7f00:1", false, false},                      // NAT64 127.0.0.1
		{"64:ff9b::a00:1", false, false},                       // NAT64 10.0.0.1
		{"64:ff9b::c000:20a", false, false},                    // NAT64 192.0.2.10
		{"64:ff9b:1::7f00:1", false, false},                    // local-use NAT64 (RFC 8215)
		{"2002:7f00:1::", false, false},                        // 6to4 127.0.0.1
		{"2002:a9fe:a9fe::1", false, false},                    // 6to4 169.254.169.254
		{"2002:c000:20a::1", false, false},                     // 6to4 192.0.2.10
		{"2001:0:4136:e378:8000:63bf:3fff:fdd2", false, false}, // Teredo
		// Private: only under "internal".
		{"10.0.0.1", true, false},
		{"172.16.5.4", true, false},
		{"192.168.1.1", true, false},
		{"fc00::1", true, false},
		{"fd12:3456::1", true, false},
		{"100.64.0.1", true, false}, // CGNAT, RFC 6598
		{"::ffff:10.0.0.1", true, false},
		// Public documentation addresses (RFC 5737, RFC 3849).
		{"192.0.2.10", true, true},
		{"198.51.100.7", true, true},
		{"203.0.113.9", true, true},
		{"2001:db8::1", true, true},
		{"::ffff:192.0.2.10", true, true},
		// Ordinary global IPv6 next to the refused ranges is untouched.
		{"2606:4700:4700::1111", true, true},
		{"2001:1::1", true, true},    // 2001::/16 outside the Teredo /32
		{"2003::1", true, true},      // next to 6to4
		{"64:ff9a::1", true, true},   // next to NAT64
		{"64:ff9b:2::1", true, true}, // next to local-use NAT64
	} {
		a, err := netip.ParseAddr(tc.addr)
		if err != nil {
			t.Fatalf("%s: %v", tc.addr, err)
		}
		if got := Allowed(a, PolicyInternal) == nil; got != tc.internal {
			t.Errorf("%s under internal: allowed = %v, want %v", tc.addr, got, tc.internal)
		}
		if got := Allowed(a, PolicyPublic) == nil; got != tc.public {
			t.Errorf("%s under public: allowed = %v, want %v", tc.addr, got, tc.public)
		}
	}
	if Allowed(netip.Addr{}, PolicyInternal) == nil {
		t.Error("the zero address is allowed")
	}
	// An unknown policy is as permissive as "internal" only for addresses
	// that are never refused: it must not make a loopback address reachable.
	if Allowed(netip.MustParseAddr("127.0.0.1"), "") == nil {
		t.Error("loopback allowed under an empty policy")
	}
}

type fakeNet struct {
	mu      sync.Mutex
	lookups []string
	dials   []string
	answers [][]netip.Addr // per lookup, the last one repeats
	failing map[string]error
}

func (f *fakeNet) lookup(_ context.Context, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lookups = append(f.lookups, host)
	i := min(len(f.lookups), len(f.answers)) - 1
	return f.answers[i], nil
}

func (f *fakeNet) dial(_ context.Context, _, addr string) (net.Conn, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dials = append(f.dials, addr)
	if err := f.failing[addr]; err != nil {
		return nil, err
	}
	c, _ := net.Pipe()
	return c, nil
}

func addrs(s ...string) []netip.Addr {
	var out []netip.Addr
	for _, a := range s {
		out = append(out, netip.MustParseAddr(a))
	}
	return out
}

func port443(p uint16) error {
	if p != 443 {
		return errors.New("only 443")
	}
	return nil
}

func opErr(err error) error {
	return &net.OpError{Op: "dial", Net: "tcp", Err: err}
}

func TestDialConnectsToTheCheckedAddressOnly(t *testing.T) {
	t.Parallel()
	// DNS rebinding: the second lookup would answer 127.0.0.1. The guard
	// looks up once and connects to the address it checked.
	f := &fakeNet{answers: [][]netip.Addr{addrs("192.0.2.10"), addrs("127.0.0.1")}}
	d := &Dialer{Policy: PolicyInternal, Dial: f.dial, LookupIP: f.lookup, CheckPort: port443}
	conn, err := d.DialContext(t.Context(), "tcp", "proxy.homelab.lan:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if len(f.lookups) != 1 || len(f.dials) != 1 || f.dials[0] != "192.0.2.10:443" {
		t.Errorf("lookups %v, dials %v", f.lookups, f.dials)
	}
}

func TestDialRefusals(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		policy string
		addr   string
		answer []netip.Addr
		want   string // part of the error text
		kind   string
	}{
		{"loopback answer", PolicyInternal, "loop.homelab.lan:443", addrs("127.0.0.1"), "refuses all 1 address(es)", KindConnection},
		{"all refused", PolicyInternal, "x.homelab.lan:443", addrs("127.0.0.1", "169.254.169.254", "::1"), "refuses all 3 address(es)", KindConnection},
		{"private under public", PolicyPublic, "x.homelab.lan:443", addrs("10.1.2.3"), "refuses all 1 address(es)", KindConnection},
		{"literal loopback", PolicyInternal, "127.0.0.1:443", nil, "refuses all 1 address(es)", KindConnection},
		{"literal v6 loopback", PolicyInternal, "[::1]:443", nil, "refuses all 1 address(es)", KindConnection},
		{"literal mapped", PolicyInternal, "[::ffff:127.0.0.1]:443", nil, "refuses all 1 address(es)", KindConnection},
		{"no address", PolicyInternal, "x.homelab.lan:443", addrs(), "has no address", KindDNS},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeNet{answers: [][]netip.Addr{tc.answer}}
			d := &Dialer{Policy: tc.policy, Dial: f.dial, LookupIP: f.lookup, CheckPort: port443}
			_, err := d.DialContext(t.Context(), "tcp", tc.addr)
			var ge *Error
			if !errors.As(err, &ge) || ge.Kind != tc.kind || !strings.Contains(ge.Detail, tc.want) {
				t.Fatalf("error = %v, want %s %q", err, tc.kind, tc.want)
			}
			if len(f.dials) != 0 {
				t.Errorf("dialed %v", f.dials)
			}
			// The client never learns an address.
			for _, a := range tc.answer {
				if strings.Contains(err.Error(), a.String()) {
					t.Errorf("error names %s: %v", a, err)
				}
			}
			if tc.want != "has no address" && !ge.Refused {
				t.Error("Refused is not set")
			}
		})
	}
}

func TestDialPortRule(t *testing.T) {
	t.Parallel()
	f := &fakeNet{answers: [][]netip.Addr{addrs("192.0.2.10")}}
	// No CheckPort: every port is refused, nothing is resolved.
	closed := &Dialer{Policy: PolicyInternal, Dial: f.dial, LookupIP: f.lookup}
	if _, err := closed.DialContext(t.Context(), "tcp", "x.homelab.lan:443"); err == nil {
		t.Error("a dialer without a port rule connected")
	}
	d := &Dialer{Policy: PolicyInternal, Dial: f.dial, LookupIP: f.lookup, CheckPort: port443}
	for _, addr := range []string{
		"x.homelab.lan:80", "x.homelab.lan:22", "x.homelab.lan:0", "x.homelab.lan:65536", "x.homelab.lan:-1",
		"x.homelab.lan:0443", "x.homelab.lan:+443", "x.homelab.lan:https", "x.homelab.lan:", "x.homelab.lan",
	} {
		if conn, err := d.DialContext(t.Context(), "tcp", addr); err == nil {
			_ = conn.Close()
			t.Errorf("%s connected", addr)
		}
	}
	if len(f.lookups) != 0 || len(f.dials) != 0 {
		t.Errorf("a refused port resolved %v or dialed %v", f.lookups, f.dials)
	}
	// The error of the port rule is returned as it is.
	rule := errors.New("the rule's own error")
	d.CheckPort = func(uint16) error { return rule }
	if _, err := d.DialContext(t.Context(), "tcp", "x.homelab.lan:443"); !errors.Is(err, rule) {
		t.Errorf("error = %v", err)
	}
}

func TestDialTriesAllowedAddressesInOrder(t *testing.T) {
	t.Parallel()
	refused := opErr(syscall.ECONNREFUSED)
	f := &fakeNet{
		answers: [][]netip.Addr{addrs("127.0.0.1", "192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5", "192.0.2.6")},
		failing: map[string]error{"192.0.2.1:443": refused, "192.0.2.2:443": refused, "192.0.2.3:443": refused, "192.0.2.4:443": refused},
	}
	// Without a limit the fifth address answers.
	d := &Dialer{Policy: PolicyInternal, Dial: f.dial, LookupIP: f.lookup, CheckPort: port443}
	conn, err := d.DialContext(t.Context(), "tcp", "x.homelab.lan:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if got := strings.Join(f.dials, " "); got != "192.0.2.1:443 192.0.2.2:443 192.0.2.3:443 192.0.2.4:443 192.0.2.5:443" {
		t.Errorf("dials = %s", got)
	}
	// With MaxTries 4 it gives up after four dials; the refused loopback
	// answer does not count as a try.
	f.dials = nil
	d.MaxTries = 4
	_, err = d.DialContext(t.Context(), "tcp", "x.homelab.lan:443")
	var ge *Error
	if !errors.As(err, &ge) || ge.Kind != KindConnection || ge.Refused || len(f.dials) != 4 {
		t.Fatalf("err = %v, dials = %v", err, f.dials)
	}
	if !strings.Contains(ge.Detail, "1 address(es) refused by the address policy, 4 could not be reached (could not connect)") {
		t.Errorf("detail = %q", ge.Detail)
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Error("the last dial error is not reachable with errors.Is")
	}
	for _, a := range []string{"192.0.2", "127.0.0.1"} {
		if strings.Contains(err.Error(), a) {
			t.Errorf("the error names an address: %v", err)
		}
	}
}

func TestDialTryTimeout(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var tries int
	hang := func(ctx context.Context, _, _ string) (net.Conn, error) {
		mu.Lock()
		tries++
		mu.Unlock()
		<-ctx.Done()
		return nil, opErr(ctx.Err())
	}
	d := &Dialer{
		Policy: PolicyInternal, Dial: hang, CheckPort: port443, TryTimeout: 5 * time.Millisecond, MaxTries: 3,
		LookupIP: func(context.Context, string) ([]netip.Addr, error) {
			return addrs("192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"), nil
		},
	}
	_, err := d.DialContext(t.Context(), "tcp", "x.homelab.lan:443")
	if err == nil || tries != 3 || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("tries = %d, err = %v", tries, err)
	}
}

func TestDialDNSErrorsHaveKindsNotAddresses(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		err  error
		want string
	}{
		{&net.DNSError{Err: "no such host", Name: "x.homelab.lan", Server: "10.9.8.7:53", IsNotFound: true}, "no such name"},
		{&net.DNSError{Err: "i/o timeout", Name: "x.homelab.lan", Server: "10.9.8.7:53", IsTimeout: true}, "the DNS lookup timed out"},
		{errors.New("read udp 10.0.0.5:5353->10.9.8.7:53: boom"), "the DNS lookup failed"},
	} {
		d := &Dialer{
			Policy: PolicyInternal, CheckPort: port443,
			LookupIP: func(context.Context, string) ([]netip.Addr, error) { return nil, tc.err },
		}
		_, err := d.DialContext(t.Context(), "tcp", "x.homelab.lan:443")
		var ge *Error
		if !errors.As(err, &ge) || ge.Kind != KindDNS || ge.Detail != "x.homelab.lan: "+tc.want {
			t.Errorf("%v: err = %v", tc.err, err)
		}
		if strings.Contains(err.Error(), "10.") {
			t.Errorf("the error names an address: %v", err)
		}
	}
}

func TestDialLogsRefusalsForTheServerLog(t *testing.T) {
	t.Parallel()
	var buf lockedBuffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	f := &fakeNet{answers: [][]netip.Addr{addrs("127.0.0.1")}}
	d := &Dialer{Policy: PolicyInternal, Dial: f.dial, LookupIP: f.lookup, CheckPort: port443, Log: log, LogName: "test guard"}
	_, _ = d.DialContext(t.Context(), "tcp", "x.homelab.lan:443")
	if got := buf.String(); !strings.Contains(got, "test guard: address refused") || !strings.Contains(got, "127.0.0.1") {
		t.Errorf("log = %q", got)
	}
}

func TestProblemsNameKindsOnly(t *testing.T) {
	t.Parallel()
	if got := NetProblem(opErr(io.EOF)); got != "could not connect" {
		t.Errorf("dial error: %q", got)
	}
	if got := NetProblem(context.DeadlineExceeded); got != "timed out" {
		t.Errorf("deadline: %q", got)
	}
	if got := NetProblem(errors.New("HTTP/1.1 SECRET-BANNER")); strings.Contains(got, "SECRET") {
		t.Errorf("a remote text got through: %q", got)
	}
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}
