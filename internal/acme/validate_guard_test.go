package acme

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"
)

// TestPolicyDialKeepsTheACMEPortRuleAndTheMessages: the guard itself is
// tested in internal/netguard; here the part that stays in acme – the port
// rule (80, and 443 after a redirect) – and that the shared guard's refusals
// still reach the client as the same ACME problems.
func TestPolicyDialKeepsTheACMEPortRuleAndTheMessages(t *testing.T) {
	t.Parallel()
	v := newNetValidator(slog.New(slog.DiscardHandler), "")
	var dialed []string
	v.lookupIP = func(_ context.Context, host string) ([]netip.Addr, error) {
		switch host {
		case "loop.homelab.lan":
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		case "gone.homelab.lan":
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		return []netip.Addr{netip.MustParseAddr("192.0.2.10")}, nil
	}
	v.dial = func(_ context.Context, _, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		c, _ := net.Pipe()
		return c, nil
	}
	dial := v.policyDial("internal")
	for _, tc := range []struct {
		addr, typ, detail string
	}{
		{"x.homelab.lan:8080", "connection", "port 8080: http-01 connects to port 80 (and 443 after a redirect) only"},
		{"x.homelab.lan:22", "connection", "port 22: http-01 connects to port 80 (and 443 after a redirect) only"},
		{"x.homelab.lan:080", "connection", "port 080 is not a port number"},
		{"loop.homelab.lan:80", "connection", "loop.homelab.lan: the address policy of the domain refuses all 1 address(es)"},
		{"gone.homelab.lan:80", "dns", "gone.homelab.lan: no such name"},
	} {
		_, err := dial(t.Context(), "tcp", tc.addr)
		var ve *validationError
		if !errors.As(err, &ve) || ve.typ != tc.typ || !strings.HasPrefix(ve.detail, tc.detail) {
			t.Errorf("%s: err = %v, want %s: %s", tc.addr, err, tc.typ, tc.detail)
		}
	}
	if len(dialed) != 0 {
		t.Errorf("dialed %v", dialed)
	}
	for _, addr := range []string{"x.homelab.lan:80", "x.homelab.lan:443"} {
		conn, err := dial(t.Context(), "tcp", addr)
		if err != nil {
			t.Fatalf("%s: %v", addr, err)
		}
		_ = conn.Close()
	}
	if strings.Join(dialed, " ") != "192.0.2.10:80 192.0.2.10:443" {
		t.Errorf("dialed %v", dialed)
	}
}
