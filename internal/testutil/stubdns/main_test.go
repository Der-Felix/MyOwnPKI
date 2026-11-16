package main

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func ask(t *testing.T, network, addr, name string, qtype uint16) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	resp, _, err := (&dns.Client{Net: network}).Exchange(m, addr)
	if err != nil {
		t.Fatalf("%s query %s: %v", network, name, err)
	}
	return resp
}

func TestStubDNSAnswers(t *testing.T) {
	t.Parallel()
	srv, err := start("127.0.0.1:0", "Upgrade.Lan", netip.MustParseAddr("192.0.2.10"))
	if err != nil {
		t.Fatal(err)
	}
	defer srv.close()

	for _, network := range []string{"udp", "tcp"} {
		for _, name := range []string{"acme1.upgrade.lan.", "a.b.upgrade.lan.", "UPGRADE.lan.", "upgrade.lan."} {
			resp := ask(t, network, srv.addr, name, dns.TypeA)
			if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
				t.Fatalf("%s A %s: rcode %d, %d answers", network, name, resp.Rcode, len(resp.Answer))
			}
			a, ok := resp.Answer[0].(*dns.A)
			if !ok || a.A.String() != "192.0.2.10" || a.Hdr.Ttl != 1 {
				t.Errorf("%s A %s: %v", network, name, resp.Answer[0])
			}
		}
		// AAAA and TXT: no data, but not an error – a client must not wait for IPv6.
		for _, qtype := range []uint16{dns.TypeAAAA, dns.TypeTXT} {
			resp := ask(t, network, srv.addr, "acme1.upgrade.lan.", qtype)
			if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 {
				t.Errorf("%s type %d: rcode %d, %d answers, want NODATA", network, qtype, resp.Rcode, len(resp.Answer))
			}
		}
		// Outside the zone, and a name that only ends in the same letters.
		for _, name := range []string{"example.com.", "notupgrade.lan.", "upgrade.lan.example."} {
			if resp := ask(t, network, srv.addr, name, dns.TypeA); resp.Rcode != dns.RcodeRefused {
				t.Errorf("%s A %s: rcode %d, want REFUSED", network, name, resp.Rcode)
			}
		}
	}
}

func TestStubDNSArguments(t *testing.T) {
	t.Parallel()
	for name, args := range map[string][]string{
		"no zone":      {"--ip", "192.0.2.1"},
		"no address":   {"--zone", "upgrade.lan"},
		"IPv6":         {"--zone", "upgrade.lan", "--ip", "2001:db8::1"},
		"not an IP":    {"--zone", "upgrade.lan", "--ip", "pki"},
		"unknown flag": {"--nope"},
	} {
		var out, errOut bytes.Buffer
		if code := run(args, &out, &errOut); code != 2 {
			t.Errorf("%s: exit %d, want 2 (%s)", name, code, errOut.String())
		}
	}
	if _, err := start("127.0.0.1:notaport", "upgrade.lan", netip.MustParseAddr("192.0.2.1")); err == nil || !strings.Contains(err.Error(), "--listen") {
		t.Errorf("a bad listen address gave %v", err)
	}
}
