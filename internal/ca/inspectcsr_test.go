package ca

import (
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"
	"testing"
)

// TestInspectCSRNameCap: the preview of a CSR shows at most maxSANs names over
// all four lists, in the order DNS, IP, e-mail, URI, each clipped to 80 bytes,
// and says so in Problems. A CSR is attacker input: 64 KiB hold about 2,500
// names, and the preview is handed back whole. The answer stays a preview – it
// does not fail where an issuance would explain (decision D4 of
// docs/PHASE3.md section 19).
func TestInspectCSRNameCap(t *testing.T) {
	t.Parallel()
	key := mustKey(t, elliptic.P256())
	dns := func(n int) []string {
		var out []string
		for i := range n {
			out = append(out, fmt.Sprintf("h%d.homelab.lan", i))
		}
		return out
	}
	ips := func(n int) []net.IP {
		var out []net.IP
		for i := range n {
			out = append(out, net.IPv4(10, 0, byte(i), 1))
		}
		return out
	}
	problem := func(n int) string {
		return fmt.Sprintf("%d names – at most %d per certificate; the list shows the first %d", n, maxSANs, maxSANs)
	}
	tests := []struct {
		name                   string
		tmpl                   x509.CertificateRequest
		dns, ips, emails, uris int // names in the preview
		problems               []string
		firstDNS, lastDNS      string
		firstIP                string
	}{
		{name: "at the cap", tmpl: x509.CertificateRequest{DNSNames: dns(100)}, dns: 100, firstDNS: "h0.homelab.lan", lastDNS: "h99.homelab.lan"},
		{name: "one over", tmpl: x509.CertificateRequest{DNSNames: dns(101)}, dns: 100, problems: []string{problem(101)}, firstDNS: "h0.homelab.lan", lastDNS: "h99.homelab.lan"},
		{name: "2,500 DNS names", tmpl: x509.CertificateRequest{DNSNames: dns(2500)}, dns: 100, problems: []string{problem(2500)}, firstDNS: "h0.homelab.lan", lastDNS: "h99.homelab.lan"},
		{
			name: "four types share the cap", dns: 60, ips: 40, problems: []string{problem(127)}, firstDNS: "h0.homelab.lan", lastDNS: "h59.homelab.lan", firstIP: "10.0.0.1",
			tmpl: x509.CertificateRequest{
				DNSNames: dns(60), IPAddresses: ips(60),
				EmailAddresses: []string{"a@homelab.lan", "b@homelab.lan", "c@homelab.lan", "d@homelab.lan", "e@homelab.lan"},
				URIs:           []*url.URL{{Scheme: "spiffe", Host: "homelab.lan", Path: "/a"}, {Scheme: "spiffe", Host: "homelab.lan", Path: "/b"}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tmpl := tt.tmpl
			insp, err := InspectCSR(makeCSR(t, key, &tmpl))
			if err != nil {
				t.Fatal(err)
			}
			if len(insp.DNSNames) != tt.dns || len(insp.IPs) != tt.ips || len(insp.Emails) != tt.emails || len(insp.URIs) != tt.uris {
				t.Errorf("preview shows %d DNS, %d IP, %d e-mail and %d URI names, want %d, %d, %d and %d",
					len(insp.DNSNames), len(insp.IPs), len(insp.Emails), len(insp.URIs), tt.dns, tt.ips, tt.emails, tt.uris)
			}
			if !slices.Equal(insp.Problems, tt.problems) {
				t.Errorf("problems %q, want %q", insp.Problems, tt.problems)
			}
			if tt.dns > 0 && (insp.DNSNames[0] != tt.firstDNS || insp.DNSNames[tt.dns-1] != tt.lastDNS) {
				t.Errorf("DNS names run from %q to %q, want %q to %q", insp.DNSNames[0], insp.DNSNames[tt.dns-1], tt.firstDNS, tt.lastDNS)
			}
			if tt.firstIP != "" && insp.IPs[0] != tt.firstIP {
				t.Errorf("first IP %q, want %q", insp.IPs[0], tt.firstIP)
			}
			// The lists are never nil: the REST answer says [] and not null.
			if insp.DNSNames == nil || insp.IPs == nil || insp.Emails == nil || insp.URIs == nil || insp.Problems == nil {
				t.Error("a list of the preview is nil")
			}
		})
	}
}

// TestInspectCSRClipsNames: a name in the preview is at most 80 bytes, cut
// like every echo of attacker text (short), and shorter names stay whole.
func TestInspectCSRClipsNames(t *testing.T) {
	t.Parallel()
	key := mustKey(t, elliptic.P256())
	long := strings.Repeat("a", 300) + ".homelab.lan"
	insp, err := InspectCSR(makeCSR(t, key, &x509.CertificateRequest{
		DNSNames:       []string{"short.homelab.lan", long},
		EmailAddresses: []string{strings.Repeat("m", 200) + "@homelab.lan"},
		URIs:           []*url.URL{{Scheme: "spiffe", Host: "homelab.lan", Path: "/" + strings.Repeat("p", 200)}},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if insp.DNSNames[0] != "short.homelab.lan" {
		t.Errorf("a short name is %q", insp.DNSNames[0])
	}
	for _, list := range [][]string{insp.DNSNames[1:], insp.Emails, insp.URIs} {
		if len(list) != 1 || len(list[0]) != 80 || !strings.HasSuffix(list[0], "...") {
			t.Errorf("a long name is %q, want 80 bytes ending in ...", list)
		}
	}
	if !strings.HasPrefix(insp.DNSNames[1], "aaaa") || insp.DNSNames[1] != long[:77]+"..." {
		t.Errorf("the clipped DNS name is %q", insp.DNSNames[1])
	}
	if len(insp.Problems) != 0 {
		t.Errorf("problems %q for a CSR with four names", insp.Problems)
	}
}
