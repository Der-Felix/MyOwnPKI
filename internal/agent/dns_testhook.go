package agent

import (
	"crypto/x509"
	"time"
)

// DNSTest is what an end-to-end test of dns-01 replaces from outside this
// package, like SetDial and SetACMEDial do for the connections: the address of
// a Cloudflare stub, the roots that vouch for it, and the polling interval of
// the propagation check. Production never sets it and agent.yaml has no key
// for it.
type DNSTest struct {
	// CloudflareURL is the API base of the stub, "" for the real API.
	CloudflareURL string
	// CloudflareRoots trusts the stub's certificate.
	CloudflareRoots *x509.CertPool
	// Poll replaces the 2 s interval of the propagation check (0 = unchanged).
	Poll time.Duration
}

// SetDNSTest points the dns-01 path at test doubles – for tests only.
func (a *Agent) SetDNSTest(t DNSTest) {
	a.dns.poll = t.Poll
	a.dns.cloudflare = nil
	if t.CloudflareURL != "" {
		a.dns.cloudflare = &cloudflareTest{baseURL: t.CloudflareURL, roots: t.CloudflareRoots}
	}
}
