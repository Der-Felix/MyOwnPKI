package analysis

import (
	"crypto/x509"
	"strings"
	"testing"
	"unicode"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
)

// TestSafeHref: a link of a finding stays inside the UI. Browsers strip TAB,
// CR and LF from a URL, so "/<TAB>/evil" is "//evil" to them.
func TestSafeHref(t *testing.T) {
	t.Parallel()
	for _, ok := range []string{"", "/", "/certificates", "/certificates/abc-123", "/acme/accounts/acc_1", "/certificates?status=valid"} {
		if got := SafeHref(ok); got != ok {
			t.Errorf("SafeHref(%q) = %q, want it kept", ok, got)
		}
	}
	for _, bad := range []string{
		"//evil.example", "/\\evil.example", "/\t/evil.example", "/\n/evil.example", "/\r/evil.example", "/\x00/evil", "/\x0b/evil",
		"/\x1f/evil", "/\x7f/evil", "/a\tb", "https://evil.example", "javascript:alert(1)", "evil.example", "certificates", " /x",
	} {
		if got := SafeHref(bad); got != "" {
			t.Errorf("SafeHref(%q) = %q, want it dropped", bad, got)
		}
	}
}

// TestCleanText: control, format and bidi characters and bad UTF-8 go; ordinary
// text, including non-ASCII letters, stays.
func TestCleanText(t *testing.T) {
	t.Parallel()
	for in, out := range map[string]string{
		"plain.homelab.lan":                 "plain.homelab.lan",
		"münchen.lan ü 日本":                  "münchen.lan ü 日本",
		"a\xe2\x80\xaeevil\xe2\x80\xac.lan": "aevil.lan", // right-to-left override and pop
		"a\xe2\x81\xa6b\xe2\x81\xa9c":       "abc",       // isolates
		"zero\xe2\x80\x8bwidth\xef\xbb\xbf": "zerowidth", // zero-width space and BOM
		"two\nlines\r\tand\x1bescape":       "twolinesandescape",
		"bad\xffbyte":                       "badbyte",
		"<script>alert(1)</script>.lan":     "<script>alert(1)</script>.lan", // markup stays data: the template escapes it
	} {
		if got := CleanText(in); got != out {
			t.Errorf("CleanText(%q) = %q, want %q", in, got, out)
		}
	}
}

const bidi = "\xe2\x80\xae\xe2\x81\xa6\xe2\x80\x8b\n\t"

func noUnwanted(t *testing.T, what, s string) {
	t.Helper()
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			t.Errorf("%s holds %U: %q", what, r, s)
			return
		}
	}
}

// TestFindingTextIsCleaned: names from certificates, agents, CAs, domains and
// accounts reach a finding without control and bidi characters, whatever the
// rule, and a link that leaves the UI is dropped.
func TestFindingTextIsCleaned(t *testing.T) {
	t.Parallel()
	evil := "ev" + bidi + "il.homelab.lan"
	snap := Snapshot{
		Now: now, ServerVersion: "0.3.8",
		Certificates: []Certificate{
			cert("a", names(evil), func(c *Certificate) { c.CommonName = evil }),
			cert("k", func(c *Certificate) {
				c.CommonName = evil
				c.Traits = &ca.Traits{KeyAlgorithm: ca.TraitRSA, KeyBits: 1024, Signature: x509.SHA1WithRSA}
			}),
		},
		CAs:       []CA{{ID: "ca-1", Name: "ca" + bidi, Issuing: true, Generations: []Generation{{Number: 1, Current: true, Signed: true, NotAfter: now.Add(5 * day)}}}},
		Agents:    []Agent{{ID: "agt-1", Hostname: "host" + bidi, Version: "0.1.0", Status: "active"}},
		Accounts:  []Account{{ID: "acc" + bidi, Status: "valid", CreatedAt: now.Add(-100 * day)}},
		Domains:   []ca.Domain{{ID: "dom-1", Name: "dom" + bidi + ".lan", CreatedAt: now.Add(-100 * day)}},
		Endpoints: []Endpoint{endpoint("a", func(e *Endpoint) { e.Name = "a.homelab.lan" })},
	}
	snap.Certificates[0].DNSNames = []string{"a.homelab.lan", evil}
	n := 0
	for _, r := range Run(snap) {
		for _, f := range r.Findings {
			n++
			noUnwanted(t, r.ID+" subject", f.Subject)
			noUnwanted(t, r.ID+" seen", f.Seen)
			noUnwanted(t, r.ID+" why", f.Why)
			noUnwanted(t, r.ID+" recommendation", f.Recommendation)
		}
	}
	if n < 5 {
		t.Fatalf("only %d findings: the fixture no longer exercises the rules", n)
	}
	// Cleaning comes before clipping: the clip counts what is shown.
	long := strings.Repeat("a"+bidi, 200)
	if got := clip(long); len([]rune(got)) != maxClip || strings.ContainsAny(got, bidi) {
		t.Errorf("clip: %d runes, %q", len([]rune(got)), got)
	}

	// A finding with a link that leaves the UI loses the link, whatever the rule.
	res := finish([]Finding{
		{Key: "k1", Rule: "r", Severity: SeverityInfo, Subject: "s\xe2\x80\xae", Seen: "x", Why: "y", Recommendation: "z", Href: "/\t/evil.example"},
		{Key: "k2", Rule: "r", Severity: SeverityInfo, Subject: "s", Seen: "x", Why: "y", Recommendation: "z", Href: "/certificates/1"},
	}, 0, "")
	for _, f := range res.Findings {
		switch f.Key {
		case "k1":
			if f.Href != "" || f.Subject != "s" {
				t.Errorf("k1: %+v", f)
			}
		case "k2":
			if f.Href != "/certificates/1" {
				t.Errorf("k2: %+v", f)
			}
		}
	}
}
