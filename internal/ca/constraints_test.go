package ca

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// The expected values of these tests come from RFC 5280 §4.2.1.10 and from
// reading each rule by hand, not from running the matcher under test.

func ncRows(permitted bool, kind string, values ...string) []constraint {
	var rows []constraint
	for _, v := range values {
		rows = append(rows, constraint{kind: kind, value: v, permitted: permitted})
	}
	return rows
}

func joinRows(sets ...[]constraint) []constraint {
	var all []constraint
	for _, s := range sets {
		all = append(all, s...)
	}
	return all
}

func addrs(t *testing.T, list ...string) []netip.Addr {
	t.Helper()
	var out []netip.Addr
	for _, s := range list {
		a, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, a)
	}
	return out
}

// TestCheckConstraintsRows: one CA with every kind of constraint, and a name
// per row of the table. want is a part of the one problem a refused name
// produces; "" = the name is allowed.
func TestCheckConstraintsRows(t *testing.T) {
	t.Parallel()
	issuing := caConstraints{ca: "issuing", names: joinRows(
		ncRows(true, "dns", "homelab.lan"), ncRows(false, "dns", "secret.homelab.lan"),
		ncRows(true, "ip", "10.0.0.0/8", "fd00::/8"), ncRows(false, "ip", "10.9.0.0/16"),
		ncRows(true, "email", "homelab.lan"), ncRows(false, "email", "bob@homelab.lan"),
		ncRows(true, "uri", ".homelab.lan"), ncRows(false, "uri", "evil.homelab.lan"),
	)}
	tests := []struct {
		name  string
		names Names
		want  string
	}{
		{"dns at the permitted name", Names{DNS: []string{"homelab.lan"}}, ""},
		{"dns below the permitted name", Names{DNS: []string{"a.b.homelab.lan"}}, ""},
		{"dns that only ends alike", Names{DNS: []string{"evilhomelab.lan"}}, `dns "evilhomelab.lan" is outside the name constraints of CA "issuing" (permitted: homelab.lan)`},
		{"dns elsewhere", Names{DNS: []string{"evil.com"}}, `dns "evil.com" is outside`},
		{"dns excluded exactly", Names{DNS: []string{"secret.homelab.lan"}}, `dns "secret.homelab.lan" is excluded by the name constraints of CA "issuing" (secret.homelab.lan)`},
		{"dns below an excluded name", Names{DNS: []string{"x.secret.homelab.lan"}}, "is excluded"},
		{"wildcard that covers an excluded name", Names{DNS: []string{"*.homelab.lan"}}, `dns "*.homelab.lan" is excluded`},
		{"wildcard one level lower", Names{DNS: []string{"*.apps.homelab.lan"}}, ""},
		{"wildcard outside", Names{DNS: []string{"*.evil.com"}}, "is outside"},
		{"ipv4 inside", Names{IPs: addrs(t, "10.1.2.3")}, ""},
		{"ipv4 at the edge of the prefix", Names{IPs: addrs(t, "10.255.255.255")}, ""},
		{"ipv4 just outside the prefix", Names{IPs: addrs(t, "11.0.0.0")}, `ip "11.0.0.0" is outside the name constraints of CA "issuing" (permitted: 10.0.0.0/8, fd00::/8)`},
		{"ipv4 excluded", Names{IPs: addrs(t, "10.9.200.1")}, `ip "10.9.200.1" is excluded by the name constraints of CA "issuing" (10.9.0.0/16)`},
		{"ipv4 next to the excluded prefix", Names{IPs: addrs(t, "10.10.0.1")}, ""},
		{"ipv6 inside", Names{IPs: addrs(t, "fd12:3456::1")}, ""},
		{"ipv6 outside", Names{IPs: addrs(t, "fe80::1")}, `ip "fe80::1" is outside`},
		{"email at the permitted host", Names{Emails: []string{"alice@homelab.lan"}}, ""},
		{"email at a subdomain of a host constraint", Names{Emails: []string{"alice@mail.homelab.lan"}}, `email "alice@mail.homelab.lan" is outside`},
		{"email at another host", Names{Emails: []string{"alice@evil.com"}}, "is outside"},
		{"email of an excluded mailbox", Names{Emails: []string{"bob@homelab.lan"}}, `email "bob@homelab.lan" is excluded`},
		{"uri below the permitted domain", Names{URIs: []string{"https://svc.homelab.lan/x"}}, ""},
		{"uri at the bare domain of a dotted constraint", Names{URIs: []string{"https://homelab.lan/"}}, `uri "https://homelab.lan/" is outside`},
		{"uri with an ip host", Names{URIs: []string{"https://10.0.0.1/"}}, "is outside"},
		{"uri without a host", Names{URIs: []string{"urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a66"}}, "is outside"},
		{"uri excluded host", Names{URIs: []string{"https://evil.homelab.lan/"}}, `uri "https://evil.homelab.lan/" is excluded`},
		{"uri host in capitals", Names{URIs: []string{"https://SVC.HomeLab.LAN/"}}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := checkConstraints([]caConstraints{issuing}, tt.names, "")
			switch {
			case tt.want == "" && len(got) != 0:
				t.Errorf("refused: %q", got)
			case tt.want != "" && (len(got) != 1 || !strings.Contains(got[0], tt.want)):
				t.Errorf("problems %q, want one with %q", got, tt.want)
			}
		})
	}
}

// TestCheckConstraintsOnlyWhereConstrained: a kind without a row is free, a
// CA with only excluded rows permits everything else, and an exclusion wins
// over a permission.
func TestCheckConstraintsOnlyWhereConstrained(t *testing.T) {
	t.Parallel()
	all := Names{DNS: []string{"evil.com"}, IPs: addrs(t, "192.168.1.1"), Emails: []string{"x@evil.com"}, URIs: []string{"https://evil.com/"}}
	for name, tt := range map[string]struct {
		rows []constraint
		want int
	}{
		"no rows":                     {nil, 0},
		"dns rows only":               {ncRows(true, "dns", "homelab.lan"), 1},
		"ip rows only":                {ncRows(true, "ip", "10.0.0.0/8"), 1},
		"email rows only":             {ncRows(true, "email", "homelab.lan"), 1},
		"uri rows only":               {ncRows(true, "uri", "homelab.lan"), 1},
		"only an exclusion elsewhere": {ncRows(false, "dns", "secret.homelab.lan"), 0},
		"only an exclusion that hits": {ncRows(false, "dns", "evil.com"), 1},
		"permitted and excluded":      {joinRows(ncRows(true, "dns", "evil.com"), ncRows(false, "dns", "evil.com")), 1},
	} {
		got := checkConstraints([]caConstraints{{ca: "c", names: tt.rows}}, all, "")
		if len(got) != tt.want {
			t.Errorf("%s: %d problems %q, want %d", name, len(got), got, tt.want)
		}
	}
	if got := checkConstraints(nil, all, "evil.com"); len(got) != 0 {
		t.Errorf("an empty chain refused: %q", got)
	}
}

// TestCheckConstraintsEveryCAInTheChain: an issuing CA wider than its parent
// can't issue what the parent doesn't permit – the parent is named.
func TestCheckConstraintsEveryCAInTheChain(t *testing.T) {
	t.Parallel()
	issuing := caConstraints{ca: "issuing", names: ncRows(true, "dns", "lan")}
	root := caConstraints{ca: "root", names: joinRows(ncRows(true, "dns", "homelab.lan"), ncRows(false, "dns", "secret.homelab.lan"))}
	chain := []caConstraints{issuing, root}
	tests := []struct {
		name  string
		dns   string
		wants []string // one per problem, in the order of the chain
	}{
		{"inside both", "a.homelab.lan", nil},
		{"inside the issuing CA, outside the root", "a.other.lan", []string{`name constraints of CA "root" (permitted: homelab.lan)`}},
		{"outside both", "evil.com", []string{`CA "issuing"`, `CA "root"`}},
		{"permitted by the issuing CA, excluded by the root", "secret.homelab.lan", []string{`excluded by the name constraints of CA "root"`}},
	}
	for _, tt := range tests {
		got := checkConstraints(chain, Names{DNS: []string{tt.dns}}, "")
		if len(got) != len(tt.wants) {
			t.Errorf("%s: problems %q, want %d", tt.name, got, len(tt.wants))
			continue
		}
		for i, want := range tt.wants {
			if !strings.Contains(got[i], want) {
				t.Errorf("%s: problem %d %q, want %q", tt.name, i, got[i], want)
			}
		}
	}
}

// TestCheckConstraintsCommonName: a CN that clients could read as a host name
// is held to the DNS constraints too, with the hint how to fix the request.
func TestCheckConstraintsCommonName(t *testing.T) {
	t.Parallel()
	chain := []caConstraints{{ca: "issuing", names: ncRows(true, "dns", "homelab.lan")}}
	got := checkConstraints(chain, Names{}, "max.mustermann")
	if len(got) != 1 || !strings.Contains(got[0], `common name "max.mustermann" is outside`) || !strings.Contains(got[0], "Use a display name without dots as CN") {
		t.Errorf("CN outside: %q", got)
	}
	if got := checkConstraints(chain, Names{}, "nas.homelab.lan"); len(got) != 0 {
		t.Errorf("CN inside: %q", got)
	}
	if got := checkConstraints(chain, Names{}, ""); len(got) != 0 {
		t.Errorf("no CN host: %q", got)
	}
	// An IP, e-mail or URI constraint doesn't look at the CN.
	if got := checkConstraints([]caConstraints{{ca: "c", names: ncRows(true, "ip", "10.0.0.0/8")}}, Names{}, "evil.com"); len(got) != 0 {
		t.Errorf("CN against an ip constraint: %q", got)
	}
}

// TestNCOutsideParent: a new CA that permits DNS names its parent doesn't
// permit gets a warning per name – certificates for it would never verify.
func TestNCOutsideParent(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		parent []string
		child  []constraint
		want   []string // the child values that are warned about
	}{
		{"parent without constraints", nil, ncRows(true, "dns", "anything.example"), nil},
		{"the same name", []string{"homelab.lan"}, ncRows(true, "dns", "homelab.lan"), nil},
		{"a name below", []string{"homelab.lan"}, ncRows(true, "dns", "lab.homelab.lan"), nil},
		{"a dotted name below", []string{"homelab.lan"}, ncRows(true, "dns", ".lab.homelab.lan"), nil},
		{"a wider name", []string{"homelab.lan"}, ncRows(true, "dns", "lan"), []string{"lan"}},
		{"another name", []string{"homelab.lan"}, ncRows(true, "dns", "other.lan"), []string{"other.lan"}},
		{"a name that only ends alike", []string{"homelab.lan"}, ncRows(true, "dns", "evilhomelab.lan"), []string{"evilhomelab.lan"}},
		{"the bare domain of a dotted parent", []string{".homelab.lan"}, ncRows(true, "dns", "homelab.lan"), []string{"homelab.lan"}},
		{"below a dotted parent", []string{".homelab.lan"}, ncRows(true, "dns", "a.homelab.lan"), nil},
		{"one of two parent names", []string{"a.lan", "b.lan"}, ncRows(true, "dns", "b.lan"), nil},
		{"one inside, one outside", []string{"homelab.lan"}, joinRows(ncRows(true, "dns", "a.homelab.lan"), ncRows(true, "dns", "c.example")), []string{"c.example"}},
		{"exclusions are not warned about", []string{"homelab.lan"}, ncRows(false, "dns", "evil.com"), nil},
		{"other kinds are not warned about", []string{"homelab.lan"}, joinRows(ncRows(true, "ip", "10.0.0.0/8"), ncRows(true, "email", "evil.com"), ncRows(true, "uri", "evil.com")), nil},
	}
	for _, tt := range tests {
		got := ncOutsideParent(&x509.Certificate{PermittedDNSDomains: tt.parent}, checkedNC{rows: tt.child})
		if len(got) != len(tt.want) {
			t.Errorf("%s: warnings %q, want %q", tt.name, got, tt.want)
			continue
		}
		for i, v := range tt.want {
			if !strings.Contains(got[i], "permitted DNS name "+v+" is outside the parent's name constraints ("+strings.Join(tt.parent, ", ")+")") {
				t.Errorf("%s: warning %q", tt.name, got[i])
			}
		}
	}
}

// TestNameConstraintRowsAreChecked: every kind goes through its own syntax
// check and comes out in canonical form.
func TestNameConstraintRowsAreChecked(t *testing.T) {
	t.Parallel()
	good := NameConstraints{
		PermittedDNS: []string{"HomeLab.LAN", " .Apps.homelab.lan "}, ExcludedDNS: []string{"secret.homelab.lan"},
		PermittedIP: []string{"10.0.0.0/8", "FD00::/8"}, ExcludedIP: []string{"10.9.0.0/16", "fd00:bad::/32"},
		PermittedEmail: []string{"homelab.lan", ".mail.homelab.lan", "felix@Homelab.LAN"}, ExcludedEmail: []string{"bob@homelab.lan"},
		PermittedURI: []string{"svc.homelab.lan", ".homelab.lan"}, ExcludedURI: []string{"evil.homelab.lan"},
	}
	got, problems := checkNameConstraints(good)
	if len(problems) != 0 || !got.critical {
		t.Fatalf("problems %q, critical %v", problems, got.critical)
	}
	want := joinRows(
		ncRows(true, "dns", "homelab.lan", ".apps.homelab.lan"), ncRows(false, "dns", "secret.homelab.lan"),
		ncRows(true, "ip", "10.0.0.0/8", "fd00::/8"), ncRows(false, "ip", "10.9.0.0/16", "fd00:bad::/32"),
		ncRows(true, "email", "homelab.lan", ".mail.homelab.lan", "felix@homelab.lan"), ncRows(false, "email", "bob@homelab.lan"),
		ncRows(true, "uri", "svc.homelab.lan", ".homelab.lan"), ncRows(false, "uri", "evil.homelab.lan"),
	)
	if len(got.rows) != len(want) {
		t.Fatalf("rows %v, want %v", got.rows, want)
	}
	for i := range want {
		if got.rows[i] != want[i] {
			t.Errorf("row %d: %+v, want %+v", i, got.rows[i], want[i])
		}
	}
	if dup, _ := checkNameConstraints(NameConstraints{PermittedDNS: []string{"a.lan", "A.LAN"}}); len(dup.rows) != 1 {
		t.Errorf("the same constraint twice: %v", dup.rows)
	}
	if nc, _ := checkNameConstraints(NameConstraints{PermittedDNS: []string{"a.lan"}, NotCritical: true}); nc.critical {
		t.Error("NotCritical is ignored")
	}

	bad := []struct {
		nc   NameConstraints
		want string
	}{
		{NameConstraints{PermittedIP: []string{"10.0.0.5/8"}}, "host bits are set – did you mean 10.0.0.0/8?"},
		{NameConstraints{ExcludedIP: []string{"10.0.0.0"}}, "want a CIDR prefix like 10.0.0.0/8 or fd00::/8"},
		{NameConstraints{PermittedIP: []string{"fd00::1/8"}}, "host bits are set – did you mean fd00::/8?"},
		{NameConstraints{PermittedIP: []string{"::ffff:10.0.0.0/104"}}, "IPv4-mapped"},
		{NameConstraints{PermittedDNS: []string{"a_b.lan"}}, "name constraint dns"},
		{NameConstraints{PermittedDNS: []string{"*.lan"}}, "needs the wildcard preset"},
		{NameConstraints{PermittedDNS: []string{"10.0.0.1"}}, "is an IP address"},
		{NameConstraints{PermittedEmail: []string{"felix@"}}, "is not an e-mail address"},
		{NameConstraints{ExcludedEmail: []string{"a b@homelab.lan"}}, "the part before @ is not a plain address"},
		{NameConstraints{PermittedEmail: []string{"bücher.example"}}, "non-ASCII"},
		{NameConstraints{PermittedURI: []string{"https://svc.homelab.lan/"}}, "name constraint uri"},
		{NameConstraints{ExcludedURI: []string{"xn--"}}, "name constraint uri"},
	}
	for _, tt := range bad {
		rows, problems := checkNameConstraints(tt.nc)
		if len(problems) != 1 || !strings.Contains(problems[0], tt.want) || len(rows.rows) != 0 {
			t.Errorf("%+v: problems %q rows %v, want %q", tt.nc, problems, rows.rows, tt.want)
		}
	}
}

// TestNameConstraintsSurviveTheCertificate: what the engine stores in the
// database and what a verifier reads from the certificate are the same
// constraints – and the extension is critical, as RFC 5280 wants.
func TestNameConstraintsSurviveTheCertificate(t *testing.T) {
	t.Parallel()
	nc, problems := checkNameConstraints(NameConstraints{
		PermittedDNS: []string{"homelab.lan"}, ExcludedDNS: []string{"secret.homelab.lan"},
		PermittedIP: []string{"10.0.0.0/8", "fd00::/8"}, ExcludedIP: []string{"10.9.0.0/16"},
		PermittedEmail: []string{"homelab.lan"}, ExcludedEmail: []string{"bob@homelab.lan"},
		PermittedURI: []string{".homelab.lan"}, ExcludedURI: []string{"evil.homelab.lan"},
	})
	if len(problems) != 0 {
		t.Fatal(problems)
	}
	key := mustKey(t, elliptic.P256())
	build := func(c checkedNC) *x509.Certificate {
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(77), Subject: pkix.Name{CommonName: "NC test"}, NotBefore: t0, NotAfter: t0.Add(24 * time.Hour),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		}
		c.apply(tmpl)
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
		if err != nil {
			t.Fatal(err)
		}
		return parse(t, der)
	}
	cert := build(nc)
	if !cert.PermittedDNSDomainsCritical {
		t.Error("the name constraints extension is not critical")
	}
	for _, p := range []struct {
		name      string
		got, want []string
	}{
		{"permitted DNS", cert.PermittedDNSDomains, []string{"homelab.lan"}},
		{"excluded DNS", cert.ExcludedDNSDomains, []string{"secret.homelab.lan"}},
		{"permitted e-mail", cert.PermittedEmailAddresses, []string{"homelab.lan"}},
		{"excluded e-mail", cert.ExcludedEmailAddresses, []string{"bob@homelab.lan"}},
		{"permitted URI", cert.PermittedURIDomains, []string{".homelab.lan"}},
		{"excluded URI", cert.ExcludedURIDomains, []string{"evil.homelab.lan"}},
	} {
		if strings.Join(p.got, ",") != strings.Join(p.want, ",") {
			t.Errorf("%s in the certificate: %v, want %v", p.name, p.got, p.want)
		}
	}
	if len(cert.PermittedIPRanges) != 2 || cert.PermittedIPRanges[0].String() != "10.0.0.0/8" || cert.PermittedIPRanges[1].String() != "fd00::/8" ||
		len(cert.ExcludedIPRanges) != 1 || cert.ExcludedIPRanges[0].String() != "10.9.0.0/16" {
		t.Errorf("IP ranges: permitted %v, excluded %v", cert.PermittedIPRanges, cert.ExcludedIPRanges)
	}
	if !sameConstraints(ncFromCert(cert), nc) {
		t.Errorf("read back %v, stored %v", ncFromCert(cert).rows, nc.rows)
	}
	// A different constraint set is not the same, whatever the order.
	other, _ := checkNameConstraints(NameConstraints{PermittedDNS: []string{"homelab.lan"}})
	if sameConstraints(ncFromCert(cert), other) || sameConstraints(other, ncFromCert(cert)) {
		t.Error("different constraints compare equal")
	}

	// NotCritical is the compatibility switch: the same names, not critical.
	nc.critical = false
	if build(nc).PermittedDNSDomainsCritical {
		t.Error("NotCritical still writes a critical extension")
	}
	// No constraints, no extension, and never "critical".
	empty := build(checkedNC{critical: true})
	if empty.PermittedDNSDomainsCritical || len(ncFromCert(empty).rows) != 0 {
		t.Errorf("an empty set wrote constraints: %+v", ncFromCert(empty))
	}
}

// TestOpenSSLReadsTheNameConstraints: an independent reader sees the same
// permitted and excluded names, and the extension is critical.
func TestOpenSSLReadsTheNameConstraints(t *testing.T) {
	t.Parallel()
	nc, problems := checkNameConstraints(NameConstraints{
		PermittedDNS: []string{"homelab.lan"}, ExcludedDNS: []string{"secret.homelab.lan"},
		PermittedIP: []string{"10.0.0.0/8"}, PermittedEmail: []string{"homelab.lan"}, PermittedURI: []string{".homelab.lan"},
	})
	if len(problems) != 0 {
		t.Fatal(problems)
	}
	key := mustKey(t, elliptic.P256())
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(78), Subject: pkix.Name{CommonName: "NC test"}, NotBefore: t0, NotAfter: t0.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	nc.apply(tmpl)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	text := opensslText(t, "x509", der)
	for _, want := range []string{
		"X509v3 Name Constraints: critical", "Permitted:", "DNS:homelab.lan", "IP:10.0.0.0/255.0.0.0", "email:homelab.lan", "URI:.homelab.lan",
		"Excluded:", "DNS:secret.homelab.lan",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("openssl x509 -text lacks %q:\n%s", want, text)
		}
	}
}

// TestIssuingCAWiderThanItsParent: creating the CA works but warns, the
// certificate carries the CA's own constraints, and what the parent doesn't
// permit is refused before signing – by the parent, which the message names.
func TestIssuingCAWiderThanItsParent(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.root(t, "root", nil)
	v.intermediate(t, "policy", "root", func(r *IntermediateRequest) {
		r.PathLen = 1
		r.NameConstraints = NameConstraints{PermittedDNS: []string{"homelab.lan"}}
	})
	wide := v.intermediate(t, "wide", "policy", func(r *IntermediateRequest) {
		r.NameConstraints = NameConstraints{PermittedDNS: []string{"lan", "homelab.lan"}}
	})
	if len(wide.Warnings) != 1 || !strings.Contains(wide.Warnings[0], "permitted DNS name lan is outside the parent's name constraints (homelab.lan)") {
		t.Errorf("warnings %q", wide.Warnings)
	}
	if got := certOf(t, wide).PermittedDNSDomains; strings.Join(got, ",") != "lan,homelab.lan" {
		t.Errorf("the CA certificate permits %v", got)
	}

	if got := v.denied(t, Request{CA: "wide", Preset: "server", DNSNames: []string{"a.other.lan"}}); !strings.Contains(got, `outside the name constraints of CA "policy" (permitted: homelab.lan)`) ||
		strings.Contains(got, `CA "wide"`) {
		t.Errorf("a name only the wide CA permits: %q", got)
	}
	out := v.issue(t, Request{CA: "wide", Preset: "server", DNSNames: []string{"a.homelab.lan"}})
	opensslVerifyAt(t, t0, out.Chain, out.CertDER, "sslserver")
}
