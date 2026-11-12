package tlsscan

import (
	"testing"
	"time"
)

var now = time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)

const day = 24 * time.Hour

var params = Params{UnreachableAfter: 3, MismatchAfter: time.Hour, ExpiryWarn: 14 * day, ExpiryCrit: 3 * day}

// scanned is an endpoint that has been scanned three times with the
// certificate "AA" and a trusted chain, created two days ago.
func scanned(edit func(*Endpoint)) Endpoint {
	ep := Endpoint{
		ID: "ep_1", Host: "proxy.homelab.lan", Port: 443, CreatedAt: now.Add(-48 * time.Hour),
		LastScanAt: now.Add(-time.Minute), LastOKAt: now.Add(-time.Minute), Fingerprint: "AA", ChainState: ChainTrusted,
		SameCount: 3, NotAfter: now.Add(60 * day),
	}
	if edit != nil {
		edit(&ep)
	}
	return ep
}

// issued is a current certificate created age ago.
func issued(fp string, age time.Duration) Issued {
	return Issued{ID: "crt_" + fp, Fingerprint: fp, Serial: "01", NotAfter: now.Add(60 * day), CreatedAt: now.Add(-age)}
}

type want struct {
	state                                string
	mismatch, expiry, unreachable, chain string // severity, "" = no alert
}

func TestAssess(t *testing.T) {
	t.Parallel()
	failing := func(streak int, kind string) func(*Endpoint) {
		return func(e *Endpoint) { e.FailStreak, e.LastErrorKind, e.LastError, e.LastScanAt = streak, kind, kind, now }
	}
	ours := &Known{CoversName: true}
	for _, tc := range []struct {
		name string
		ep   Endpoint
		in   Input
		want want
	}{
		{"never scanned", Endpoint{ID: "ep_1", Host: "proxy.homelab.lan", Port: 443, CreatedAt: now}, Input{Current: []Issued{issued("AA", day)}}, want{state: StatePending}},
		{"the issued certificate with a trusted chain", scanned(nil), Input{Current: []Issued{issued("AA", day)}}, want{state: StateOK}},
		{"fingerprints compare without case", scanned(func(e *Endpoint) { e.Fingerprint = "aa" }), Input{Current: []Issued{issued("AA", day)}}, want{state: StateOK}},
		{"one of two current certificates (exact and wildcard)", scanned(nil), Input{Current: []Issued{issued("BB", day), issued("AA", day)}}, want{state: StateOK}},

		// Chain.
		{"incomplete chain, seen once", scanned(func(e *Endpoint) { e.ChainState, e.SameCount = ChainIncomplete, 1 }), Input{Current: []Issued{issued("AA", day)}}, want{state: StateChain}},
		{"incomplete chain, seen twice", scanned(func(e *Endpoint) { e.ChainState, e.SameCount = ChainIncomplete, 2 }), Input{Current: []Issued{issued("AA", day)}}, want{state: StateChain, chain: Warning}},
		{"untrusted chain, seen twice", scanned(func(e *Endpoint) { e.ChainState, e.SameCount = ChainUntrusted, 2 }), Input{Current: []Issued{issued("AA", day)}}, want{state: StateChain, chain: Warning}},

		// Mismatch: confirmation and grace.
		{"older, the first scan", scanned(func(e *Endpoint) { e.SameCount = 1 }), Input{Current: []Issued{issued("BB", 5*time.Hour)}, Known: ours}, want{state: StateOlder}},
		{"older, confirmed, inside the grace time", scanned(nil), Input{Current: []Issued{issued("BB", 59*time.Minute)}, Known: ours}, want{state: StateOlder}},
		{"older, confirmed, grace over", scanned(nil), Input{Current: []Issued{issued("BB", time.Hour)}, Known: ours}, want{state: StateOlder, mismatch: Warning}},
		{"older, the grace runs from the newest certificate", scanned(nil), Input{Current: []Issued{issued("BB", 5*time.Hour), issued("CC", 10*time.Minute)}, Known: ours}, want{state: StateOlder}},
		{"older, expired and nothing current: no reference, no alert", scanned(func(e *Endpoint) { e.NotAfter = now.Add(-day) }), Input{Known: ours}, want{state: StateOlder, expiry: Critical}},
		{"foreign, confirmed, grace over", scanned(nil), Input{Current: []Issued{issued("BB", 2*time.Hour)}}, want{state: StateForeign, mismatch: Warning}},
		{"foreign, seen once", scanned(func(e *Endpoint) { e.SameCount = 1 }), Input{Current: []Issued{issued("BB", 2*time.Hour)}}, want{state: StateForeign}},
		{"wrong name, confirmed, grace over", scanned(nil), Input{Current: []Issued{issued("BB", 2*time.Hour)}, Known: &Known{CoversName: false}}, want{state: StateWrongName, mismatch: Warning}},
		{"wrong name, nothing issued for the name: no reference", scanned(nil), Input{Known: &Known{CoversName: false}}, want{state: StateWrongName}},
		{"revoked, seen once", scanned(func(e *Endpoint) { e.SameCount = 1 }), Input{Current: []Issued{issued("BB", day)}, Known: &Known{Revoked: true, CoversName: true}}, want{state: StateRevoked}},
		{"revoked, seen twice: no grace", scanned(func(e *Endpoint) { e.SameCount = 2 }), Input{Current: []Issued{issued("BB", time.Minute)}, Known: &Known{Revoked: true, CoversName: true}}, want{state: StateRevoked, mismatch: Critical}},
		{"revoked and nothing current", scanned(nil), Input{Known: &Known{Revoked: true}}, want{state: StateRevoked, mismatch: Critical}},

		// Unmanaged.
		{"a name never issued for, a foreign certificate", scanned(nil), Input{}, want{state: StateUnmanaged}},
		{"an IP endpoint without SNI", scanned(func(e *Endpoint) { e.Host = "192.0.2.10" }), Input{Known: &Known{CoversName: false}}, want{state: StateUnmanaged}},
		{"an IP endpoint without SNI, foreign", scanned(func(e *Endpoint) { e.Host = "192.0.2.10" }), Input{}, want{state: StateUnmanaged}},
		{"an IP endpoint with an SNI nothing was issued for", scanned(func(e *Endpoint) { e.Host, e.SNI = "192.0.2.10", "app.homelab.lan" }), Input{}, want{state: StateUnmanaged}},
		{"an IP endpoint without SNI but an IP certificate exists", scanned(func(e *Endpoint) { e.Host = "192.0.2.10" }), Input{Current: []Issued{issued("BB", 2*time.Hour)}}, want{state: StateForeign, mismatch: Warning}},
		{"an IP endpoint served the right IP certificate", scanned(func(e *Endpoint) { e.Host = "192.0.2.10" }), Input{Current: []Issued{issued("AA", day)}}, want{state: StateOK}},

		// Unreachable: a reboot alerts nothing.
		{"one failed scan keeps the last state", scanned(failing(1, KindConnRefused)), Input{Current: []Issued{issued("AA", day)}}, want{state: StateOK}},
		{"two failed scans keep the last state", scanned(failing(2, KindTimeout)), Input{Current: []Issued{issued("AA", day)}}, want{state: StateOK}},
		{"two failed scans keep an alert state too", scanned(failing(2, KindTimeout)), Input{Current: []Issued{issued("BB", 2*time.Hour)}, Known: ours}, want{state: StateOlder, mismatch: Warning}},
		{"the third failed scan", scanned(failing(3, KindConnRefused)), Input{Current: []Issued{issued("AA", day)}}, want{state: StateUnreachable, unreachable: Warning}},
		{"every kind that counts", scanned(failing(3, KindHandshake)), Input{}, want{state: StateUnreachable, unreachable: Warning}},
		{"down for a day", scanned(func(e *Endpoint) { failing(5, KindTimeout)(e); e.LastOKAt = now.Add(-24 * time.Hour) }), Input{}, want{state: StateUnreachable, unreachable: Critical}},
		{"down for 23 hours", scanned(func(e *Endpoint) { failing(5, KindTimeout)(e); e.LastOKAt = now.Add(-23 * time.Hour) }), Input{}, want{state: StateUnreachable, unreachable: Warning}},
		{"never reachable, counted from the creation", scanned(func(e *Endpoint) {
			failing(40, KindDNS)(e)
			e.LastOKAt, e.Fingerprint = time.Time{}, ""
		}), Input{}, want{state: StateUnreachable, unreachable: Critical}},
		{"a failure streak of a new endpoint below the threshold", scanned(func(e *Endpoint) { failing(1, KindDNS)(e); e.LastOKAt, e.Fingerprint = time.Time{}, "" }), Input{}, want{state: StatePending}},
		{"a client certificate demand is no outage", scanned(failing(5, KindClientCert)), Input{}, want{state: StateUnreachable}},

		// Refused.
		{"no domain covers the host", scanned(failing(1, KindRefusedDomain)), Input{Current: []Issued{issued("AA", day)}}, want{state: StateRefused}},
		{"the guard refuses the address", scanned(failing(9, KindRefusedPolicy)), Input{}, want{state: StateRefused}},
		{"the port left the list", scanned(failing(1, KindRefusedPort)), Input{}, want{state: StateRefused}},

		// Expiry of what is served.
		{"expiry in 15 days", scanned(func(e *Endpoint) { e.NotAfter = now.Add(15 * day) }), Input{Current: []Issued{issued("AA", day)}}, want{state: StateOK}},
		{"expiry in 14 days", scanned(func(e *Endpoint) { e.NotAfter = now.Add(14 * day) }), Input{Current: []Issued{issued("AA", day)}}, want{state: StateOK, expiry: Warning}},
		{"expiry in 3 days", scanned(func(e *Endpoint) { e.NotAfter = now.Add(3 * day) }), Input{Current: []Issued{issued("AA", day)}}, want{state: StateOK, expiry: Critical}},
		{"expired", scanned(func(e *Endpoint) { e.NotAfter = now.Add(-time.Second) }), Input{Current: []Issued{issued("AA", day)}}, want{state: StateOK, expiry: Critical}},
		{"expiry of a foreign certificate", scanned(func(e *Endpoint) { e.NotAfter = now.Add(2 * day) }), Input{}, want{state: StateUnmanaged, expiry: Critical}},
		{"expiry of a superseded certificate", scanned(func(e *Endpoint) { e.NotAfter = now.Add(10 * day) }), Input{Current: []Issued{issued("BB", day)}, Known: ours}, want{state: StateOlder, mismatch: Warning, expiry: Warning}},
		{"expiry is not judged while unreachable", scanned(func(e *Endpoint) { failing(3, KindTimeout)(e); e.NotAfter = now.Add(day) }), Input{}, want{state: StateUnreachable, unreachable: Warning}},
		{"expiry is not judged when refused", scanned(func(e *Endpoint) { failing(1, KindRefusedDomain)(e); e.NotAfter = now.Add(day) }), Input{}, want{state: StateRefused}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := Assess(tc.ep, tc.in, params, now)
			sev := func(a *Alarm) string {
				if a == nil {
					return ""
				}
				return a.Severity
			}
			have := want{got.State, sev(got.Mismatch), sev(got.Expiry), sev(got.Unreachable), sev(got.Chain)}
			if have != tc.want {
				t.Errorf("got %+v, want %+v", have, tc.want)
			}
		})
	}
}

func TestAssessThresholdOfOne(t *testing.T) {
	t.Parallel()
	ep := scanned(func(e *Endpoint) { e.FailStreak, e.LastErrorKind, e.LastScanAt = 1, KindTimeout, now })
	p := params
	p.UnreachableAfter = 1
	if a := Assess(ep, Input{}, p, now); a.State != StateUnreachable || a.Unreachable == nil {
		t.Errorf("%+v", a)
	}
}

func TestAssessIsPure(t *testing.T) {
	t.Parallel()
	ep := scanned(nil)
	in := Input{Current: []Issued{issued("BB", 3*time.Hour)}, Known: &Known{CoversName: true}}
	before := ep
	a := Assess(ep, in, params, now)
	b := Assess(ep, in, params, now)
	if a.State != b.State || ep.Fingerprint != before.Fingerprint || len(in.Current) != 1 {
		t.Error("Assess changed its input or is not deterministic")
	}
	if a.Newest == nil || a.Newest.Fingerprint != "BB" || !a.ServedIsOurs {
		t.Errorf("assessment: %+v", a)
	}
}

func TestCoversName(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		dns, ips []string
		name     string
		want     bool
	}{
		{[]string{"proxy.homelab.lan"}, nil, "proxy.homelab.lan", true},
		{[]string{"Proxy.HomeLab.LAN."}, nil, "proxy.homelab.lan", true},
		{[]string{"proxy.homelab.lan"}, nil, "PROXY.homelab.lan.", true},
		{[]string{"proxy.homelab.lan"}, nil, "other.homelab.lan", false},
		{[]string{"*.homelab.lan"}, nil, "proxy.homelab.lan", true},
		{[]string{"*.homelab.lan"}, nil, "a.b.homelab.lan", false}, // one label only
		{[]string{"*.homelab.lan"}, nil, "homelab.lan", false},     // not the apex
		{[]string{"*.homelab.lan"}, nil, ".homelab.lan", false},    // no label
		{[]string{"*.homelab.lan"}, nil, "xhomelab.lan", false},    // the dot matters
		{[]string{"*.lan"}, nil, "proxy.lan", false},               // too broad to count
		{[]string{"*.com"}, nil, "example.com", false},
		{[]string{"*.homelab.lan"}, nil, "*.homelab.lan", false},           // an endpoint is never a wildcard
		{[]string{"proxy.*.lan"}, nil, "proxy.homelab.lan", false},         // only the leftmost label
		{[]string{"proxy*.homelab.lan"}, nil, "proxy1.homelab.lan", false}, // only a whole label
		{[]string{"*.homelab.lan", "proxy.homelab.lan"}, nil, "proxy.homelab.lan", true},
		{nil, []string{"192.0.2.10"}, "192.0.2.10", true},
		{nil, []string{"192.0.2.10"}, "::ffff:192.0.2.10", true},
		{nil, []string{"2001:db8::1"}, "2001:db8:0::1", true},
		{nil, []string{"192.0.2.10"}, "192.0.2.11", false},
		{[]string{"192.0.2.10"}, nil, "192.0.2.10", false}, // a DNS name that looks like an IP is no IP name
		{nil, nil, "proxy.homelab.lan", false},
		{[]string{"proxy.homelab.lan"}, nil, "", false},
	} {
		if got := CoversName(tc.dns, tc.ips, tc.name); got != tc.want {
			t.Errorf("CoversName(%v, %v, %q) = %v, want %v", tc.dns, tc.ips, tc.name, got, tc.want)
		}
	}
}

func TestKnownKind(t *testing.T) {
	t.Parallel()
	for _, k := range []string{KindDNS, KindTimeout, KindConnRefused, KindCouldNotConnect, KindHandshake, KindNoCertificate, KindClientCert, KindRefusedPolicy, KindRefusedDomain, KindRefusedPort} {
		if !KnownKind(k) {
			t.Errorf("%q is not known", k)
		}
	}
	for _, k := range []string{"", "<script>", "remote said SECRET", "tls: bad certificate"} {
		if KnownKind(k) {
			t.Errorf("%q is known", k)
		}
	}
}
