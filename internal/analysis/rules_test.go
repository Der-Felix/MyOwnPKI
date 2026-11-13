package analysis

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
)

// now is a Friday in ISO week 2026-W46.
var now = time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)

const hour = time.Hour

// cert is a valid, current ACME certificate of 90 days that is 30 days old;
// mod changes it.
func cert(id string, mod ...func(*Certificate)) Certificate {
	c := Certificate{
		ID: id, Serial: "AB" + id, Fingerprint: "FP" + strings.ToUpper(id), Source: "issued", CAID: "ca-1", CAName: "issuing",
		DNSNames: []string{id + ".homelab.lan"}, Class: ca.SourceACME, IssuerKey: "acme:acc-1",
		NotBefore: now.Add(-30 * day), NotAfter: now.Add(60 * day), CreatedAt: now.Add(-30 * day),
		Traits: &ca.Traits{KeyAlgorithm: ca.TraitECDSA, KeyBits: 256, Signature: x509.ECDSAWithSHA256},
	}
	for _, m := range mod {
		m(&c)
	}
	return c
}

func names(n ...string) func(*Certificate) { return func(c *Certificate) { c.DNSNames = n } }

func issuer(class, key string) func(*Certificate) {
	return func(c *Certificate) { c.Class, c.IssuerKey = class, key }
}

func created(t time.Time) func(*Certificate) { return func(c *Certificate) { c.CreatedAt = t } }

func ends(t time.Time) func(*Certificate) { return func(c *Certificate) { c.NotAfter = t } }

// fixture loads a committed PEM and parses its traits through the same path
// the engine uses.
func fixture(t *testing.T, file string) ca.Traits {
	t.Helper()
	data, err := os.ReadFile("testdata/" + file)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("%s: no PEM block", file)
	}
	tr, err := ca.TraitsOf(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

// want checks state, counts and the number of unassessed things of a result.
func want(t *testing.T, name string, r Result, state string, findings, unassessed int) {
	t.Helper()
	if r.State != state || r.Counts.Total() != findings || len(r.Findings) != findings || r.Unassessed != unassessed {
		t.Errorf("%s: state %s, %d findings (%d kept), %d unassessed (%q); want %s, %d, %d", name, r.State, r.Counts.Total(), len(r.Findings),
			r.Unassessed, r.UnknownReason, state, findings, unassessed)
	}
	if (state == StateUnknown || unassessed > 0) && r.UnknownReason == "" {
		t.Errorf("%s: unknown without a reason", name)
	}
	if state == StateOK && r.UnknownReason != "" {
		t.Errorf("%s: ok with a reason %q", name, r.UnknownReason)
	}
	for _, f := range r.Findings {
		if f.Key == "" || f.Rule == "" || f.Subject == "" || f.Seen == "" || f.Why == "" || f.Recommendation == "" {
			t.Errorf("%s: incomplete finding %+v", name, f)
		}
	}
}

// endpoint covers "<id>.homelab.lan", was scanned an hour ago and has served
// another certificate for 10 days.
func endpoint(id string, mod ...func(*Endpoint)) Endpoint {
	e := Endpoint{ID: "ep-" + id, Host: id + ".homelab.lan", Port: 443, Name: id + ".homelab.lan",
		LastOKAt: now.Add(-hour), Fingerprint: "OTHER", FingerprintSince: now.Add(-10 * day)}
	for _, m := range mod {
		m(&e)
	}
	return e
}

// --- orphaned_certificate -----------------------------------------------------

func TestOrphanedCertificate(t *testing.T) {
	t.Parallel()
	c := cert("a")
	snap := func(certs []Certificate, eps ...Endpoint) Snapshot {
		return Snapshot{Now: now, Certificates: certs, Endpoints: eps}
	}

	t.Run("fires", func(t *testing.T) {
		t.Parallel()
		r := OrphanedCertificate(snap([]Certificate{c}, endpoint("a")))
		want(t, "fires", r, StateFindings, 1, 0)
		f := r.Findings[0]
		if f.Severity != SeverityInfo || f.Key != "orphaned_certificate:a" || f.Href != "/certificates/a" || f.Subject != "a.homelab.lan" {
			t.Errorf("finding %+v", f)
		}
		if !strings.Contains(f.Seen, "1 scanned endpoint") || !strings.Contains(f.Seen, "no agent deployment") {
			t.Errorf("seen: %s", f.Seen)
		}
		// A finding says "not seen", never "unused" (D9).
		for _, text := range []string{f.Seen, f.Why, f.Recommendation} {
			if strings.Contains(strings.ToLower(text), "unused") || strings.Contains(strings.ToLower(text), "not used") {
				t.Errorf("claims too much: %s", text)
			}
		}
	})
	t.Run("two endpoints", func(t *testing.T) {
		t.Parallel()
		r := OrphanedCertificate(snap([]Certificate{c}, endpoint("a"), endpoint("a", func(e *Endpoint) { e.ID = "ep-2" })))
		want(t, "two endpoints", r, StateFindings, 1, 0)
		if !strings.Contains(r.Findings[0].Seen, "2 scanned endpoints") {
			t.Errorf("seen: %s", r.Findings[0].Seen)
		}
	})
	t.Run("wildcard certificate covers the endpoint", func(t *testing.T) {
		t.Parallel()
		w := cert("w", names("*.homelab.lan"))
		want(t, "wildcard", OrphanedCertificate(snap([]Certificate{w}, endpoint("proxy"))), StateFindings, 1, 0)
	})
	t.Run("an endpoint serves it", func(t *testing.T) {
		t.Parallel()
		want(t, "served", OrphanedCertificate(snap([]Certificate{c}, endpoint("a", func(e *Endpoint) { e.Fingerprint = "fpa" }))), StateOK, 0, 0)
	})
	t.Run("one endpoint serves it, another does not", func(t *testing.T) {
		t.Parallel()
		served := endpoint("a", func(e *Endpoint) { e.Fingerprint = c.Fingerprint })
		want(t, "served elsewhere", OrphanedCertificate(snap([]Certificate{c}, endpoint("a"), served)), StateOK, 0, 0)
	})
	t.Run("an agent deployed it", func(t *testing.T) {
		t.Parallel()
		for name, dep := range map[string]Deployment{
			"serial":      {State: "deployed", Serial: "ab" + "a"},
			"id":          {State: "deployed", CertificateID: "a"},
			"fingerprint": {State: "deployed", Fingerprint: "fpa"},
		} {
			s := snap([]Certificate{c}, endpoint("a"))
			s.Agents = []Agent{{ID: "agt", Status: "active", Deployments: []Deployment{dep}}}
			want(t, "deployed by "+name, OrphanedCertificate(s), StateOK, 0, 0)
		}
		// A pending, failed or removed deployment is no proof of use.
		for name, dep := range map[string]Deployment{
			"pending": {State: "pending", Serial: "ABa"}, "failed": {State: "failed", Serial: "ABa"}, "removed": {State: "deployed", Serial: "ABa", Removed: true},
		} {
			s := snap([]Certificate{c}, endpoint("a"))
			s.Agents = []Agent{{ID: "agt", Status: "active", Deployments: []Deployment{dep}}}
			want(t, name+" deployment", OrphanedCertificate(s), StateFindings, 1, 0)
		}
	})
	t.Run("age boundary", func(t *testing.T) {
		t.Parallel()
		fresh := cert("a", created(now.Add(-14*day+time.Second)))
		want(t, "14 days minus a second", OrphanedCertificate(snap([]Certificate{fresh}, endpoint("a"))), StateOK, 0, 0)
		exact := cert("a", created(now.Add(-14*day)))
		want(t, "exactly 14 days", OrphanedCertificate(snap([]Certificate{exact}, endpoint("a"))), StateFindings, 1, 0)
	})
	t.Run("scan window boundary", func(t *testing.T) {
		t.Parallel()
		// The last good scan must be less than 7 days old.
		old := endpoint("a", func(e *Endpoint) { e.LastOKAt = now.Add(-7 * day) })
		want(t, "last scan 7 days ago", OrphanedCertificate(snap([]Certificate{c}, old)), StateUnknown, 0, 1)
		recent := endpoint("a", func(e *Endpoint) { e.LastOKAt = now.Add(-7*day + time.Second) })
		want(t, "last scan just inside", OrphanedCertificate(snap([]Certificate{c}, recent)), StateFindings, 1, 0)
		// The other certificate must have been served for at least 7 days.
		since := endpoint("a", func(e *Endpoint) { e.FingerprintSince = now.Add(-7*day + time.Second) })
		want(t, "other certificate for just under 7 days", OrphanedCertificate(snap([]Certificate{c}, since)), StateUnknown, 0, 1)
		exact := endpoint("a", func(e *Endpoint) { e.FingerprintSince = now.Add(-7 * day) })
		want(t, "other certificate for exactly 7 days", OrphanedCertificate(snap([]Certificate{c}, exact)), StateFindings, 1, 0)
	})
	t.Run("superseded and future certificates are not judged", func(t *testing.T) {
		t.Parallel()
		newer := cert("a2", names("a.homelab.lan"), ends(now.Add(80*day)))
		older := cert("a", names("a.homelab.lan"))
		want(t, "superseded", OrphanedCertificate(snap([]Certificate{older, newer}, endpoint("a"))), StateFindings, 1, 0) // only the newer one
		future := cert("a", func(c *Certificate) { c.NotBefore = now.Add(time.Hour) })
		want(t, "not yet valid", OrphanedCertificate(snap([]Certificate{future}, endpoint("a"))), StateOK, 0, 0)
	})

	// Unknown: scanning off, no endpoint, or no endpoint with a stable result.
	t.Run("scan off", func(t *testing.T) {
		t.Parallel()
		s := snap([]Certificate{c}, endpoint("a"))
		s.Missing.Scan = "the TLS scan is off, so no endpoint was scanned."
		r := OrphanedCertificate(s)
		want(t, "scan off", r, StateUnknown, 0, 0)
		if r.UnknownReason != s.Missing.Scan {
			t.Errorf("reason %q", r.UnknownReason)
		}
	})
	t.Run("no endpoint covers them: one summary, never one line per certificate", func(t *testing.T) {
		t.Parallel()
		r := OrphanedCertificate(snap([]Certificate{cert("a"), cert("b"), cert("c")}))
		want(t, "uncovered", r, StateUnknown, 0, 3)
		if !strings.Contains(r.UnknownReason, "3 certificates cannot be checked") {
			t.Errorf("reason %q", r.UnknownReason)
		}
		one := OrphanedCertificate(snap([]Certificate{cert("a")}))
		if !strings.HasPrefix(one.UnknownReason, "1 certificate cannot be checked") || !strings.Contains(one.UnknownReason, "covers it") {
			t.Errorf("singular reason %q", one.UnknownReason)
		}
	})
	t.Run("findings and unassessed together", func(t *testing.T) {
		t.Parallel()
		r := OrphanedCertificate(snap([]Certificate{cert("a"), cert("b")}, endpoint("a")))
		want(t, "mixed", r, StateFindings, 1, 1)
	})
	t.Run("an endpoint that never succeeded is no witness", func(t *testing.T) {
		t.Parallel()
		never := endpoint("a", func(e *Endpoint) { e.LastOKAt, e.Fingerprint, e.FingerprintSince = time.Time{}, "", time.Time{} })
		want(t, "never scanned", OrphanedCertificate(snap([]Certificate{c}, never)), StateUnknown, 0, 1)
	})
}

// --- duplicate_certificates ---------------------------------------------------

func TestDuplicateCertificates(t *testing.T) {
	t.Parallel()
	ui := issuer(ca.SourceUI, "ui")
	acme := issuer(ca.SourceACME, "acme:acc-1")
	agent := issuer(ca.SourceAgent, "agent:agt-1")
	snap := func(certs ...Certificate) Snapshot { return Snapshot{Now: now, Certificates: certs} }
	same := names("nas.homelab.lan", "files.homelab.lan")

	t.Run("two sources fire", func(t *testing.T) {
		t.Parallel()
		r := DuplicateCertificates(snap(cert("a", same, ui), cert("b", same, acme)))
		want(t, "two sources", r, StateFindings, 1, 0)
		f := r.Findings[0]
		if f.Severity != SeverityWarning || f.Subject != "files.homelab.lan, nas.homelab.lan" || !strings.HasPrefix(f.Key, "duplicate_certificates:") {
			t.Errorf("finding %+v", f)
		}
		for _, s := range []string{"2 valid certificates", "2 sources", "ACME account acc-1", "the UI or API"} {
			if !strings.Contains(f.Seen, s) {
				t.Errorf("seen lacks %q: %s", s, f.Seen)
			}
		}
		// The name order and case do not matter.
		r2 := DuplicateCertificates(snap(cert("a", names("NAS.homelab.lan.", "files.homelab.lan"), ui), cert("b", same, acme)))
		want(t, "name normalization", r2, StateFindings, 1, 0)
		if r2.Findings[0].Key != f.Key {
			t.Errorf("keys differ: %s %s", r2.Findings[0].Key, f.Key)
		}
	})
	t.Run("three sources are one finding", func(t *testing.T) {
		t.Parallel()
		r := DuplicateCertificates(snap(cert("a", same, ui), cert("b", same, acme), cert("c", same, agent)))
		want(t, "three sources", r, StateFindings, 1, 0)
		if !strings.Contains(r.Findings[0].Seen, "3 sources") {
			t.Errorf("seen: %s", r.Findings[0].Seen)
		}
	})
	t.Run("one source, two certificates: renewal overlap", func(t *testing.T) {
		t.Parallel()
		want(t, "overlap", DuplicateCertificates(snap(cert("a", same, acme), cert("b", same, acme))), StateOK, 0, 0)
	})
	t.Run("one source, three certificates: info", func(t *testing.T) {
		t.Parallel()
		r := DuplicateCertificates(snap(cert("a", same, acme), cert("b", same, acme), cert("c", same, acme)))
		want(t, "three from one", r, StateFindings, 1, 0)
		if r.Findings[0].Severity != SeverityInfo || !strings.Contains(r.Findings[0].Seen, "one source") {
			t.Errorf("finding %+v", r.Findings[0])
		}
	})
	t.Run("different names are no duplicates", func(t *testing.T) {
		t.Parallel()
		want(t, "different names", DuplicateCertificates(snap(cert("a", ui), cert("b", acme))), StateOK, 0, 0)
	})
	t.Run("a certificate near its end is a renewal overlap", func(t *testing.T) {
		t.Parallel()
		// 90-day lifetime: more than a third left means more than 30 days.
		lifetime := 90 * day
		old := func(left time.Duration) Certificate {
			return cert("b", same, acme, func(c *Certificate) { c.NotBefore, c.NotAfter = now.Add(left-lifetime), now.Add(left) })
		}
		want(t, "exactly a third left", DuplicateCertificates(snap(cert("a", same, ui), old(30*day))), StateOK, 0, 0)
		want(t, "a second more than a third", DuplicateCertificates(snap(cert("a", same, ui), old(30*day+time.Second))), StateFindings, 1, 0)
	})
	t.Run("imported and external certificates are not issuances", func(t *testing.T) {
		t.Parallel()
		imported := cert("b", same, func(c *Certificate) { c.Source, c.Class, c.IssuerKey = "imported", "", "" })
		want(t, "imported", DuplicateCertificates(snap(cert("a", same, ui), imported)), StateOK, 0, 0)
	})
	t.Run("unknown origin", func(t *testing.T) {
		t.Parallel()
		blind := cert("b", same, func(c *Certificate) { c.Class, c.IssuerKey = "", "" })
		r := DuplicateCertificates(snap(cert("a", same, ui), blind))
		want(t, "unknown origin", r, StateUnknown, 0, 1)
		// A group that can be judged still fires next to one that cannot.
		other := names("web.homelab.lan")
		r = DuplicateCertificates(snap(cert("a", same, ui), blind, cert("c", other, ui), cert("d", other, acme)))
		want(t, "mixed", r, StateFindings, 1, 1)
	})
	t.Run("a hostile name is clipped, raw and not part of the key", func(t *testing.T) {
		t.Parallel()
		evil := names(`<script>alert("x")</script>` + strings.Repeat("a", 4000) + ".lan")
		r := DuplicateCertificates(snap(cert("a", evil, ui), cert("b", evil, acme)))
		want(t, "hostile", r, StateFindings, 1, 0)
		f := r.Findings[0]
		if !strings.HasPrefix(f.Subject, `<script>alert("x")</script>`) || utf8.RuneCountInString(f.Subject) > maxClip {
			t.Errorf("subject %q (%d runes)", f.Subject[:40], utf8.RuneCountInString(f.Subject))
		}
		if len(f.Key) > 64 || strings.ContainsAny(f.Key, "<\"> ") {
			t.Errorf("key %q", f.Key)
		}
	})
}

// --- renewal_loop -------------------------------------------------------------

func TestRenewalLoop(t *testing.T) {
	t.Parallel()
	same := names("api.homelab.lan")
	// n certificates created every 10 minutes, the newest 10 minutes ago.
	loop := func(n int, mod ...func(*Certificate)) []Certificate {
		var out []Certificate
		for i := range n {
			c := cert("l"+string(rune('a'+i)), same, created(now.Add(-time.Duration(i+1)*10*time.Minute)))
			for _, m := range mod {
				m(&c)
			}
			out = append(out, c)
		}
		return out
	}
	run := func(recent []Certificate) Result { return RenewalLoop(Snapshot{Now: now, Recent: recent}) }

	want(t, "none", run(nil), StateOK, 0, 0)
	want(t, "two in a day", run(loop(2)), StateOK, 0, 0)
	for n, sev := range map[int]string{3: SeverityWarning, 5: SeverityWarning, 6: SeverityCritical, 12: SeverityCritical} {
		r := run(loop(n))
		want(t, "n in a day", r, StateFindings, 1, 0)
		if r.Findings[0].Severity != sev {
			t.Errorf("%d in a day: %s, want %s", n, r.Findings[0].Severity, sev)
		}
	}
	r := run(loop(3, issuer(ca.SourceAgent, "agent:agt-9")))
	if !strings.Contains(r.Findings[0].Seen, "3 certificates") || !strings.Contains(r.Findings[0].Seen, "agent agt-9") || r.Findings[0].Href == "" {
		t.Errorf("seen: %s", r.Findings[0].Seen)
	}
	// Revoked or expired certificates are still certificates a client got:
	// Recent carries them, and only their creation counts.
	want(t, "revoked ones count", run(loop(3, func(c *Certificate) { c.NotAfter = now.Add(-day) })), StateFindings, 1, 0)

	t.Run("24 hour boundary", func(t *testing.T) {
		t.Parallel()
		two := loop(2)
		edge := cert("e", same, created(now.Add(-loopDay))) // exactly a day: no longer "in a day"
		want(t, "third one exactly 24h old", run(append(two, edge)), StateOK, 0, 0)
		in := cert("e", same, created(now.Add(-loopDay+time.Second)))
		want(t, "third one just inside", run(append(two, in)), StateFindings, 1, 0)
	})
	t.Run("eight in a week", func(t *testing.T) {
		t.Parallel()
		var week []Certificate
		for i := range 8 {
			week = append(week, cert("w"+string(rune('a'+i)), same, created(now.Add(-time.Duration(i)*20*hour-2*hour))))
		}
		r := run(week)
		want(t, "eight in a week", r, StateFindings, 1, 0)
		if r.Findings[0].Severity != SeverityWarning || !strings.Contains(r.Findings[0].Seen, "8 certificates for these names were created in the last 7 days") {
			t.Errorf("finding %+v", r.Findings[0])
		}
		want(t, "seven in a week", run(week[:7]), StateOK, 0, 0)
		// The 7 day window is exclusive at the old end.
		week[7].CreatedAt = now.Add(-RecentWindow)
		want(t, "one exactly 7 days old", run(week), StateOK, 0, 0)
	})
	t.Run("only issued certificates, only the same names", func(t *testing.T) {
		t.Parallel()
		imported := loop(3, func(c *Certificate) { c.Source = "imported" })
		want(t, "imported", run(imported), StateOK, 0, 0)
		a, b, c := cert("x", names("a.lan"), created(now.Add(-hour))), cert("y", names("b.lan"), created(now.Add(-hour))), cert("z", names("c.lan"), created(now.Add(-hour)))
		want(t, "different names", run([]Certificate{a, b, c}), StateOK, 0, 0)
	})
}

// --- expiry_wave --------------------------------------------------------------

func TestExpiryWave(t *testing.T) {
	t.Parallel()
	// Monday 2026-11-23 is the start of 2026-W48.
	w48 := time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC)
	spread := func(n int) []Certificate { // one certificate per week, from week 49 on
		var out []Certificate
		for i := range n {
			out = append(out, cert("s"+string(rune('a'+i%26))+string(rune('a'+i/26)), ends(w48.Add(time.Duration(i+7)*7*day+hour))))
		}
		return out
	}
	inWeek := func(n int, at time.Time) []Certificate {
		var out []Certificate
		for i := range n {
			out = append(out, cert("v"+string(rune('a'+i%26))+string(rune('a'+i/26)), ends(at.Add(time.Duration(i)*time.Second))))
		}
		return out
	}
	run := func(certs []Certificate) Result { return ExpiryWave(Snapshot{Now: now, Certificates: certs}) }

	r := run(append(spread(10), inWeek(10, w48.Add(2*day))...))
	want(t, "fires", r, StateFindings, 1, 0)
	f := r.Findings[0]
	if f.Severity != SeverityWarning || f.Key != "expiry_wave:2026-W48" || !strings.Contains(f.Seen, "10 of 20 valid certificates end in week 2026-W48") ||
		!strings.Contains(f.Recommendation, "jitter") {
		t.Errorf("finding %+v", f)
	}
	// Unknown below 20 certificates, however clustered.
	r = run(inWeek(19, w48))
	want(t, "19 certificates", r, StateUnknown, 0, 0)
	if !strings.Contains(r.UnknownReason, "19 valid certificates") || !strings.Contains(r.UnknownReason, "20") {
		t.Errorf("reason %q", r.UnknownReason)
	}
	want(t, "no certificates", run(nil), StateUnknown, 0, 0)
	want(t, "exactly 20", run(inWeek(20, w48)), StateFindings, 1, 0)
	// At least 10 in the week.
	want(t, "9 of 20", run(append(spread(11), inWeek(9, w48)...)), StateOK, 0, 0)
	// At least 30%: 29 of 100 no, 30 of 100 yes.
	want(t, "29 of 100", run(append(spread(71), inWeek(29, w48)...)), StateOK, 0, 0)
	want(t, "30 of 100", run(append(spread(70), inWeek(30, w48)...)), StateFindings, 1, 0)
	// Two heavy weeks are two findings.
	two := append(inWeek(10, w48), inWeek(10, w48.Add(7*day))...)
	want(t, "two weeks", run(two), StateFindings, 2, 0)
	// Week borders: Sunday 23:59:59 belongs to W47, Monday 00:00:00 to W48.
	borders := append(inWeek(5, w48.Add(-time.Second)), inWeek(15, w48)...)
	want(t, "borders", run(borders), StateFindings, 1, 0)
	if k := run(borders).Findings[0].Key; k != "expiry_wave:2026-W48" {
		t.Errorf("key %s", k)
	}
	// 53-week year: 2026-12-28 is the Monday of 2026-W53.
	r = run(inWeek(20, time.Date(2027, 1, 3, 12, 0, 0, 0, time.UTC)))
	want(t, "W53", r, StateFindings, 1, 0)
	if r.Findings[0].Key != "expiry_wave:2026-W53" {
		t.Errorf("key %s", r.Findings[0].Key)
	}
}

// --- weak_key -----------------------------------------------------------------

func TestWeakKey(t *testing.T) {
	t.Parallel()
	rsa := func(bits int) Certificate {
		return cert("k", func(c *Certificate) {
			c.Traits = &ca.Traits{KeyAlgorithm: ca.TraitRSA, KeyBits: bits, Signature: x509.SHA256WithRSA}
		})
	}
	run := func(certs ...Certificate) Result { return WeakKey(Snapshot{Now: now, Certificates: certs}) }

	r := run(rsa(1024))
	want(t, "RSA 1024", r, StateFindings, 1, 0)
	f := r.Findings[0]
	if f.Severity != SeverityCritical || f.Key != "weak_key:k" || !strings.Contains(f.Seen, "RSA 1024 bits") || !strings.Contains(f.Why, "RSA 1024 bits can be factored") {
		t.Errorf("finding %+v", f)
	}
	want(t, "RSA 2047", run(rsa(2047)), StateFindings, 1, 0)
	want(t, "RSA 2048 is not flagged", run(rsa(2048)), StateOK, 0, 0)
	want(t, "RSA 3072", run(rsa(3072)), StateOK, 0, 0)
	want(t, "ECDSA", run(cert("e")), StateOK, 0, 0)
	want(t, "Ed25519", run(cert("e", func(c *Certificate) { c.Traits = &ca.Traits{KeyAlgorithm: ca.TraitEd25519} })), StateOK, 0, 0)
	want(t, "no certificates", run(), StateOK, 0, 0)

	// Unknown: the DER could not be parsed, or the size is missing.
	blind := cert("b", func(c *Certificate) { c.Traits = nil })
	r = run(blind)
	want(t, "unparsed", r, StateUnknown, 0, 1)
	if !strings.Contains(r.UnknownReason, "1 certificate could not be read") {
		t.Errorf("reason %q", r.UnknownReason)
	}
	want(t, "RSA without size", run(rsa(0)), StateUnknown, 0, 1)
	want(t, "finding and unparsed", run(rsa(1024), blind), StateFindings, 1, 1)

	// The committed fixture: a real RSA 1024 certificate.
	tr := fixture(t, "weak-key-rsa1024.pem")
	if tr.KeyAlgorithm != ca.TraitRSA || tr.KeyBits != 1024 {
		t.Fatalf("fixture traits %+v", tr)
	}
	want(t, "fixture", run(cert("fx", func(c *Certificate) { c.Traits = &tr })), StateFindings, 1, 0)
}

// --- weak_signature -----------------------------------------------------------

func TestWeakSignature(t *testing.T) {
	t.Parallel()
	signed := func(a x509.SignatureAlgorithm) Certificate {
		return cert("s", func(c *Certificate) { c.Traits = &ca.Traits{KeyAlgorithm: ca.TraitRSA, KeyBits: 2048, Signature: a} })
	}
	run := func(s Snapshot) Result { s.Now = now; return WeakSignature(s) }
	one := func(c Certificate) Snapshot { return Snapshot{Certificates: []Certificate{c}} }

	for _, a := range []x509.SignatureAlgorithm{x509.SHA1WithRSA, x509.MD5WithRSA, x509.MD2WithRSA, x509.ECDSAWithSHA1, x509.DSAWithSHA1} {
		r := run(one(signed(a)))
		want(t, a.String(), r, StateFindings, 1, 0)
		if r.Findings[0].Severity != SeverityCritical || !strings.Contains(r.Findings[0].Seen, a.String()) || !strings.Contains(r.Findings[0].Why, "Baseline Requirements") {
			t.Errorf("%s: %+v", a, r.Findings[0])
		}
	}
	for _, a := range []x509.SignatureAlgorithm{x509.SHA256WithRSA, x509.SHA384WithRSA, x509.ECDSAWithSHA256, x509.PureEd25519, x509.SHA256WithRSAPSS} {
		want(t, a.String(), run(one(signed(a))), StateOK, 0, 0)
	}
	// Unknown algorithm or unparsed DER: not judged.
	want(t, "unknown algorithm", run(one(signed(x509.UnknownSignatureAlgorithm))), StateUnknown, 0, 1)
	want(t, "unparsed", run(one(cert("b", func(c *Certificate) { c.Traits = nil }))), StateUnknown, 0, 1)

	// The committed fixture: a real SHA-1 certificate.
	tr := fixture(t, "weak-signature-sha1.pem")
	if tr.Signature != x509.SHA1WithRSA || tr.KeyBits != 2048 {
		t.Fatalf("fixture traits %+v", tr)
	}
	want(t, "fixture", run(one(cert("fx", func(c *Certificate) { c.Traits = &tr }))), StateFindings, 1, 0)
	// The other fixture is signed with SHA-256: a weak key is not a weak signature.
	good := fixture(t, "weak-key-rsa1024.pem")
	want(t, "other fixture", run(one(cert("fx", func(c *Certificate) { c.Traits = &good }))), StateOK, 0, 0)

	// CA certificates: intermediates count, roots do not.
	gen := func(mod func(*Generation)) Snapshot {
		g := Generation{Number: 1, Current: true, Signed: true, Intermediate: true, NotAfter: now.Add(365 * day), Signature: x509.SHA1WithRSA}
		mod(&g)
		return Snapshot{CAs: []CA{{ID: "ca-9", Name: "sub", Issuing: true, Generations: []Generation{g}}}}
	}
	r := run(gen(func(*Generation) {}))
	want(t, "intermediate", r, StateFindings, 1, 0)
	if r.Findings[0].Key != "weak_signature:ca-9/1" || r.Findings[0].Href != "/authorities/ca-9" || r.Findings[0].Subject != "CA sub, generation 1" {
		t.Errorf("finding %+v", r.Findings[0])
	}
	want(t, "root", run(gen(func(g *Generation) { g.Intermediate = false })), StateOK, 0, 0)
	want(t, "revoked", run(gen(func(g *Generation) { g.Revoked = true })), StateOK, 0, 0)
	want(t, "expired", run(gen(func(g *Generation) { g.NotAfter = now })), StateOK, 0, 0)
	want(t, "pending", run(gen(func(g *Generation) { g.Signed = false })), StateOK, 0, 0)
	want(t, "unknown CA algorithm", run(gen(func(g *Generation) { g.Signature = x509.UnknownSignatureAlgorithm })), StateUnknown, 0, 1)
	want(t, "SHA-256 intermediate", run(gen(func(g *Generation) { g.Signature = x509.ECDSAWithSHA384 })), StateOK, 0, 0)
}

// --- ca_cliff -----------------------------------------------------------------

func TestCACliff(t *testing.T) {
	t.Parallel()
	authority := func(left time.Duration, mod ...func(*CA)) CA {
		c := CA{ID: "ca-1", Name: "issuing", Issuing: true,
			Generations: []Generation{{Number: 2, Current: true, Signed: true, NotAfter: now.Add(left)}, {Number: 1, Signed: true, NotAfter: now.Add(-day)}}}
		for _, m := range mod {
			m(&c)
		}
		return c
	}
	run := func(s Snapshot) Result { s.Now = now; return CACliff(s) }
	only := func(c CA, domains ...ca.Domain) Snapshot { return Snapshot{CAs: []CA{c}, Domains: domains} }

	r := run(only(authority(60 * day)))
	want(t, "60 days left, default 90", r, StateFindings, 1, 0)
	f := r.Findings[0]
	end := now.Add(60 * day).Format(time.DateOnly)
	if f.Severity != SeverityWarning || f.Key != "ca_cliff:ca-1" || f.Href != "/authorities/ca-1" || f.Subject != "CA issuing" ||
		!strings.Contains(f.Seen, "ends on "+end) || !strings.Contains(f.Seen, "90 days") || !strings.Contains(f.Recommendation, "second factor") {
		t.Errorf("finding %+v", f)
	}
	want(t, "exactly 90 days", run(only(authority(90*day))), StateOK, 0, 0)
	want(t, "90 days minus a second", run(only(authority(90*day-time.Second))), StateFindings, 1, 0)
	want(t, "a year", run(only(authority(365*day))), StateOK, 0, 0)

	// Critical under 14 days.
	if rr := run(only(authority(14 * day))); rr.Findings[0].Severity != SeverityWarning {
		t.Errorf("exactly 14 days: %s", rr.Findings[0].Severity)
	}
	if rr := run(only(authority(14*day - time.Second))); rr.Findings[0].Severity != SeverityCritical {
		t.Errorf("14 days minus a second: %s", rr.Findings[0].Severity)
	}

	// The default is the domain's validity_days, the longest of the CA's domains.
	domain := func(days int) ca.Domain {
		return ca.Domain{ID: "dom-" + string(rune('a'+days%26)), Name: "x.lan", CAID: "ca-1", ValidityDays: days}
	}
	want(t, "domain of 30 days", run(only(authority(60*day), domain(30))), StateOK, 0, 0)
	want(t, "domain of 180 days", run(only(authority(100*day), domain(180))), StateFindings, 1, 0)
	want(t, "longest of two domains", run(only(authority(100*day), domain(30), domain(120))), StateFindings, 1, 0)
	other := domain(365)
	other.CAID = "ca-other"
	want(t, "domain of another CA", run(only(authority(60*day), domain(30), other)), StateOK, 0, 0)

	// How many certificates already end with the CA.
	s := only(authority(20 * day))
	s.Certificates = []Certificate{cert("a", ends(now.Add(20*day))), cert("b", ends(now.Add(20*day))), cert("c", ends(now.Add(19*day))),
		cert("d", ends(now.Add(20*day)), func(c *Certificate) { c.CAID = "ca-other" })}
	if rs := run(s); !strings.Contains(rs.Findings[0].Seen, "2 valid certificates already end that day") {
		t.Errorf("seen: %s", rs.Findings[0].Seen)
	}

	// Not issuing, retired, revoked: skipped. No signed generation: unknown.
	want(t, "offline root", run(only(authority(20*day, func(c *CA) { c.Issuing = false }))), StateOK, 0, 0)
	want(t, "revoked generation", run(only(authority(20*day, func(c *CA) { c.Generations[0].Revoked = true }))), StateOK, 0, 0)
	pending := authority(20*day, func(c *CA) { c.Generations = []Generation{{Number: 1, Current: true}} })
	r = run(only(pending))
	want(t, "no signed generation", r, StateUnknown, 0, 1)
	if !strings.Contains(r.UnknownReason, "1 issuing CA has no signed generation yet") {
		t.Errorf("reason %q", r.UnknownReason)
	}
	want(t, "no current generation", run(only(authority(20*day, func(c *CA) { c.Generations[0].Current = false }))), StateUnknown, 0, 1)
	want(t, "no CA", run(Snapshot{}), StateOK, 0, 0)
	// An ended CA is critical and does not say that it will issue.
	r = run(only(authority(-2 * day)))
	want(t, "ended", r, StateFindings, 1, 0)
	if r.Findings[0].Severity != SeverityCritical || !strings.Contains(r.Findings[0].Seen, "ended on") || strings.Contains(r.Findings[0].Why, "from now on") {
		t.Errorf("ended: %+v", r.Findings[0])
	}
}

// --- outdated_agent -----------------------------------------------------------

func TestOutdatedAgent(t *testing.T) {
	t.Parallel()
	agent := func(version string, mod ...func(*Agent)) Agent {
		a := Agent{ID: "agt-1", Hostname: "proxy-01.homelab.lan", Status: "active", Version: version}
		for _, m := range mod {
			m(&a)
		}
		return a
	}
	run := func(server string, agents ...Agent) Result {
		return OutdatedAgent(Snapshot{Now: now, ServerVersion: server, Agents: agents})
	}

	r := run("0.3.8", agent("0.3.2"))
	want(t, "minor behind", r, StateFindings, 1, 0)
	f := r.Findings[0]
	if f.Severity != SeverityInfo || f.Seen != "Agent proxy-01.homelab.lan runs 0.3.2, the server runs 0.3.8." || f.Key != "outdated_agent:agt-1" || f.Href != "/agents/agt-1" ||
		!strings.Contains(f.Recommendation, "Salt formula") {
		t.Errorf("finding %+v", f)
	}
	// Same minor, older patch: info. Older minor or major: warning.
	for _, tc := range []struct{ agent, server, sev string }{
		{"0.3.2", "0.3.8", SeverityInfo}, {"0.3.7", "0.3.8", SeverityInfo}, {"0.2.9", "0.3.0", SeverityWarning},
		{"0.3.8", "0.4.0", SeverityWarning}, {"0.9.9", "1.0.0", SeverityWarning}, {"v0.3.2", "v0.3.8", SeverityInfo},
		{"0.3.8-rc1", "0.3.8", SeverityInfo},
	} {
		rt := run(tc.server, agent(tc.agent))
		if rt.Counts.Total() != 1 || rt.Findings[0].Severity != tc.sev {
			t.Errorf("agent %s, server %s: %+v", tc.agent, tc.server, rt.Counts)
		}
	}
	for _, v := range []string{"0.3.8", "0.3.9", "0.4.0", "1.0.0", "0.3.8+build5"} {
		want(t, "agent "+v, run("0.3.8", agent(v)), StateOK, 0, 0)
	}
	want(t, "disabled agent", run("0.3.8", agent("0.1.0", func(a *Agent) { a.Status = "disabled" })), StateOK, 0, 0)
	want(t, "revoked agent", run("0.3.8", agent("0.1.0", func(a *Agent) { a.Status = "revoked" })), StateOK, 0, 0)
	want(t, "no agents", run("0.3.8"), StateOK, 0, 0)

	// Unknown: a development server, an agent version that is no release, no agent data.
	r = run("dev", agent("0.3.2"))
	want(t, "dev server", r, StateUnknown, 0, 0)
	if !strings.Contains(r.UnknownReason, "development build") {
		t.Errorf("reason %q", r.UnknownReason)
	}
	want(t, "empty server version", run("", agent("0.3.2")), StateUnknown, 0, 0)
	want(t, "server pseudo-version", run("v0.3.8-0.20261113120000-abcdef123456+dirty", agent("0.3.2")), StateFindings, 1, 0) // strict SemVer, comparable
	r = run("0.3.8", agent("not-a-version"), agent("0.3.2", func(a *Agent) { a.ID = "agt-2" }))
	want(t, "agent without release version", r, StateFindings, 1, 1)
	want(t, "only an unparsable agent", run("0.3.8", agent("devel")), StateUnknown, 0, 1)
	missing := Snapshot{Now: now, ServerVersion: "0.3.8", Missing: Missing{Agents: "the agent listener is off, so there is no agent data."}}
	r = OutdatedAgent(missing)
	want(t, "listener off", r, StateUnknown, 0, 0)
	if r.UnknownReason != missing.Missing.Agents {
		t.Errorf("reason %q", r.UnknownReason)
	}
	// A hostile host name is clipped and kept raw.
	evil := `<img src=x onerror=alert(1)>` + strings.Repeat("h", 4000)
	r = run("0.3.8", agent("0.3.2", func(a *Agent) { a.Hostname = evil }))
	if f := r.Findings[0]; !strings.Contains(f.Subject, "<img src=x") || utf8.RuneCountInString(f.Subject) > maxClip+len("Agent ") || utf8.RuneCountInString(f.Seen) > 3*maxClip {
		t.Errorf("hostile host name: %d runes in subject, %d in seen", utf8.RuneCountInString(f.Subject), utf8.RuneCountInString(f.Seen))
	}
}

// --- unused_acme_account ------------------------------------------------------

func TestUnusedACMEAccount(t *testing.T) {
	t.Parallel()
	account := func(mod ...func(*Account)) Account {
		a := Account{ID: "acc-1", Status: "valid", CreatedAt: now.Add(-200 * day), LastOrderAt: now.Add(-100 * day)}
		for _, m := range mod {
			m(&a)
		}
		return a
	}
	run := func(a ...Account) Result { return UnusedACMEAccount(Snapshot{Now: now, Accounts: a}) }

	r := run(account())
	want(t, "no orders for 100 days", r, StateFindings, 1, 0)
	f := r.Findings[0]
	if f.Severity != SeverityInfo || f.Seen != "No orders for 100 days." || f.Key != "unused_acme_account:acc-1" || f.Href != "/acme/accounts/acc-1" ||
		!strings.Contains(f.Recommendation, "RFC 8555 section 7.3.6") {
		t.Errorf("finding %+v", f)
	}
	want(t, "exactly 90 days", run(account(func(a *Account) { a.LastOrderAt = now.Add(-90 * day) })), StateFindings, 1, 0)
	want(t, "89 days", run(account(func(a *Account) { a.LastOrderAt = now.Add(-89 * day) })), StateOK, 0, 0)
	want(t, "ordered yesterday", run(account(func(a *Account) { a.LastOrderAt = now.Add(-day) })), StateOK, 0, 0)

	never := func(age time.Duration) Account {
		return account(func(a *Account) { a.CreatedAt, a.LastOrderAt = now.Add(-age), time.Time{} })
	}
	r = run(never(45 * day))
	want(t, "never ordered, 45 days old", r, StateFindings, 1, 0)
	if r.Findings[0].Seen != "This account never ordered a certificate and is 45 days old." {
		t.Errorf("seen: %s", r.Findings[0].Seen)
	}
	want(t, "never ordered, exactly 30 days", run(never(30*day)), StateFindings, 1, 0)
	want(t, "never ordered, 30 days minus a second", run(never(30*day-time.Second)), StateOK, 0, 0)
	want(t, "agent account", run(account(func(a *Account) { a.AgentLinked = true })), StateOK, 0, 0)
	want(t, "deactivated account", run(account(func(a *Account) { a.Status = "deactivated" })), StateOK, 0, 0)
	want(t, "revoked account", run(account(func(a *Account) { a.Status = "revoked" })), StateOK, 0, 0)
	want(t, "no accounts", run(), StateOK, 0, 0)
}

// --- unused_domain ------------------------------------------------------------

func TestUnusedDomain(t *testing.T) {
	t.Parallel()
	domain := func(name string, mod ...func(*ca.Domain)) ca.Domain {
		d := ca.Domain{ID: "dom-" + name, Name: name, CAID: "ca-1", IncludeSubdomains: true, CreatedAt: now.Add(-60 * day)}
		for _, m := range mod {
			m(&d)
		}
		return d
	}
	dns := func(v ...string) []ca.CertName {
		var out []ca.CertName
		for _, n := range v {
			out = append(out, ca.CertName{Type: "dns", Value: n})
		}
		return out
	}
	run := func(domains []ca.Domain, names []ca.CertName) Result {
		return UnusedDomain(Snapshot{Now: now, Domains: domains, Names: names})
	}

	r := run([]ca.Domain{domain("homelab.lan")}, nil)
	want(t, "nothing issued", r, StateFindings, 1, 0)
	f := r.Findings[0]
	if f.Severity != SeverityInfo || f.Key != "unused_domain:dom-homelab.lan" || f.Href != "/domains/dom-homelab.lan" || f.Subject != "Domain homelab.lan" ||
		!strings.Contains(f.Seen, "No certificate was ever issued") {
		t.Errorf("finding %+v", f)
	}
	want(t, "used by the name itself", run([]ca.Domain{domain("homelab.lan")}, dns("homelab.lan")), StateOK, 0, 0)
	want(t, "used by a sub-domain", run([]ca.Domain{domain("homelab.lan")}, dns("nas.homelab.lan")), StateOK, 0, 0)
	want(t, "sub-domains not included", run([]ca.Domain{domain("homelab.lan", func(d *ca.Domain) { d.IncludeSubdomains = false })}, dns("nas.homelab.lan")), StateFindings, 1, 0)
	want(t, "another domain's name", run([]ca.Domain{domain("homelab.lan")}, dns("nas.example.org", "nothomelab.lan")), StateFindings, 1, 0)
	want(t, "wildcard allowed", run([]ca.Domain{domain("homelab.lan", func(d *ca.Domain) { d.Wildcards = true })}, dns("*.homelab.lan")), StateOK, 0, 0)
	want(t, "wildcard not allowed", run([]ca.Domain{domain("homelab.lan")}, dns("*.homelab.lan")), StateFindings, 1, 0)
	// Age: 30 days.
	want(t, "29 days old", run([]ca.Domain{domain("homelab.lan", func(d *ca.Domain) { d.CreatedAt = now.Add(-30*day + time.Second) })}, nil), StateOK, 0, 0)
	want(t, "30 days old", run([]ca.Domain{domain("homelab.lan", func(d *ca.Domain) { d.CreatedAt = now.Add(-30 * day) })}, nil), StateFindings, 1, 0)
	// IP ranges.
	ipDomain := domain("lan", func(d *ca.Domain) { d.IPRanges = nil })
	want(t, "an IP does not use a DNS domain", run([]ca.Domain{ipDomain}, []ca.CertName{{Type: "ip", Value: "192.0.2.1"}}), StateFindings, 1, 0)
	want(t, "no domains", run(nil, dns("a.lan")), StateOK, 0, 0)
	// Two domains, one used.
	want(t, "one of two", run([]ca.Domain{domain("a.lan"), domain("b.lan")}, dns("x.a.lan")), StateFindings, 1, 0)
}
