package analysis

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/agents"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
)

// Tests of the fixes that came out of the review of the v0.3.8 branch.

// TestCACliffDefaultIsCappedAtTheCAMaximum: the engine shortens a leaf to the
// maximum validity of the CA, so a CA that ends in 60 days is not "sooner than
// 90 days" when its maximum is 30; the reverse still fires.
func TestCACliffDefaultIsCappedAtTheCAMaximum(t *testing.T) {
	t.Parallel()
	authority := func(left time.Duration, maxDays int) CA {
		return CA{ID: "ca-1", Name: "issuing", Issuing: true, MaxValidityDays: maxDays,
			Generations: []Generation{{Number: 1, Current: true, Signed: true, NotAfter: now.Add(left)}}}
	}
	run := func(c CA, domains ...ca.Domain) Result {
		return CACliff(Snapshot{Now: now, CAs: []CA{c}, Domains: domains})
	}
	domain := func(days int) ca.Domain {
		return ca.Domain{ID: "dom-1", Name: "x.lan", CAID: "ca-1", ValidityDays: days}
	}

	want(t, "max 30, 60 days left", run(authority(60*day, 30)), StateOK, 0, 0)
	want(t, "max 30, exactly 30 days left", run(authority(30*day, 30)), StateOK, 0, 0)
	want(t, "max 30, 30 days minus a second", run(authority(30*day-time.Second, 30)), StateFindings, 1, 0)
	// The reverse: a high maximum does not raise the default of 90.
	r := run(authority(60*day, 400))
	want(t, "max 400, 60 days left", r, StateFindings, 1, 0)
	if f := r.Findings[0]; !strings.Contains(f.Seen, "ACME default validity of 90 days") {
		t.Errorf("seen: %s", f.Seen)
	}
	want(t, "max 400, 90 days left", run(authority(90*day, 400)), StateOK, 0, 0)
	// A domain with a validity above the maximum of the CA (the maximum was
	// lowered later): the cap wins, and the text names the capped number.
	r = run(authority(100*day, 120), domain(365))
	want(t, "domain 365, max 120, 100 days left", r, StateFindings, 1, 0)
	if !strings.Contains(r.Findings[0].Seen, "validity of 120 days") {
		t.Errorf("seen: %s", r.Findings[0].Seen)
	}
	want(t, "domain 365, max 100, 100 days left", run(authority(100*day, 100), domain(365)), StateOK, 0, 0)
	// 0 = not known: no cap.
	want(t, "maximum unknown", run(authority(60*day, 0)), StateFindings, 1, 0)
}

// TestOrphanedCertificateWhyNamesTheBlindSpot: the scan keeps one fingerprint
// per endpoint, which the finding says; the severity stays info.
func TestOrphanedCertificateWhyNamesTheBlindSpot(t *testing.T) {
	t.Parallel()
	r := OrphanedCertificate(Snapshot{Now: now, Certificates: []Certificate{cert("a")}, Endpoints: []Endpoint{endpoint("a")}})
	want(t, "fires", r, StateFindings, 1, 0)
	f := r.Findings[0]
	const caveat = "A host that serves two certificates for one name, or several servers behind one address, shows only one of them to the scan."
	if !strings.Contains(f.Why, caveat) {
		t.Errorf("why: %s", f.Why)
	}
	if f.Severity != SeverityInfo {
		t.Errorf("severity %s", f.Severity)
	}
}

// TestCertificatesAfterTheSnapshotAreOutOfScope: Load reads the certificates and
// their traits and origins in separate queries. A certificate issued in between
// has no traits or origin yet: that is not "could not be read".
func TestCertificatesAfterTheSnapshotAreOutOfScope(t *testing.T) {
	t.Parallel()
	fresh := func(mod ...func(*Certificate)) Certificate {
		return cert("n", append([]func(*Certificate){func(c *Certificate) {
			c.CreatedAt, c.NotBefore, c.Traits, c.Class, c.IssuerKey = now.Add(time.Second), now.Add(time.Second), nil, "", ""
		}}, mod...)...)
	}
	snap := func(c ...Certificate) Snapshot { return Snapshot{Now: now, Certificates: c} }

	want(t, "weak_key", WeakKey(snap(fresh())), StateOK, 0, 0)
	want(t, "weak_signature", WeakSignature(snap(fresh())), StateOK, 0, 0)
	want(t, "duplicates", DuplicateCertificates(snap(cert("a", names("x.lan")), fresh(names("x.lan")))), StateOK, 0, 0)
	// The same certificate created exactly at the snapshot time, or earlier, and
	// without traits, still counts as unreadable.
	old := func(created time.Time) Certificate {
		return cert("o", func(c *Certificate) { c.CreatedAt, c.Traits = created, nil })
	}
	want(t, "weak_key at the snapshot time", WeakKey(snap(old(now))), StateUnknown, 0, 1)
	want(t, "weak_signature earlier", WeakSignature(snap(old(now.Add(-time.Hour)))), StateUnknown, 0, 1)
	// A fresh certificate with traits is judged as any other.
	weak := fresh(func(c *Certificate) {
		c.Traits = &ca.Traits{KeyAlgorithm: ca.TraitRSA, KeyBits: 1024, Signature: x509.SHA256WithRSA}
	})
	want(t, "fresh weak key with traits", WeakKey(snap(weak)), StateFindings, 1, 0)
}

// TestReasonsAreGrammatical: singular and plural of the reasons, and the
// expiry wave of a small tenant reads as "too few", not as a failure.
func TestReasonsAreGrammatical(t *testing.T) {
	t.Parallel()
	pending := func(id string) CA {
		return CA{ID: id, Name: id, Issuing: true, Generations: []Generation{{Number: 1, Current: true}}}
	}
	for _, tc := range []struct {
		cas  []CA
		want string
	}{
		{[]CA{pending("a")}, "1 issuing CA has no signed generation yet."},
		{[]CA{pending("a"), pending("b")}, "2 issuing CAs have no signed generation yet."},
	} {
		if r := CACliff(Snapshot{Now: now, CAs: tc.cas}); r.UnknownReason != tc.want {
			t.Errorf("ca_cliff reason %q, want %q", r.UnknownReason, tc.want)
		}
	}
	agent := func(id string) Agent { return Agent{ID: id, Hostname: id, Status: "active", Version: "devel"} }
	for _, tc := range []struct {
		agents []Agent
		want   string
	}{
		{[]Agent{agent("a")}, "1 agent has a version that is not a release number."},
		{[]Agent{agent("a"), agent("b")}, "2 agents have a version that is not a release number."},
	} {
		if r := OutdatedAgent(Snapshot{Now: now, ServerVersion: "0.3.8", Agents: tc.agents}); r.UnknownReason != tc.want {
			t.Errorf("outdated_agent reason %q, want %q", r.UnknownReason, tc.want)
		}
	}
	r := ExpiryWave(Snapshot{Now: now, Certificates: []Certificate{cert("a")}})
	want(t, "small tenant", r, StateUnknown, 0, 0)
	if !strings.HasPrefix(r.UnknownReason, "too few certificates to judge") || strings.Contains(strings.ToLower(r.UnknownReason), "fail") {
		t.Errorf("reason %q", r.UnknownReason)
	}
}

// TestLoadHandlesTheRacesOfSeparateReads: an agent deleted between ListAgents
// and GetAgent is left out; the maximum validity of a CA and a cut-off list of
// ACME accounts reach the snapshot.
func TestLoadHandlesTheRacesOfSeparateReads(t *testing.T) {
	t.Parallel()
	e := &fakeEngine{traits: map[string]ca.Traits{}, origins: map[string]ca.Origin{}, accountsTruncated: true}
	e.cas = []ca.CAInfo{{ID: "sub", Name: "sub", Status: ca.StatusActive, KeyMode: ca.KeyModeOnlineEncrypted, MaxValidityDays: 30}}
	ag := &fakeAgents{
		list: []agents.Agent{{ID: "agt-1", Hostname: "a", Status: agents.StatusActive, Version: "0.3.8"}, {ID: "agt-2", Hostname: "gone", Status: agents.StatusActive, Version: "0.3.8"}},
		deps: map[string][]agents.Deployment{"agt-1": {{Name: "web", State: "deployed"}}},
		gone: map[string]bool{"agt-2": true},
	}
	d := Deps{Tenant: "default", Engine: e, Agents: ag, ServerVersion: "0.3.8", Clock: clock.NewFake(now)}
	s, err := Load(t.Context(), d, now)
	if err != nil {
		t.Fatalf("a deleted agent failed the analysis: %v", err)
	}
	if len(s.Agents) != 1 || s.Agents[0].ID != "agt-1" {
		t.Errorf("agents %+v", s.Agents)
	}
	if len(s.CAs) != 1 || s.CAs[0].MaxValidityDays != 30 {
		t.Errorf("CAs %+v", s.CAs)
	}
	if s.AccountsLimit != ca.MaxActivityAccounts {
		t.Errorf("AccountsLimit %d", s.AccountsLimit)
	}
	e.accountsTruncated = false
	if s, err = Load(t.Context(), d, now); err != nil || s.AccountsLimit != 0 {
		t.Errorf("complete accounts: limit %d, %v", s.AccountsLimit, err)
	}
}
