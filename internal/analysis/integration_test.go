package analysis

import (
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

// TestAnalyzeAgainstTheRealEngine: Load reads a real engine (CA scoping,
// paging, DER traits, origins) and the rules fire on what it finds. The same
// names issued three times within minutes make a renewal loop and three
// certificates from one source; nothing else fires, and the rules whose
// input is missing say so.
func TestAnalyzeAgainstTheRealEngine(t *testing.T) {
	t.Parallel()
	inst := testinstance.New(t, testinstance.Options{})
	inst.Unseal(t)
	for range 3 {
		if _, err := inst.Engine.Issue(t.Context(), ca.Request{CA: "issuing", Preset: "server", DNSNames: []string{"loop.homelab.lan"}, Who: testinstance.Console}); err != nil {
			t.Fatal(err)
		}
		inst.Clock.Advance(time.Minute)
	}
	if _, err := inst.Engine.Issue(t.Context(), ca.Request{CA: "issuing", Preset: "server", DNSNames: []string{"single.homelab.lan"}, Who: testinstance.Console}); err != nil {
		t.Fatal(err)
	}

	a, err := Analyze(t.Context(), Deps{Tenant: store.DefaultTenant, Engine: inst.Engine, ServerVersion: "0.3.8", Clock: inst.Clock}, inst.Clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]Result{}
	for _, r := range a.Results {
		by[r.ID] = r
	}
	loop := by[RuleRenewalLoop]
	if loop.State != StateFindings || loop.Counts.Warning != 1 || loop.Findings[0].Subject != "loop.homelab.lan" ||
		loop.Findings[0].Href == "" || len(loop.Findings[0].Key) > 64 {
		t.Errorf("renewal_loop: %+v", loop)
	}
	dup := by[RuleDuplicateCertificates]
	if dup.State != StateFindings || dup.Counts.Info != 1 {
		t.Errorf("duplicate_certificates: %+v", dup)
	}
	for _, id := range []string{RuleWeakKey, RuleWeakSignature, RuleCACliff, RuleUnusedACMEAccount} {
		if by[id].State == StateFindings {
			t.Errorf("%s fired on a healthy demo instance: %+v", id, by[id].Findings)
		}
	}
	// Traits come from the real DER: a default certificate is not weak, and
	// no certificate is left "unassessed".
	if by[RuleWeakKey].State != StateOK || by[RuleWeakSignature].State != StateOK {
		t.Errorf("weak_key %s, weak_signature %s (%q %q)", by[RuleWeakKey].State, by[RuleWeakSignature].State, by[RuleWeakKey].UnknownReason, by[RuleWeakSignature].UnknownReason)
	}
	// No agent listener, no scan, four certificates: these cannot be assessed.
	for _, id := range []string{RuleOrphanedCertificate, RuleOutdatedAgent, RuleExpiryWave} {
		if by[id].State != StateUnknown || by[id].UnknownReason == "" {
			t.Errorf("%s: %s %q", id, by[id].State, by[id].UnknownReason)
		}
	}
	if a.Summary.Warning != 1 || a.Summary.Info != 1 || a.Summary.Critical != 0 || a.Summary.Unknown != 3 {
		t.Errorf("summary %+v", a.Summary)
	}
}
