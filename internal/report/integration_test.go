package report

import (
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/monitor"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

// The real services satisfy the interfaces Build reads through.
var _ Engine = (*ca.Engine)(nil)

// TestBuildAgainstTheRealEngine: the numbers of the report are the numbers of
// the certificate list (the live test of docs/PHASE3.md 14.1, step 2): the
// timeline holds the valid certificates, the issuances of the current week
// are the UI class, the authorities add up to the counts of the engine.
func TestBuildAgainstTheRealEngine(t *testing.T) {
	t.Parallel()
	inst := testinstance.New(t, testinstance.Options{})
	inst.Unseal(t)
	for i, days := range []int{10, 40, 40, 80} {
		req := ca.Request{CA: "issuing", Preset: "server", DNSNames: []string{string(rune('a'+i)) + ".homelab.lan"}, ValidityDays: days, Who: testinstance.Console}
		if _, err := inst.Engine.Issue(t.Context(), req); err != nil {
			t.Fatal(err)
		}
	}
	now := inst.Clock.Now()
	d := Deps{Tenant: store.DefaultTenant, Engine: inst.Engine, Alerts: &fakeAlerts{}, Rules: monitor.DefaultRules(), ServerVersion: "0.3.8", Clock: inst.Clock}
	r, err := Build(t.Context(), d, now)
	if err != nil {
		t.Fatal(err)
	}

	timeline := 0
	for _, w := range r.Expiry.Weeks {
		timeline += w.Count
	}
	// 13 weeks cover 91 to 97 days: all four certificates (10, 40, 40, 80 days) end inside.
	if timeline != 4 {
		t.Errorf("the timeline holds %d certificates, want 4", timeline)
	}
	page, err := inst.Engine.Certificates(t.Context(), testinstance.Console, ca.CertificateFilter{Status: ca.CertValid, HideAgentCertificates: true})
	if err != nil || len(page.Items) != timeline {
		t.Errorf("the list has %d valid certificates (%v), the timeline %d", len(page.Items), err, timeline)
	}

	issued := 0
	current := r.Issuances.Weeks[IssuanceWeeks-1]
	for _, w := range r.Issuances.Weeks {
		issued += w.Total()
	}
	if issued != 4 || current.UI != 4 || current.ACME != 0 || current.Agent != 0 || !current.Start.Equal(WeekStart(now)) {
		t.Errorf("issuances %d, current week %+v", issued, current)
	}

	total, perCA, err := inst.Engine.CertificateCounts(t.Context(), testinstance.Console, ca.CertificateFilter{HideAgentCertificates: true})
	if err != nil {
		t.Fatal(err)
	}
	var valid, expiring int64
	for _, a := range r.Authorities {
		valid += a.Valid
		expiring += a.Expiring
		if n := perCA[a.ID]; a.Valid != n.Valid || a.Expiring != n.Expiring || a.Expired != n.Expired || a.Revoked != n.Revoked {
			t.Errorf("authority %s: %+v, engine %+v", a.Name, a, n)
		}
	}
	if valid != total.Valid || expiring != total.Expiring || r.Agents != nil {
		t.Errorf("authorities %d/%d, engine %+v, agents %v", valid, expiring, total, r.Agents)
	}

	// The cache of the service hands out the same report within a minute.
	s := NewService(d)
	first, err := s.Get(t.Context(), testinstance.Console)
	if err != nil {
		t.Fatal(err)
	}
	inst.Clock.Advance(30 * time.Second)
	if again, _ := s.Get(t.Context(), testinstance.Console); again != first {
		t.Error("no cache")
	}
}
