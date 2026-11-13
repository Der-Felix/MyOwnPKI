package ca

import (
	"crypto/x509"
	"slices"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
)

// TestCertificateTraits: the traits of the valid certificates only (not
// revoked, not expired, no agent identity certificate), by ID; the
// signature of a CA generation shows in the CA list.
func TestCertificateTraits(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.chain(t, caOpts{})
	f := newReportFixture(t, v)

	got, err := v.e.CertificateTraits(t.Context(), tester)
	if err != nil {
		t.Fatal(err)
	}
	// ui, acme, agent and imported are valid; revoked and agent identity are not.
	for _, c := range []*Issued{f.ui, f.acme, f.agent, f.imported} {
		tr, ok := got[c.ID]
		if !ok || tr.KeyAlgorithm != TraitECDSA || tr.KeyBits != 256 || tr.Signature != x509.ECDSAWithSHA256 {
			t.Errorf("%s: %+v %v", c.ID, tr, ok)
		}
	}
	if _, ok := got[f.revoked.ID]; ok {
		t.Error("a revoked certificate has traits")
	}
	if _, ok := got[f.agentIdentity.ID]; ok {
		t.Error("an agent identity certificate has traits")
	}
	if len(got) != 4 {
		t.Errorf("%d traits, want 4", len(got))
	}

	scoped := signedIn("cv", time.Time{}, authz.Binding{CA: "root", Role: authz.Viewer})
	if got, err = v.e.CertificateTraits(t.Context(), scoped); err != nil || len(got) != 0 {
		t.Errorf("a viewer of another CA: %d %v", len(got), err)
	}

	v.clk.Advance(f.ui.NotAfter.Sub(v.clk.Now()) + time.Second)
	if got, err = v.e.CertificateTraits(t.Context(), tester); err != nil || len(got) != 0 {
		t.Errorf("expired certificates: %d %v", len(got), err)
	}

	cas, err := v.e.CAs(t.Context(), tester)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cas {
		for _, g := range c.Generations {
			if g.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
				t.Errorf("CA %s generation %d: no signature algorithm", c.Name, g.Generation)
			}
		}
	}
}

func TestTraitsOfRejectsGarbage(t *testing.T) {
	t.Parallel()
	if _, err := TraitsOf([]byte("not a certificate")); err == nil {
		t.Error("garbage parsed")
	}
}

func TestCertificateOrigins(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.chain(t, caOpts{})
	f := newReportFixture(t, v)

	got, err := v.e.CertificateOrigins(t.Context(), tester)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Origin{
		f.ui.ID:      {SourceUI, "ui"},
		f.revoked.ID: {SourceUI, "ui"},
		f.acme.ID:    {SourceACME, "acme:acc-plain"},
		f.agent.ID:   {SourceAgent, "agent:agt-1"},
	}
	for id, o := range want {
		if got[id] != o {
			t.Errorf("%s: %+v, want %+v", id, got[id], o)
		}
	}
	if _, ok := got[f.imported.ID]; ok {
		t.Error("an imported certificate has an origin")
	}
	if _, ok := got[f.agentIdentity.ID]; ok {
		t.Error("an agent identity certificate has an origin")
	}
	if len(got) != len(want) {
		t.Errorf("%d origins, want %d", len(got), len(want))
	}
}

func TestCertificateNames(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	root, _ := v.chain(t, caOpts{})
	v.addCA(t, "other", caOpts{parent: root})
	v.issue(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"a.homelab.lan", "b.homelab.lan"}, IPAddresses: []string{"192.0.2.7"}})
	v.issue(t, Request{CA: "other", Preset: "server", DNSNames: []string{"a.homelab.lan", "c.homelab.lan"}})
	got, err := v.e.CertificateNames(t.Context(), tester)
	if err != nil {
		t.Fatal(err)
	}
	want := []CertName{{"dns", "a.homelab.lan"}, {"dns", "b.homelab.lan"}, {"dns", "c.homelab.lan"}, {"ip", "192.0.2.7"}}
	if !slices.Equal(got, want) {
		t.Errorf("names %v", got)
	}
	scoped := signedIn("cv", time.Time{}, authz.Binding{CA: "other", Role: authz.Viewer})
	got, err = v.e.CertificateNames(t.Context(), scoped)
	if err != nil || !slices.Equal(got, []CertName{{"dns", "a.homelab.lan"}, {"dns", "c.homelab.lan"}}) {
		t.Errorf("CA viewer: %v %v", got, err)
	}
}

func TestACMEAccountActivity(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.chain(t, caOpts{})
	newReportFixture(t, v) // accounts acc-plain (two orders) and acc-agent (one order), created now
	created := v.clk.Now()
	v.clk.Advance(48 * time.Hour)
	later := v.clk.Now().Format("2006-01-02T15:04:05Z")
	v.exec(t, `INSERT INTO acme_accounts (id, key_thumbprint, jwk, status, contact, created_at, created_ip, updated_at)
		VALUES ('acc-idle', 'acc-idle', '{}', 'valid', '[]', ?1, '192.0.2.1', ?1)`, later)

	got, err := v.e.ACMEAccountActivity(t.Context(), tester)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].ID != "acc-idle" {
		t.Fatalf("accounts %+v", got)
	}
	by := map[string]AccountActivity{}
	for _, a := range got {
		by[a.ID] = a
	}
	if a := by["acc-idle"]; !a.LastOrderAt.IsZero() || a.AgentLinked || !a.CreatedAt.Equal(v.clk.Now()) {
		t.Errorf("idle account %+v", a)
	}
	if a := by["acc-plain"]; !a.LastOrderAt.Equal(created) || a.AgentLinked || a.Status != "valid" {
		t.Errorf("plain account %+v", a)
	}
	if a := by["acc-agent"]; !a.AgentLinked || a.LastOrderAt.IsZero() {
		t.Errorf("agent account %+v", a)
	}

	scoped := signedIn("cv", time.Time{}, authz.Binding{CA: "issuing", Role: authz.Viewer})
	if _, err := v.e.ACMEAccountActivity(t.Context(), scoped); err == nil {
		t.Error("a CA-scoped viewer read the ACME accounts")
	}
	if _, err := v.e.ACMEAccountActivity(t.Context(), keys.Who{}); err == nil {
		t.Error("nobody read the ACME accounts")
	}
}
