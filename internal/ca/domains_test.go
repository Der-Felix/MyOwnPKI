package ca

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
)

func ptr[T any](v T) *T { return &v }

// domainEnv: a root, an intermediate "issuing" limited to homelab.lan and
// 10.0.0.0/8, and "open" without constraints.
func domainEnv(t *testing.T) *env {
	t.Helper()
	v := newEnv(t)
	v.root(t, "root", nil)
	v.intermediate(t, "issuing", "root", func(r *IntermediateRequest) {
		r.NameConstraints = NameConstraints{PermittedDNS: []string{"homelab.lan"}, PermittedIP: []string{"10.0.0.0/8"}}
	})
	v.intermediate(t, "open", "root", nil)
	return v
}

func TestDomainCreateAndDefaults(t *testing.T) {
	t.Parallel()
	v := domainEnv(t)
	ctx := t.Context()
	d, err := v.e.CreateDomain(ctx, DomainRequest{Name: "homelab.lan", DomainSettings: DomainSettings{CA: ptr("issuing")}, Who: tester})
	if err != nil {
		t.Fatal(err)
	}
	if !d.IncludeSubdomains || d.Wildcards || d.Approval != ApprovalAccount || d.Preset != "server" ||
		d.EffectiveValidityDays() != 90 || d.AddressPolicy != AddressInternal || !slices.Equal(d.ChallengeTypes, []string{ChallengeHTTP01, ChallengeDNS01}) {
		t.Errorf("defaults: %+v", d)
	}
	got, err := v.e.GetDomain(ctx, tester, d.ID)
	if err != nil || got.Name != "homelab.lan" || got.CA != "issuing" {
		t.Fatalf("get: %+v %v", got, err)
	}
	if _, derr := v.e.CreateDomain(ctx, DomainRequest{Name: "homelab.lan", DomainSettings: DomainSettings{CA: ptr("issuing")}, Who: tester}); !deniedWith(derr, "exists already") {
		t.Errorf("duplicate: %v", derr)
	}
	// Change: wildcards with dns-01, IP range inside the constraints.
	d2, err := v.e.UpdateDomain(ctx, d.ID, DomainSettings{Wildcards: ptr(true), IPRanges: []string{"10.1.0.0/16"}, ValidityDays: ptr(30)}, tester)
	if err != nil || !d2.Wildcards || len(d2.IPRanges) != 1 || d2.EffectiveValidityDays() != 30 {
		t.Fatalf("update: %+v %v", d2, err)
	}
	if err := v.e.DeleteDomain(ctx, d.ID, tester); err != nil {
		t.Fatal(err)
	}
	if _, err := v.e.GetDomain(ctx, tester, d.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("after delete: %v", err)
	}
	var actions []string
	for _, r := range v.auditRows(t) {
		actions = append(actions, r.action+"/"+r.result)
	}
	for _, want := range []string{"domain.create/success", "domain.create/denied", "domain.update/success", "domain.delete/success"} {
		if !slices.Contains(actions, want) {
			t.Errorf("audit lacks %s: %v", want, actions)
		}
	}
}

func deniedWith(err error, text string) bool {
	var d *DeniedError
	return errors.As(err, &d) && strings.Contains(strings.Join(d.Reasons, " | "), text)
}

func TestDomainRefusals(t *testing.T) {
	t.Parallel()
	v := domainEnv(t)
	for name, tc := range map[string]struct {
		req  DomainRequest
		want string
	}{
		"one label":            {DomainRequest{Name: "lan", DomainSettings: DomainSettings{CA: ptr("open")}}, "one label"},
		"upper case":           {DomainRequest{Name: "Homelab.LAN", DomainSettings: DomainSettings{CA: ptr("issuing")}}, "must be written as"},
		"wildcard name":        {DomainRequest{Name: "*.homelab.lan", DomainSettings: DomainSettings{CA: ptr("issuing")}}, "wildcard"},
		"root CA":              {DomainRequest{Name: "homelab.lan", DomainSettings: DomainSettings{CA: ptr("root")}}, "root CA only signs"},
		"no CA":                {DomainRequest{Name: "homelab.lan"}, "needs the CA"},
		"outside constraints":  {DomainRequest{Name: "example.org", DomainSettings: DomainSettings{CA: ptr("issuing")}}, "example.org"},
		"IP outside":           {DomainRequest{Name: "homelab.lan", DomainSettings: DomainSettings{CA: ptr("issuing"), IPRanges: []string{"192.168.0.0/24"}}}, "192.168"},
		"IP host bits":         {DomainRequest{Name: "homelab.lan", DomainSettings: DomainSettings{CA: ptr("issuing"), IPRanges: []string{"10.0.0.1/8"}}}, "host bits"},
		"wildcard needs dns":   {DomainRequest{Name: "a.lan2", DomainSettings: DomainSettings{CA: ptr("open"), Wildcards: ptr(true), ChallengeTypes: []string{ChallengeHTTP01}}}, "dns-01"},
		"wildcard needs subs":  {DomainRequest{Name: "a.lan2", DomainSettings: DomainSettings{CA: ptr("open"), Wildcards: ptr(true), IncludeSubdomains: ptr(false)}}, "include_subdomains"},
		"IP needs http":        {DomainRequest{Name: "a.lan2", DomainSettings: DomainSettings{CA: ptr("open"), IPRanges: []string{"10.0.0.0/8"}, ChallengeTypes: []string{ChallengeDNS01}}}, "http-01"},
		"no challenge":         {DomainRequest{Name: "a.lan2", DomainSettings: DomainSettings{CA: ptr("open"), ChallengeTypes: []string{}}}, "at least one challenge"},
		"unknown challenge":    {DomainRequest{Name: "a.lan2", DomainSettings: DomainSettings{CA: ptr("open"), ChallengeTypes: []string{"tls-alpn-01"}}}, "unknown"},
		"approval":             {DomainRequest{Name: "a.lan2", DomainSettings: DomainSettings{CA: ptr("open"), Approval: ptr("never")}}, "approval"},
		"preset without DNS":   {DomainRequest{Name: "a.lan2", DomainSettings: DomainSettings{CA: ptr("open"), Preset: ptr("smime")}}, "no DNS names"},
		"no serverAuth":        {DomainRequest{Name: "a.lan2", DomainSettings: DomainSettings{CA: ptr("open"), Preset: ptr("client")}}, "serverAuth"},
		"validity over max":    {DomainRequest{Name: "a.lan2", DomainSettings: DomainSettings{CA: ptr("open"), ValidityDays: ptr(5000)}}, "exceeds the maximum"},
		"unknown preset":       {DomainRequest{Name: "a.lan2", DomainSettings: DomainSettings{CA: ptr("open"), Preset: ptr("nope")}}, "no preset"},
		"address policy":       {DomainRequest{Name: "a.lan2", DomainSettings: DomainSettings{CA: ptr("open"), AddressPolicy: ptr("any")}}, "address policy"},
		"unknown CA":           {DomainRequest{Name: "a.lan2", DomainSettings: DomainSettings{CA: ptr("nope")}}, "no CA named"},
		"excluded by the root": {DomainRequest{Name: "secret.homelab.lan", DomainSettings: DomainSettings{CA: ptr("issuing")}}, ""},
	} {
		tc.req.Who = tester
		_, err := v.e.CreateDomain(t.Context(), tc.req)
		if name == "excluded by the root" {
			// No exclusion on this chain: the name is fine – a control case.
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		if !deniedWith(err, tc.want) {
			t.Errorf("%s: %v, want a refusal with %q", name, err, tc.want)
		}
	}
}

func TestDomainRejectsCAWithoutServerAuth(t *testing.T) {
	t.Parallel()
	v := domainEnv(t)
	v.intermediate(t, "agent-ca", "root", func(r *IntermediateRequest) { r.EKULimit = []string{"clientAuth"} })
	request := DomainRequest{Name: "agent-only.lan", DomainSettings: DomainSettings{CA: ptr("agent-ca"), Preset: ptr("server")}, Who: tester}
	if _, err := v.e.CreateDomain(t.Context(), request); !deniedWith(err, `CA "agent-ca" does not allow serverAuth required by preset "server"`) {
		t.Fatalf("create with a clientAuth-only CA: %v", err)
	}
	d, err := v.e.CreateDomain(t.Context(), DomainRequest{Name: "homelab.lan", DomainSettings: DomainSettings{CA: ptr("issuing")}, Who: tester})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.e.UpdateDomain(t.Context(), d.ID, DomainSettings{CA: ptr("agent-ca"), Preset: ptr("server")}, tester); !deniedWith(err, `CA "agent-ca" does not allow serverAuth required by preset "server"`) {
		t.Fatalf("update to a clientAuth-only CA: %v", err)
	}
}

func TestDomainLookup(t *testing.T) {
	t.Parallel()
	v := domainEnv(t)
	ctx := t.Context()
	mk := func(name string, s DomainSettings) {
		t.Helper()
		if s.CA == nil {
			s.CA = ptr("issuing")
		}
		if _, err := v.e.CreateDomain(ctx, DomainRequest{Name: name, DomainSettings: s, Who: tester}); err != nil {
			t.Fatal(err)
		}
	}
	mk("homelab.lan", DomainSettings{Wildcards: ptr(true), IPRanges: []string{"10.1.0.0/16"}})
	mk("lab.homelab.lan", DomainSettings{IncludeSubdomains: ptr(false), Approval: ptr(ApprovalOpen)})
	for _, tc := range []struct{ typ, value, want string }{
		{"dns", "homelab.lan", "homelab.lan"},
		{"dns", "nas.homelab.lan", "homelab.lan"},
		{"dns", "NAS.Homelab.LAN", "homelab.lan"},
		{"dns", "lab.homelab.lan", "lab.homelab.lan"}, // the most specific
		{"dns", "x.lab.homelab.lan", "homelab.lan"},   // lab.* has no sub-domains: the parent serves
		{"dns", "*.homelab.lan", "homelab.lan"},       // wildcards on
		{"dns", "*.lab.homelab.lan", "homelab.lan"},   // lab has none, its parent has
		{"dns", "homelab.lan.evil.example", ""},       // suffix tricks
		{"dns", "xhomelab.lan", ""},
		{"ip", "10.1.2.3", "homelab.lan"},
		{"ip", "10.2.0.1", ""},
		{"ip", "not-an-ip", ""},
	} {
		d, err := v.e.DomainFor(ctx, tc.typ, tc.value)
		if err != nil {
			t.Fatal(err)
		}
		got := ""
		if d != nil {
			got = d.Name
		}
		if got != tc.want {
			t.Errorf("%s %s: %q, want %q", tc.typ, tc.value, got, tc.want)
		}
	}
}

// TestDomainPermissions: viewers read the domains of their CA, admins
// manage them with a fresh second factor, others see nothing.
func TestDomainPermissions(t *testing.T) {
	t.Parallel()
	v := domainEnv(t)
	ctx := t.Context()
	d, err := v.e.CreateDomain(ctx, DomainRequest{Name: "homelab.lan", DomainSettings: DomainSettings{CA: ptr("issuing")}, Who: tester})
	if err != nil {
		t.Fatal(err)
	}
	now := v.clk.Now()
	viewer := signedIn("view", now, authz.Binding{CA: "issuing", Role: authz.Viewer})
	other := signedIn("other", now, authz.Binding{CA: "open", Role: authz.Admin})
	stale := signedIn("adm", now.Add(-authz.StepUpWindow-60e9), authz.Binding{Role: authz.Admin})
	if list, err := v.e.ListDomains(ctx, viewer); err != nil || len(list) != 1 {
		t.Errorf("viewer list: %v %v", list, err)
	}
	if list, err := v.e.ListDomains(ctx, other); err != nil || len(list) != 0 {
		t.Errorf("other CA's admin sees: %v %v", list, err)
	}
	if _, err := v.e.GetDomain(ctx, other, d.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("other CA's admin gets: %v", err)
	}
	if _, err := v.e.UpdateDomain(ctx, d.ID, DomainSettings{Approval: ptr(ApprovalOpen)}, viewer); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("viewer changes: %v", err)
	}
	if _, err := v.e.UpdateDomain(ctx, d.ID, DomainSettings{Approval: ptr(ApprovalOpen)}, stale); !errors.Is(err, authz.ErrStepUpRequired) {
		t.Errorf("admin without step-up: %v", err)
	}
	if err := v.e.DeleteDomain(ctx, d.ID, other); !errors.Is(err, ErrNotFound) {
		t.Errorf("other CA's admin deletes: %v", err)
	}
}
