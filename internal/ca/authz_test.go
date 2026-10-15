package ca

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
)

// signedIn returns a web user with the given bindings in the default tenant.
func signedIn(name string, stepUp time.Time, bindings ...authz.Binding) keys.Who {
	for i := range bindings {
		bindings[i].Tenant = store.DefaultTenant
	}
	return keys.Who{
		Actor: audit.Actor{Type: audit.ActorUser, ID: "usr-" + name, Name: name}, SourceIP: "192.0.2.20",
		Principal: &authz.Principal{Kind: authz.KindUser, UserID: "usr-" + name, Username: name, Bindings: bindings, StepUpAt: stepUp},
	}
}

// TestEngineChecksPermissions: the engine itself refuses – an API or UI
// handler that forgets a check can't issue, revoke or manage CAs.
func TestEngineChecksPermissions(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	_, issuing := v.chain(t, caOpts{})
	req := Request{CA: "issuing", Preset: "server", DNSNames: []string{"a.homelab.lan"}}

	var noStepUp time.Time
	operator := signedIn("op", noStepUp, authz.Binding{CA: "issuing", Role: authz.Operator})
	viewer := signedIn("view", noStepUp, authz.Binding{Role: authz.Viewer})
	nobody := keys.Who{Actor: operator.Actor}

	for name, who := range map[string]keys.Who{"viewer": viewer, "no principal": nobody} {
		r := req
		r.Who = who
		if got := v.denied(t, r); !strings.Contains(got, "permission denied") {
			t.Errorf("%s issues: %q", name, got)
		}
	}
	req.Who = operator
	out := v.issue(t, req)

	// Revocation needs a fresh second factor.
	_, err := v.e.Revoke(t.Context(), RevokeRequest{CertificateID: out.ID, Reason: ReasonSuperseded, Who: operator})
	if !errors.Is(err, authz.ErrStepUpRequired) || !errors.Is(err, ErrDenied) {
		t.Fatalf("revoke without step-up: %v", err)
	}
	fresh := signedIn("op", v.clk.Now(), authz.Binding{CA: "issuing", Role: authz.Operator})
	res, err := v.e.Revoke(t.Context(), RevokeRequest{CertificateID: out.ID, Reason: ReasonSuperseded, Who: fresh})
	if err != nil {
		t.Fatal(err)
	}
	// The operator may not manage the CA, but the revocation is published.
	if !res.Published {
		t.Errorf("revocation by an operator not published: %+v", res.Warnings)
	}
	if _, err := v.e.SignCRL(t.Context(), issuing.id, 1, "manual", fresh); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("an operator signs a CRL directly: %v", err)
	}

	// CA management: tenant-wide admin only, with step-up.
	admin := signedIn("adm", v.clk.Now(), authz.Binding{Role: authz.Admin})
	rootReq := RootRequest{CASettings: CASettings{Name: "root2", BaseURL: baseURL}, Subject: Subject{CommonName: "Root 2"}}
	for name, who := range map[string]keys.Who{"operator": fresh, "CA admin": signedIn("cadm", v.clk.Now(), authz.Binding{CA: "issuing", Role: authz.Admin})} {
		rootReq.Who = who
		if _, err := v.e.CreateRoot(t.Context(), rootReq); !errors.Is(err, authz.ErrDenied) {
			t.Errorf("%s creates a root: %v", name, err)
		}
	}
	rootReq.Who = admin
	if _, err := v.e.CreateRoot(t.Context(), rootReq); err != nil {
		t.Errorf("tenant admin creates a root: %v", err)
	}

	// Every refusal is in the audit log as denied, with the reason.
	denied := 0
	for _, row := range v.auditRows(t) {
		if row.result == string(audit.ResultDenied) && strings.Contains(strings.Join(anyStrings(row.details["reasons"]), " "), "permission denied") {
			denied++
		}
	}
	if denied < 4 {
		t.Errorf("%d denied permission entries in the audit log, want at least 4", denied)
	}
}

func anyStrings(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, x := range list {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}
