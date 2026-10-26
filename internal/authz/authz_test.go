package authz

import (
	"errors"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 15, 8, 0, 0, 0, time.UTC)

func user(bindings ...Binding) *Principal {
	return &Principal{Kind: KindUser, UserID: "usr-1", Username: "alice", Bindings: bindings, StepUpAt: now}
}

// TestRoleMatrix pins the role table of PHASE1 step 10: a change must be a
// deliberate edit here as well.
func TestRoleMatrix(t *testing.T) {
	t.Parallel()
	all := []Permission{ReadPKI, ReadAudit, IssueCert, RevokeCert, DownloadKey, ManageCA, UploadCRL, ManageTenant, Unseal, ManageUsers}
	want := map[Role][]Permission{
		Viewer:   {ReadPKI},
		Operator: {ReadPKI, IssueCert, RevokeCert, DownloadKey},
		Admin:    {ReadPKI, ReadAudit, IssueCert, RevokeCert, DownloadKey, ManageCA, UploadCRL, ManageTenant},
	}
	res := Resource{Tenant: "default", CA: "issuing"}
	for _, role := range Roles {
		p := user(Binding{Tenant: "default", Role: role})
		for _, perm := range all {
			allowed := false
			for _, w := range want[role] {
				allowed = allowed || w == perm
			}
			err := p.Check(perm, res, now)
			if (err == nil) != allowed {
				t.Errorf("%s / %s: %v, want allowed=%v", role, perm, err, allowed)
			}
			if err != nil && !errors.Is(err, ErrDenied) {
				t.Errorf("%s / %s: %v does not wrap ErrDenied", role, perm, err)
			}
		}
	}
}

func TestViewerCantReadTheAuditLog(t *testing.T) {
	t.Parallel()
	err := user(Binding{Tenant: "default", Role: Viewer}).Check(ReadAudit, Resource{Tenant: "default"}, now)
	if !errors.Is(err, ErrDenied) {
		t.Errorf("viewer reads audit: %v", err)
	}
}

func TestScopes(t *testing.T) {
	t.Parallel()
	p := user(Binding{Tenant: "default", CA: "issuing", Role: Admin}, Binding{Tenant: "default", Role: Viewer})
	cases := []struct {
		perm Permission
		res  Resource
		ok   bool
	}{
		{ManageCA, Resource{"default", "issuing"}, true},      // CA admin
		{ManageCA, Resource{"default", "other"}, false},       // only viewer there
		{ReadPKI, Resource{"default", "other"}, true},         // tenant-wide viewer
		{ManageCA, Resource{"default", ""}, false},            // creating a CA needs a tenant-wide admin
		{ReadPKI, Resource{"other-tenant", "issuing"}, false}, // no role in that tenant
	}
	for _, c := range cases {
		if err := p.Check(c.perm, c.res, now); (err == nil) != c.ok {
			t.Errorf("%s on %+v: %v, want ok=%v", c.perm, c.res, err, c.ok)
		}
	}
	if err := p.Check(ManageCA, Resource{"default", "other"}, now); err == nil ||
		err.Error() != `permission denied: ca.manage on CA "other" in tenant default needs the role admin` {
		t.Errorf("message: %v", err)
	}
}

func TestInstanceAdminIsNotATenantAdmin(t *testing.T) {
	t.Parallel()
	p := &Principal{Kind: KindUser, Username: "root-admin", InstanceAdmin: true, StepUpAt: now}
	for _, perm := range []Permission{Unseal, ManageUsers} {
		if err := p.Check(perm, Resource{}, now); err != nil {
			t.Errorf("%s: %v", perm, err)
		}
	}
	if err := p.Check(ReadPKI, Resource{Tenant: "default"}, now); !errors.Is(err, ErrDenied) {
		t.Errorf("instance admin reads PKI without a role: %v", err)
	}
	if err := user(Binding{Tenant: "default", Role: Admin}).Check(Unseal, Resource{}, now); !errors.Is(err, ErrDenied) {
		t.Errorf("tenant admin unseals: %v", err)
	}
}

func TestStepUp(t *testing.T) {
	t.Parallel()
	p := user(Binding{Tenant: "default", Role: Admin})
	res := Resource{Tenant: "default", CA: "issuing"}
	for _, c := range []struct {
		at   time.Time
		perm Permission
		ok   bool
	}{
		{now.Add(StepUpWindow), RevokeCert, true},
		{now.Add(StepUpWindow + time.Second), RevokeCert, false},
		{now.Add(-time.Second), RevokeCert, false}, // step-up from the future: clock jump
		{now.Add(time.Hour), IssueCert, true},      // no step-up needed
	} {
		err := p.Check(c.perm, res, c.at)
		if (err == nil) != c.ok || (err != nil && !errors.Is(err, ErrStepUpRequired)) {
			t.Errorf("%s at +%v: %v", c.perm, c.at.Sub(now), err)
		}
	}
	// A step-up at 08:00:00.700, checked by the engine at 08:00:00 (whole
	// seconds) – the same second, not the future.
	p.StepUpAt = now.Add(700 * time.Millisecond)
	if err := p.Check(DownloadKey, res, now); err != nil {
		t.Errorf("step-up in the same second: %v", err)
	}
	p.StepUpAt = time.Time{}
	if err := p.Check(DownloadKey, res, now); !errors.Is(err, ErrStepUpRequired) {
		t.Errorf("never stepped up: %v", err)
	}
	// The role is checked first: no step-up prompt for something the user
	// may not do at all.
	if err := user().Check(ManageCA, res, now.Add(time.Hour)); !errors.Is(err, ErrDenied) {
		t.Errorf("no role: %v", err)
	}
}

func TestSpecialPrincipals(t *testing.T) {
	t.Parallel()
	var nobody *Principal
	if err := nobody.Check(ReadPKI, Resource{Tenant: "default"}, now); !errors.Is(err, ErrDenied) {
		t.Errorf("nil principal: %v", err)
	}
	for _, p := range []*Principal{Console(), System("crl-maintainer")} {
		if err := p.Check(ManageCA, Resource{Tenant: "default"}, now); err != nil {
			t.Errorf("%s: %v", p.Kind, err)
		}
	}
	if err := (&Principal{Kind: "robot"}).Check(ReadPKI, Resource{Tenant: "default"}, now); !errors.Is(err, ErrDenied) {
		t.Errorf("unknown kind: %v", err)
	}
}

// TestTokenNeverSatisfiesStepUp: a token gets a plain denial for every
// step-up permission – even with a fresh StepUpAt and the role – and never
// the step-up prompt it could not answer.
func TestTokenNeverSatisfiesStepUp(t *testing.T) {
	t.Parallel()
	tokenNow := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	p := &Principal{Kind: KindUser, UserID: "u1", ViaToken: true, InstanceAdmin: true, StepUpAt: tokenNow,
		Bindings: []Binding{{Tenant: "default", Role: Admin}}}
	for _, perm := range stepUp {
		if stepUpActions[perm] == "" {
			t.Errorf("%s: no action text for the token refusal", perm)
		}
		err := p.Check(perm, Resource{Tenant: "default"}, tokenNow)
		var tok *TokenStepUpError
		if !errors.As(err, &tok) || !errors.Is(err, ErrDenied) || errors.Is(err, ErrStepUpRequired) {
			t.Errorf("%s: %v", perm, err)
		}
	}
	if err := p.Check(IssueCert, Resource{Tenant: "default"}, tokenNow); err != nil {
		t.Errorf("issuing needs no step-up, a token may: %v", err)
	}
	if err := p.FreshStepUp(tokenNow); !errors.Is(err, ErrDenied) {
		t.Errorf("own account by token: %v", err)
	}
}

func TestPerProofStepUpDuration(t *testing.T) {
	t.Parallel()
	p := user(Binding{Tenant: "default", Role: Admin})
	res := Resource{Tenant: "default"}
	for _, minutes := range []int{5, 10, 15, 30, 60} {
		p.StepUpDuration = time.Duration(minutes) * time.Minute
		at := now.Add(p.StepUpDuration)
		if err := p.Check(RevokeCert, res, at); err != nil {
			t.Errorf("%d minutes at exact expiry: %v", minutes, err)
		}
		if err := p.FreshStepUp(at); err != nil {
			t.Errorf("%d minutes own account at exact expiry: %v", minutes, err)
		}
		at = at.Add(time.Nanosecond)
		if err := p.Check(RevokeCert, res, at); !errors.Is(err, ErrStepUpRequired) {
			t.Errorf("%d minutes after expiry: %v", minutes, err)
		}
		if err := p.FreshStepUp(at); !errors.Is(err, ErrStepUpRequired) {
			t.Errorf("%d minutes own account after expiry: %v", minutes, err)
		}
	}
	p.StepUpDuration = 0
	if err := p.Check(RevokeCert, res, now.Add(StepUpWindow)); err != nil {
		t.Errorf("zero duration does not use the default: %v", err)
	}
	if err := p.Check(RevokeCert, res, now.Add(StepUpWindow+time.Nanosecond)); !errors.Is(err, ErrStepUpRequired) {
		t.Errorf("zero duration past the default: %v", err)
	}
}
