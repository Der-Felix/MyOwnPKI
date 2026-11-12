package tenant

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

// TestTrustPage (v0.2.2): on by default; a change without the field keeps
// the stored value (clients of v0.2 don't send it); the public listener
// reads it without a permission check.
func TestTrustPage(t *testing.T) {
	t.Parallel()
	v := testinstance.New(t, testinstance.Options{})
	s := &Store{DB: v.SystemDB.Write, Clock: v.Clock}
	ctx := t.Context()
	got, err := s.Get(ctx, store.DefaultTenant, testinstance.Console)
	if err != nil || got.TrustPage == nil || !*got.TrustPage {
		t.Fatalf("default: %v %v", got.TrustPage, err)
	}
	off := false
	got.TrustPage = &off
	if serr := s.Set(ctx, store.DefaultTenant, *got, testinstance.Console); serr != nil {
		t.Fatal(serr)
	}
	got.TrustPage = nil
	if serr := s.Set(ctx, store.DefaultTenant, *got, testinstance.Console); serr != nil {
		t.Fatal(serr)
	}
	if on, terr := s.TrustPage(ctx, store.DefaultTenant); terr != nil || on {
		t.Errorf("after a change without the field: %v %v, want off", on, terr)
	}
	again, err := s.Get(ctx, store.DefaultTenant, testinstance.Console)
	if err != nil || *again.TrustPage {
		t.Errorf("get: %v %v", *again.TrustPage, err)
	}
}

// TestAgentEnrollment (v0.3.0): verified by default (owner Q6); an unknown
// mode is refused; a change without the field keeps the stored mode.
func TestAgentEnrollment(t *testing.T) {
	t.Parallel()
	v := testinstance.New(t, testinstance.Options{})
	s := &Store{DB: v.SystemDB.Write, Clock: v.Clock}
	ctx := t.Context()
	got, err := s.Get(ctx, store.DefaultTenant, testinstance.Console)
	if err != nil || got.AgentEnrollment == nil || *got.AgentEnrollment != EnrollVerified {
		t.Fatalf("default: %v %v", got.AgentEnrollment, err)
	}
	bad := "open"
	got.AgentEnrollment = &bad
	if serr := s.Set(ctx, store.DefaultTenant, *got, testinstance.Console); serr == nil {
		t.Error("an unknown mode was stored")
	}
	manual := EnrollManual
	got.AgentEnrollment = &manual
	if serr := s.Set(ctx, store.DefaultTenant, *got, testinstance.Console); serr != nil {
		t.Fatal(serr)
	}
	got.AgentEnrollment = nil
	if serr := s.Set(ctx, store.DefaultTenant, *got, testinstance.Console); serr != nil {
		t.Fatal(serr)
	}
	if mode, merr := s.AgentEnrollment(ctx, store.DefaultTenant); merr != nil || mode != EnrollManual {
		t.Errorf("after a change without the field: %q %v, want manual", mode, merr)
	}
}

func TestStepUpMinutes(t *testing.T) {
	t.Parallel()
	v := testinstance.New(t, testinstance.Options{})
	s := &Store{DB: v.SystemDB.Write, Clock: v.Clock}
	ctx := t.Context()
	admin := keys.Who{
		Actor: audit.Actor{Type: audit.ActorUser, Name: "tenant-admin"},
		Principal: &authz.Principal{Kind: authz.KindUser, Bindings: []authz.Binding{
			{Tenant: store.DefaultTenant, Role: authz.Admin},
		}},
	}
	got, err := s.Get(ctx, store.DefaultTenant, admin)
	if err != nil || got.StepUpMinutes == nil || *got.StepUpMinutes != DefaultStepUpMinutes {
		t.Fatalf("default: %v %v", got.StepUpMinutes, err)
	}
	for _, role := range []authz.Role{authz.Viewer, authz.Operator} {
		who := admin
		who.Principal = &authz.Principal{Kind: authz.KindUser, Bindings: []authz.Binding{{Tenant: store.DefaultTenant, Role: role}}}
		if err := s.Set(ctx, store.DefaultTenant, *got, who); !errors.Is(err, authz.ErrDenied) {
			t.Errorf("%s can change settings: %v", role, err)
		}
	}
	for _, minutes := range StepUpMinuteValues {
		got.StepUpMinutes = &minutes
		if err := s.Set(ctx, store.DefaultTenant, *got, admin); err != nil {
			t.Errorf("set %d: %v", minutes, err)
			continue
		}
		stored, err := s.Get(ctx, store.DefaultTenant, admin)
		if err != nil || *stored.StepUpMinutes != minutes {
			t.Errorf("get %d: %v %v", minutes, stored.StepUpMinutes, err)
		}
	}
	got.StepUpMinutes = nil
	if err := s.Set(ctx, store.DefaultTenant, *got, admin); err != nil {
		t.Fatal(err)
	}
	stored, _ := s.Get(ctx, store.DefaultTenant, admin)
	if *stored.StepUpMinutes != 60 {
		t.Errorf("nil did not preserve 60: %v", *stored.StepUpMinutes)
	}
	for _, minutes := range []int{0, -1, 7, 61, 120} {
		got.StepUpMinutes = &minutes
		if err := s.Set(ctx, store.DefaultTenant, *got, admin); !errors.Is(err, ErrInvalid) {
			t.Errorf("invalid %d: %v", minutes, err)
		}
	}
	ten := 10
	got.StepUpMinutes = &ten
	if err := s.Set(ctx, store.DefaultTenant, *got, admin); err != nil {
		t.Fatal(err)
	}
	v.Deliver(t)
	var actor, details string
	if err := v.InstanceAudit.Read.QueryRowContext(ctx,
		`SELECT actor_name, details_json FROM audit_entries WHERE action = ? ORDER BY seq DESC LIMIT 1`, ActionSettings,
	).Scan(&actor, &details); err != nil {
		t.Fatal(err)
	}
	if actor != "tenant-admin" || !strings.Contains(details, `"step_up_minutes":10`) || !strings.Contains(details, `"was_step_up_minutes":60`) {
		t.Errorf("settings audit actor %q details %s", actor, details)
	}
}

// TestEnrollmentModeNeedsStepUp: the mode decides whether a host is admitted
// without a person, so changing it is as weighty as approving an enrollment.
// It needs a fresh second factor and never works with an API token; the
// other settings and reading stay as they were.
func TestEnrollmentModeNeedsStepUp(t *testing.T) {
	t.Parallel()
	v := testinstance.New(t, testinstance.Options{})
	s := &Store{DB: v.SystemDB.Write, Clock: v.Clock}
	ctx := t.Context()
	person := func(role authz.Role, fresh bool, viaToken bool) keys.Who {
		p := &authz.Principal{Kind: authz.KindUser, ViaToken: viaToken, Bindings: []authz.Binding{{Tenant: store.DefaultTenant, Role: role}}}
		if fresh {
			p.StepUpAt = v.Clock.Now()
		}
		return keys.Who{Actor: audit.Actor{Type: audit.ActorUser, Name: "tenant-admin"}, Principal: p}
	}
	mode := func() string {
		t.Helper()
		m, err := s.AgentEnrollment(ctx, store.DefaultTenant)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	with := func(m *string, trust bool) Settings {
		t.Helper()
		got, err := s.Get(ctx, store.DefaultTenant, testinstance.Console)
		if err != nil {
			t.Fatal(err)
		}
		got.AgentEnrollment, got.TrustPage = m, &trust
		return *got
	}
	auto, verified := EnrollAuto, EnrollVerified

	// No fresh second factor: refused with the prompt for it, nothing stored.
	if err := s.Set(ctx, store.DefaultTenant, with(&auto, true), person(authz.Admin, false, false)); !errors.Is(err, authz.ErrStepUpRequired) {
		t.Errorf("mode change without step-up: %v, want ErrStepUpRequired", err)
	}
	// An API token never satisfies it, even when the role is admin and the
	// token was created right after a step-up.
	err := s.Set(ctx, store.DefaultTenant, with(&auto, true), person(authz.Admin, true, true))
	var tokenErr *authz.TokenStepUpError
	if !errors.Is(err, authz.ErrDenied) || errors.Is(err, authz.ErrStepUpRequired) || !errors.As(err, &tokenErr) {
		t.Errorf("mode change with a token: %v, want a TokenStepUpError", err)
	}
	if got := mode(); got != EnrollVerified {
		t.Fatalf("a refused change stored %q", got)
	}
	// A role below admin is denied, step-up or not.
	if err := s.Set(ctx, store.DefaultTenant, with(&auto, true), person(authz.Operator, true, false)); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("operator changes the mode: %v", err)
	}

	// The same mode, or none, is no change: a script that sends the whole
	// settings document keeps working, with a token too; so does every other
	// setting.
	token := person(authz.Admin, false, true)
	for name, m := range map[string]*string{"same mode": &verified, "no mode": nil} {
		if err := s.Set(ctx, store.DefaultTenant, with(m, false), token); err != nil {
			t.Errorf("%s with a token: %v", name, err)
		}
	}
	if on, terr := s.TrustPage(ctx, store.DefaultTenant); terr != nil || on {
		t.Errorf("the other setting was not stored: %v %v", on, terr)
	}

	// Reading is unchanged: any role, a token included.
	for _, who := range []keys.Who{person(authz.Viewer, false, false), person(authz.Operator, false, false), token} {
		if got, gerr := s.Get(ctx, store.DefaultTenant, who); gerr != nil || *got.AgentEnrollment != EnrollVerified {
			t.Errorf("read: %v %v", got, gerr)
		}
	}

	// With a fresh second factor the change goes through and the audit entry
	// names the old and the new mode.
	if err := s.Set(ctx, store.DefaultTenant, with(&auto, true), person(authz.Admin, true, false)); err != nil {
		t.Fatal(err)
	}
	if got := mode(); got != EnrollAuto {
		t.Errorf("mode after the change: %q", got)
	}
	// The proof runs out with the window.
	v.Clock.Advance(authz.StepUpWindow + time.Second)
	stale := person(authz.Admin, true, false)
	stale.Principal.StepUpAt = v.Clock.Now().Add(-authz.StepUpWindow - time.Second)
	if err := s.Set(ctx, store.DefaultTenant, with(&verified, true), stale); !errors.Is(err, authz.ErrStepUpRequired) {
		t.Errorf("expired step-up: %v", err)
	}
	v.Deliver(t)
	var details string
	if err := v.InstanceAudit.Read.QueryRowContext(ctx,
		`SELECT details_json FROM audit_entries WHERE action = ? ORDER BY seq DESC LIMIT 1`, ActionSettings,
	).Scan(&details); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(details, `"agent_enrollment":"auto"`) || !strings.Contains(details, `"was_agent_enrollment":"verified"`) {
		t.Errorf("audit details %s", details)
	}
}
