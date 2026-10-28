package tenant

import (
	"errors"
	"strings"
	"testing"

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
