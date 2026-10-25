package tenant

import (
	"testing"

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
