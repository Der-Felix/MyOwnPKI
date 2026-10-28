package tenant

import (
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/predecessor"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

func TestPredecessorDefaults(t *testing.T) {
	t.Parallel()
	v := testinstance.New(t, testinstance.Options{})
	s := &Store{DB: v.SystemDB.Write, Clock: v.Clock}
	ctx := t.Context()
	got, err := s.Defaults(ctx, store.DefaultTenant)
	if err != nil {
		t.Fatal(err)
	}
	if *got.AgentPredecessor != predecessor.DefaultAgent || *got.OtherPredecessor != predecessor.DefaultOther {
		t.Fatalf("factory defaults: agent %+v, other %+v", got.AgentPredecessor, got.OtherPredecessor)
	}
	agent := predecessor.Policy{Choice: predecessor.Never}
	other := predecessor.Policy{Choice: predecessor.After, Days: 30}
	got.AgentPredecessor, got.OtherPredecessor = &agent, &other
	if setErr := s.Set(ctx, store.DefaultTenant, *got, testinstance.Console); setErr != nil {
		t.Fatal(setErr)
	}
	got.AgentPredecessor = nil
	got.OtherPredecessor = nil
	if preserveErr := s.Set(ctx, store.DefaultTenant, *got, testinstance.Console); preserveErr != nil {
		t.Fatal(preserveErr)
	}
	stored, err := s.Defaults(ctx, store.DefaultTenant)
	if err != nil || stored.AgentPredecessor.Normalize() != agent || stored.OtherPredecessor.Normalize() != other {
		t.Fatalf("stored policies: %+v, %v", stored, err)
	}
	bad := predecessor.Policy{Choice: predecessor.After, Days: 31}
	stored.OtherPredecessor = &bad
	if err := s.Set(ctx, store.DefaultTenant, *stored, testinstance.Console); err == nil {
		t.Error("31-day default accepted")
	}
}
