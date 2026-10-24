package agents

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/acme/jose"
	"github.com/Der-Felix/MyOwnPKI/internal/tenant"
)

func TestRegisterACMEAccount(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollAuto)
	_, first, _ := e.admitted(t, "proxy1.homelab.lan")
	_, second, _ := e.admitted(t, "proxy2.homelab.lan")
	c1, err := e.s.Identify(t.Context(), first, "")
	if err != nil {
		t.Fatal(err)
	}
	c2, err := e.s.Identify(t.Context(), second, "")
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := jose.KeyFor(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := e.s.RegisterACMEAccount(t.Context(), c1, jwk.Thumbprint()); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.s.RegisterACMEAccount(t.Context(), c2, jwk.Thumbprint()); !errors.Is(err, ErrConflict) {
		t.Fatalf("foreign key reservation: %v", err)
	}
	if err := e.s.RegisterACMEAccount(t.Context(), c1, "not-a-thumbprint"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid thumbprint: %v", err)
	}
}
