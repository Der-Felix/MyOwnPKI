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

// A thumbprint with a line break is not the canonical text the ACME server
// computes, so a reservation of it could never match a newAccount; the
// standard decoder skips CR and LF, b64url.Decode does not.
func TestRegisterACMEAccountRefusesLineBreaks(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollAuto)
	_, token, _ := e.admitted(t, "proxy1.homelab.lan")
	c, err := e.s.Identify(t.Context(), token, "")
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
	thumb := jwk.Thumbprint()
	for _, text := range []string{thumb + "\n", thumb + "\r\n", "\n" + thumb, thumb[:10] + "\r" + thumb[10:], thumb[:10] + "\n" + thumb[10:]} {
		if err := e.s.RegisterACMEAccount(t.Context(), c, text); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q: %v", text, err)
		}
	}
	if err := e.s.RegisterACMEAccount(t.Context(), c, thumb); err != nil {
		t.Fatalf("the clean thumbprint after the refusals: %v", err)
	}
}
