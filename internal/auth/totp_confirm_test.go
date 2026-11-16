package auth

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
)

func confirmedAt(t *testing.T, v *env, id string) (string, bool) {
	t.Helper()
	var at *string
	if err := v.sys.QueryRowContext(t.Context(), `SELECT totp_confirmed_at FROM users WHERE id = ?`, id).Scan(&at); err != nil {
		t.Fatal(err)
	}
	if at == nil {
		return "", false
	}
	return *at, true
}

// TestConfirmTOTPCodes: the first code confirms the authenticator – the
// right code once, nothing else.
func TestConfirmTOTPCodes(t *testing.T) {
	t.Parallel()
	step := time.Duration(totpPeriod) * time.Second
	tests := []struct {
		name string
		// code gets the owner's secret and the clock.
		code func(v *env, secret []byte) string
		ok   bool
	}{
		{"current code", func(v *env, s []byte) string { return hotp(s, counter(v.clk.Now()), totpDigits) }, true},
		{"code with the space apps show", func(v *env, s []byte) string {
			c := hotp(s, counter(v.clk.Now()), totpDigits)
			return c[:3] + " " + c[3:]
		}, true},
		{"code with blanks around", func(v *env, s []byte) string { return " " + hotp(s, counter(v.clk.Now()), totpDigits) + " " }, true},
		{"previous step (clock skew)", func(v *env, s []byte) string { return hotp(s, counter(v.clk.Now().Add(-step)), totpDigits) }, true},
		{"next step (clock skew)", func(v *env, s []byte) string { return hotp(s, counter(v.clk.Now().Add(step)), totpDigits) }, true},
		{"two steps back", func(v *env, s []byte) string { return hotp(s, counter(v.clk.Now().Add(-2*step)), totpDigits) }, false},
		{"two steps ahead", func(v *env, s []byte) string { return hotp(s, counter(v.clk.Now().Add(2*step)), totpDigits) }, false},
		{"a code of another secret", func(v *env, _ []byte) string {
			return hotp([]byte("another secret, 20 bytes"), counter(v.clk.Now()), totpDigits)
		}, false},
		{"the other user's current code", func(v *env, _ []byte) string { return v.code("bob") }, false},
		{"empty", func(*env, []byte) string { return "" }, false},
		{"five digits", func(v *env, s []byte) string { return hotp(s, counter(v.clk.Now()), totpDigits)[1:] }, false},
		{"seven digits", func(v *env, s []byte) string { return hotp(s, counter(v.clk.Now()), totpDigits) + "0" }, false},
		{"letters", func(*env, []byte) string { return "abcdef" }, false},
		{"a recovery code is not a TOTP code", func(v *env, _ []byte) string { return v.recovery["alice"][0] }, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v := newEnv(t)
			id := v.create(t, "alice", false)
			v.create(t, "bob", false)
			err := v.s.ConfirmTOTP(t.Context(), id, tc.code(v, v.secrets["alice"]), console)
			_, confirmed := confirmedAt(t, v, id)
			log := strings.Join(v.actions(t), "\n")
			if tc.ok {
				if err != nil || !confirmed {
					t.Fatalf("error %v, confirmed %v", err, confirmed)
				}
				if !strings.Contains(log, "user.totp_confirm/success console") {
					t.Errorf("no audit entry:\n%s", log)
				}
				return
			}
			if !errors.Is(err, ErrInvalidCode) {
				t.Errorf("error %v, want ErrInvalidCode", err)
			}
			if confirmed || strings.Contains(log, "user.totp_confirm/success") {
				t.Errorf("a wrong code confirmed the authenticator (confirmed %v):\n%s", confirmed, log)
			}
		})
	}
}

// TestConfirmTOTPOnce: a code that confirmed cannot be used again, neither
// to confirm nor to sign in; the next step's code works.
func TestConfirmTOTPOnce(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	id := v.create(t, "alice", false)
	code := v.code("alice")
	if err := v.s.ConfirmTOTP(t.Context(), id, code, console); err != nil {
		t.Fatal(err)
	}
	at, _ := confirmedAt(t, v, id)
	if err := v.s.ConfirmTOTP(t.Context(), id, code, console); !errors.Is(err, ErrInvalidCode) {
		t.Errorf("the same code confirmed twice: %v", err)
	}
	// The sign-in no longer asks for a first-time setup, but the code that
	// confirmed is spent.
	v.clk.Advance(time.Second)
	res, err := v.s.Login(t.Context(), "alice", password, ip)
	if err != nil || res.FirstTOTP {
		t.Fatalf("login after the confirmation: %+v %v", res, err)
	}
	if _, err := v.s.LoginTOTP(t.Context(), res.Token, code, ip); !errors.Is(err, ErrInvalidCode) {
		t.Errorf("the confirming code signed in: %v", err)
	}
	v.clk.Advance(time.Duration(totpPeriod) * time.Second)
	if _, err := v.s.LoginTOTP(t.Context(), res.Token, v.code("alice"), ip); err != nil {
		t.Errorf("the next code: %v", err)
	}
	if got, _ := confirmedAt(t, v, id); got != at {
		t.Errorf("the confirmation time moved from %s to %s", at, got)
	}
}

// TestConfirmTOTPNeedsTheRight: only the console, a system job or an instance
// admin with a fresh step-up may confirm for somebody else; a refusal is
// audited and leaves the user unconfirmed.
func TestConfirmTOTPNeedsTheRight(t *testing.T) {
	t.Parallel()
	person := func(v *env, mut func(p *authz.Principal)) *authz.Principal {
		p := &authz.Principal{Kind: authz.KindUser, UserID: "usr_other", Username: "carol", InstanceAdmin: true, StepUpAt: v.clk.Now(), StepUpDuration: 5 * time.Minute}
		mut(p)
		return p
	}
	tests := []struct {
		name string
		who  func(v *env) *authz.Principal
		want error // nil = allowed
	}{
		{"console", func(*env) *authz.Principal { return authz.Console() }, nil},
		{"system job", func(*env) *authz.Principal { return authz.System("job") }, nil},
		{"instance admin with a fresh step-up", func(v *env) *authz.Principal { return person(v, func(*authz.Principal) {}) }, nil},
		{"nobody", func(*env) *authz.Principal { return nil }, authz.ErrDenied},
		{"unknown kind", func(*env) *authz.Principal { return &authz.Principal{Kind: "agent", InstanceAdmin: true} }, authz.ErrDenied},
		{"user without instance rights", func(v *env) *authz.Principal {
			return person(v, func(p *authz.Principal) {
				p.InstanceAdmin = false
				p.Bindings = []authz.Binding{{Tenant: "default", Role: authz.Admin}}
			})
		}, authz.ErrDenied},
		{"instance admin without step-up", func(v *env) *authz.Principal {
			return person(v, func(p *authz.Principal) { p.StepUpAt = time.Time{} })
		}, authz.ErrStepUpRequired},
		{"instance admin with an old step-up", func(v *env) *authz.Principal {
			return person(v, func(p *authz.Principal) { p.StepUpAt = v.clk.Now().Add(-6 * time.Minute) })
		}, authz.ErrStepUpRequired},
		{"instance admin with a step-up from the future", func(v *env) *authz.Principal {
			return person(v, func(p *authz.Principal) { p.StepUpAt = v.clk.Now().Add(time.Hour) })
		}, authz.ErrStepUpRequired},
		{"an API token of an instance admin", func(v *env) *authz.Principal {
			return person(v, func(p *authz.Principal) { p.ViaToken = true })
		}, authz.ErrDenied},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v := newEnv(t)
			id := v.create(t, "alice", false)
			p := tc.who(v)
			who := keys.Who{Actor: audit.Actor{Type: audit.ActorUser, Name: "carol"}, Principal: p}
			err := v.s.ConfirmTOTP(t.Context(), id, v.code("alice"), who)
			_, confirmed := confirmedAt(t, v, id)
			log := strings.Join(v.actions(t), "\n")
			if tc.want == nil {
				if err != nil || !confirmed {
					t.Fatalf("error %v, confirmed %v", err, confirmed)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("error %v, want %v", err, tc.want)
			}
			if confirmed {
				t.Error("a refused caller confirmed the authenticator")
			}
			if !strings.Contains(log, "user.totp_confirm/denied") || strings.Contains(log, "user.totp_confirm/success") {
				t.Errorf("audit log:\n%s", log)
			}
		})
	}
}

// TestConfirmTOTPUnknownUser: an ID that does not exist fails and writes no
// success entry.
func TestConfirmTOTPUnknownUser(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.create(t, "alice", false)
	for _, id := range []string{"usr_missing", "", "' OR 1=1 --"} {
		if err := v.s.ConfirmTOTP(t.Context(), id, v.code("alice"), console); err == nil || errors.Is(err, ErrInvalidCode) {
			t.Errorf("id %q: %v, want a lookup error", id, err)
		}
	}
	if strings.Contains(strings.Join(v.actions(t), "\n"), "user.totp_confirm/success") {
		t.Error("a success entry for a user that does not exist")
	}
}
