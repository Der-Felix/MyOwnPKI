package auth

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/auth/passkeytest"
	"github.com/Der-Felix/MyOwnPKI/internal/store/systemdb"
)

const browserOrigin = "https://pki.homelab.lan:9443"

func withPasskeys(t *testing.T, v *env) {
	t.Helper()
	p, err := NewPasskeys("pki.homelab.lan", browserOrigin)
	if err != nil {
		t.Fatal(err)
	}
	v.s.Passkeys = p
}

// register adds a passkey of authn for the signed-in session token.
func register(t *testing.T, v *env, token string, authn *passkeytest.Authenticator) *Passkey {
	t.Helper()
	options, err := v.s.BeginPasskeyRegistration(t.Context(), token, password, ip)
	if err != nil {
		t.Fatalf("begin registration: %v", err)
	}
	answer, err := authn.Create(options)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := v.s.FinishPasskeyRegistration(t.Context(), token, "YubiKey", answer, ip)
	if err != nil {
		t.Fatalf("finish registration: %v", err)
	}
	return pk
}

// TestPasskeyRegistrationAndLogin: register with a virtual authenticator,
// then sign in with password + passkey and step up with it.
func TestPasskeyRegistrationAndLogin(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	withPasskeys(t, v)
	id := v.create(t, "alice", false)
	token := v.login(t, "alice")
	other := v.login(t, "alice") // a second browser
	authn := passkeytest.New(browserOrigin)

	before, err := systemdb.New(v.sys).GetUser(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	pk := register(t, v, token, authn)
	if pk.Name != "YubiKey" || !strings.HasPrefix(pk.ID, "pk_") {
		t.Errorf("passkey %+v", pk)
	}
	after, _ := systemdb.New(v.sys).GetUser(t.Context(), id)
	if after.CredentialsEpoch != before.CredentialsEpoch+1 {
		t.Error("a new passkey must void the device cookies (credentials epoch)")
	}
	if _, aerr := v.s.Authenticate(t.Context(), other); !errors.Is(aerr, ErrNoSession) {
		t.Errorf("the other session survived the new passkey: %v", aerr)
	}
	if has, _ := v.s.HasPasskeys(t.Context(), id); !has {
		t.Error("HasPasskeys")
	}

	// Sign-in: password, then the passkey instead of a code.
	v.clk.Advance(time.Minute)
	res, err := v.s.Login(t.Context(), "alice", password, ip)
	if err != nil {
		t.Fatal(err)
	}
	options, err := v.s.BeginPasskeyLogin(t.Context(), res.Token, Client{IP: ip})
	if err != nil {
		t.Fatal(err)
	}
	answer, err := authn.Get(options)
	if err != nil {
		t.Fatal(err)
	}
	full, err := v.s.FinishPasskeyLogin(t.Context(), res.Token, answer, Client{IP: ip})
	if err != nil {
		t.Fatalf("passkey sign-in: %v", err)
	}
	if full.Token == res.Token || full.Factor != "passkey" || full.DeviceCookie == "" {
		t.Errorf("sign-in result %+v: want a new session ID and a device cookie", full)
	}
	// The challenge works once.
	if _, rerr := v.s.FinishPasskeyLogin(t.Context(), full.Token, answer, Client{IP: ip}); !errors.Is(rerr, ErrNoCeremony) {
		t.Errorf("replayed answer: %v", rerr)
	}

	// Step-up with the passkey while signed in.
	v.clk.Advance(10 * time.Minute)
	options, err = v.s.BeginPasskeyLogin(t.Context(), full.Token, Client{IP: ip})
	if err != nil {
		t.Fatal(err)
	}
	answer, _ = authn.Get(options)
	stepped, err := v.s.FinishPasskeyLogin(t.Context(), full.Token, answer, Client{IP: ip})
	if err != nil || stepped.Session.StepUpAt.IsZero() || stepped.Token != full.Token {
		t.Fatalf("passkey step-up: %v %+v", err, stepped)
	}

	list, err := v.s.ListPasskeys(t.Context(), full.Token)
	if err != nil || len(list) != 1 || list[0].LastUsedAt.IsZero() {
		t.Errorf("list %+v %v", list, err)
	}
	if err := v.s.DeletePasskey(t.Context(), full.Token, pk.ID, "wrong password, long enough", ip); !errors.Is(err, ErrInvalidLogin) {
		t.Errorf("delete with a wrong password: %v", err)
	}
	if err := v.s.DeletePasskey(t.Context(), full.Token, pk.ID, password, ip); err != nil {
		t.Fatal(err)
	}
	if has, _ := v.s.HasPasskeys(t.Context(), id); has {
		t.Error("passkey still there")
	}
	acts := strings.Join(v.actions(t), "\n")
	for _, want := range []string{"user.passkey_add/success", `"factor":"passkey"`, "user.step_up/success", "user.passkey_remove/success"} {
		if !strings.Contains(acts, want) {
			t.Errorf("audit lacks %s", want)
		}
	}
}

// TestPasskeyRefusals: wrong origin, no user verification, a cloned
// authenticator, another user's passkey, registration without the password,
// and passkeys switched off.
func TestPasskeyRefusals(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	if _, err := v.s.BeginPasskeyLogin(t.Context(), "x", Client{IP: ip}); !errors.Is(err, ErrPasskeysOff) {
		t.Errorf("passkeys off: %v", err)
	}
	withPasskeys(t, v)
	v.create(t, "alice", false)
	v.create(t, "bob", false)
	token := v.login(t, "alice")
	if _, err := v.s.BeginPasskeyRegistration(t.Context(), token, "not the password", ip); !errors.Is(err, ErrInvalidLogin) {
		t.Errorf("registration without the current password: %v", err)
	}
	// A passkey made for another site (phishing) is refused.
	phish := passkeytest.New("https://pki.homelab.lan.evil.example")
	options, err := v.s.BeginPasskeyRegistration(t.Context(), token, password, ip)
	if err != nil {
		t.Fatal(err)
	}
	answer, _ := phish.Create(options)
	if _, err := v.s.FinishPasskeyRegistration(t.Context(), token, "", answer, ip); err == nil {
		t.Error("passkey from another origin registered")
	}
	// Without user verification (a bare security key without PIN).
	nouv := passkeytest.New(browserOrigin)
	nouv.UserVerified = false
	options, _ = v.s.BeginPasskeyRegistration(t.Context(), token, password, ip)
	answer, _ = nouv.Create(options)
	if _, err := v.s.FinishPasskeyRegistration(t.Context(), token, "", answer, ip); err == nil {
		t.Error("passkey without user verification registered")
	}

	authn := passkeytest.New(browserOrigin)
	register(t, v, token, authn)
	// The same authenticator can't register twice (excludeCredentials).
	options, _ = v.s.BeginPasskeyRegistration(t.Context(), token, password, ip)
	if _, err := authn.Create(options); err == nil {
		t.Error("the authenticator was not excluded")
	}

	signIn := func(name string, a *passkeytest.Authenticator) error {
		v.clk.Advance(time.Minute)
		res, err := v.s.Login(t.Context(), name, password, ip)
		if err != nil {
			return err
		}
		options, err := v.s.BeginPasskeyLogin(t.Context(), res.Token, Client{IP: ip})
		if err != nil {
			return err
		}
		answer, err := a.Get(options)
		if err != nil {
			return err
		}
		_, err = v.s.FinishPasskeyLogin(t.Context(), res.Token, answer, Client{IP: ip})
		return err
	}
	// bob has no passkey: alice's authenticator can't sign him in.
	if err := signIn("bob", authn); !errors.Is(err, ErrNoPasskey) {
		t.Errorf("bob without passkeys: %v", err)
	}
	if err := signIn("alice", authn); err != nil {
		t.Fatal(err)
	}
	// The counter goes back: a cloned authenticator.
	authn.SetCounter(0)
	if err := signIn("alice", authn); err == nil || !strings.Contains(err.Error(), "cloned") {
		t.Errorf("counter went back: %v", err)
	}
	if !strings.Contains(strings.Join(v.actions(t), "\n"), `"reason":"cloned"`) {
		t.Error("the clone is not in the audit log")
	}
	// reset-2fa removes every passkey.
	if _, err := v.s.ResetTOTP(t.Context(), "alice", console); err != nil {
		t.Fatal(err)
	}
	if n, _ := systemdb.New(v.sys).CountPasskeys(t.Context(), mustUserID(t, v, "alice")); n != 0 {
		t.Errorf("%d passkeys after reset-2fa", n)
	}
}

func mustUserID(t *testing.T, v *env, name string) string {
	t.Helper()
	u, err := systemdb.New(v.sys).GetUserByName(t.Context(), name)
	if err != nil {
		t.Fatal(err)
	}
	return u.ID
}
