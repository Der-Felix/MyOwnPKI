package auth

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/store/systemdb"
)

// signInFrom signs name in with the device cookie in c and returns the result.
func (v *env) signInFrom(t *testing.T, name string, c Client) (*LoginResult, error) {
	t.Helper()
	v.clk.Advance(totpPeriod * time.Second)
	res, err := v.s.LoginFrom(t.Context(), name, password, c)
	if err != nil {
		return nil, err
	}
	return v.s.SecondFactor(t.Context(), res.Token, v.code(name), c)
}

// lockOut has strangers lock name with wrong passwords from many addresses.
func (v *env) lockOut(t *testing.T, name string, from int) {
	t.Helper()
	for i := range LockAfter {
		if _, err := v.s.Login(t.Context(), name, "wrong password, long", fmt.Sprintf("203.0.113.%d", from+i)); !errors.Is(err, ErrInvalidLogin) {
			t.Fatalf("stranger %d: %v", i, err)
		}
	}
}

// TestDeviceCookieBeatsTheLockout: strangers who know the user name lock the
// account, the real user's known browser still gets in – only after password
// and second factor – and the lock stays for the strangers.
func TestDeviceCookieBeatsTheLockout(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.create(t, "alice", false)

	// The password alone gives no device cookie, a complete sign-in does.
	res, err := v.s.LoginFrom(t.Context(), "alice", password, Client{IP: ip})
	if err != nil || res.DeviceCookie != "" {
		t.Fatalf("after the password: %+v %v", res, err)
	}
	full, err := v.s.SecondFactor(t.Context(), res.Token, v.code("alice"), Client{IP: ip})
	if err != nil || full.DeviceCookie == "" || full.Token == res.Token {
		t.Fatalf("complete sign-in: %+v %v", full, err)
	}
	known := Client{IP: ip, Device: full.DeviceCookie}

	v.lockOut(t, "alice", 1)
	var locked *LockedError
	if _, lerr := v.signInFrom(t, "alice", Client{IP: ip}); !errors.As(lerr, &locked) {
		t.Fatalf("without the cookie while locked: %v", lerr)
	}
	again, err := v.signInFrom(t, "alice", known)
	if err != nil || again.DeviceCookie == "" || again.DeviceCookie == full.DeviceCookie {
		t.Fatalf("known device while locked: %+v %v", again, err)
	}
	// Renewed at every sign-in; the old value stays valid until it ends.
	if _, err := v.signInFrom(t, "alice", Client{IP: ip, Device: again.DeviceCookie}); err != nil {
		t.Errorf("renewed cookie: %v", err)
	}
	if _, err := v.s.Login(t.Context(), "alice", password, "198.51.100.7"); !errors.As(err, &locked) {
		t.Errorf("the strangers' lock must stay: %v", err)
	}
	// A wrong password from the known device doesn't count against the user.
	if _, err := v.s.LoginFrom(t.Context(), "alice", "wrong password, long", known); !errors.Is(err, ErrInvalidLogin) {
		t.Fatal(err)
	}
	if u := v.user(t, "alice"); u.FailedLogins != 0 {
		t.Errorf("device failure counted for the user: %d", u.FailedLogins)
	}
	if got := strings.Join(v.actions(t), "\n"); !strings.Contains(got, `"known_device":true`) {
		t.Errorf("audit lacks known_device:\n%s", got)
	}
}

// TestDeviceCookieLocksItself: ten failures with one cookie lock that cookie
// for 15 minutes; it then counts like an unknown browser.
func TestDeviceCookieLocksItself(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.create(t, "alice", false)
	full, err := v.signInFrom(t, "alice", Client{IP: ip})
	if err != nil {
		t.Fatal(err)
	}
	v.lockOut(t, "alice", 1)
	// Spread over addresses, so the strict (IP, user) counter doesn't stop it first.
	for i := range DeviceLockAfter {
		c := Client{IP: fmt.Sprintf("198.51.100.%d", i+1), Device: full.DeviceCookie}
		if _, lerr := v.s.LoginFrom(t.Context(), "alice", "wrong password, long", c); !errors.Is(lerr, ErrInvalidLogin) {
			t.Fatalf("device failure %d: %v", i+1, lerr)
		}
	}
	var locked *LockedError
	if _, err := v.signInFrom(t, "alice", Client{IP: "198.51.100.50", Device: full.DeviceCookie}); !errors.As(err, &locked) {
		t.Fatalf("locked cookie on a locked account: %v", err)
	}
	v.clk.Advance(DeviceLockFor)
	if _, err := v.signInFrom(t, "alice", Client{IP: "198.51.100.50", Device: full.DeviceCookie}); err != nil {
		t.Errorf("15 minutes later: %v", err)
	}
}

// TestDeviceCookieIsVoid: other users, changed bytes, the end of the year, a
// new password, a reset second factor and user unlock make a cookie worthless.
func TestDeviceCookieIsVoid(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.create(t, "alice", false)
	v.create(t, "bob", false)
	now := func() time.Time { return v.clk.Now() }
	cookie := func(t *testing.T) string {
		t.Helper()
		full, err := v.signInFrom(t, "alice", Client{IP: ip})
		if err != nil {
			t.Fatal(err)
		}
		return full.DeviceCookie
	}
	valid := func(name, value string) bool {
		return v.s.trustedDevice(Client{Device: value}, v.user(t, name), now()) != ""
	}

	c := cookie(t)
	if !valid("alice", c) || valid("bob", c) {
		t.Fatal("valid for alice only")
	}
	if b := []byte(c); true {
		b[len(b)-2] ^= 1
		if valid("alice", string(b)) {
			t.Error("changed cookie accepted")
		}
	}
	if valid("alice", strings.Replace(c, ".", ".x", 1)) || valid("alice", "") {
		t.Error("malformed cookie accepted")
	}
	v.clk.Advance(DeviceCookieTTL)
	if valid("alice", c) {
		t.Error("cookie valid after a year")
	}

	c = cookie(t)
	token := v.login(t, "alice")
	if err := v.s.ChangePassword(t.Context(), token, password, password+" and more", ip); err != nil {
		t.Fatal(err)
	}
	if valid("alice", c) {
		t.Error("valid after a password change")
	}
	if err := v.s.ChangePassword(t.Context(), v.loginWith(t, "alice", password+" and more"), password+" and more", password, ip); err != nil {
		t.Fatal(err)
	}

	c = cookie(t)
	enr, err := v.s.ResetTOTP(t.Context(), "alice", console)
	if err != nil {
		t.Fatal(err)
	}
	v.remember(t, enr)
	if valid("alice", c) {
		t.Error("valid after reset-2fa")
	}

	c = cookie(t)
	if err := v.s.Unlock(t.Context(), "alice", console); err != nil {
		t.Fatal(err)
	}
	if valid("alice", c) {
		t.Error("valid after user unlock")
	}
}

// loginWith is login with another password.
func (v *env) loginWith(t *testing.T, name, pw string) string {
	t.Helper()
	v.clk.Advance(totpPeriod * time.Second)
	res, err := v.s.Login(t.Context(), name, pw, ip)
	if err != nil {
		t.Fatal(err)
	}
	full, err := v.s.LoginTOTP(t.Context(), res.Token, v.code(name), ip)
	if err != nil {
		t.Fatal(err)
	}
	return full.Token
}

// TestPassiveRequestsDontKeepTheSession: status polling must not keep an
// open tab signed in forever.
func TestPassiveRequestsDontKeepTheSession(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.create(t, "alice", false)
	token := v.login(t, "alice")
	for range 2 {
		v.clk.Advance(10 * time.Minute)
		if _, err := v.s.AuthenticatePassive(t.Context(), token); err != nil {
			t.Fatalf("passive within the idle time: %v", err)
		}
	}
	v.clk.Advance(10 * time.Minute)
	if _, err := v.s.AuthenticatePassive(t.Context(), token); !errors.Is(err, ErrNoSession) {
		t.Errorf("30 minutes of polling only: %v", err)
	}
	token = v.login(t, "alice")
	v.clk.Advance(10 * time.Minute)
	sess, err := v.s.Authenticate(t.Context(), token)
	if err != nil || !sess.IdleExpiresAt().Equal(v.clk.Now().Add(IdleTimeout)) {
		t.Errorf("activity moves the idle end: %v %v", sess.IdleExpiresAt(), err)
	}
}

func TestSecondFactorTellsCodesApart(t *testing.T) {
	t.Parallel()
	for code, want := range map[string]bool{"123456": true, "123 456": true, "12345": false, "ABCDE-12345-FGHJK-MNPQR": false, "12345a": false} {
		if got := looksLikeTOTP(code); got != want {
			t.Errorf("%q: %v", code, got)
		}
	}
}

func (v *env) user(t *testing.T, name string) systemdb.User {
	t.Helper()
	u, err := systemdb.New(v.sys).GetUserByName(t.Context(), name)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
