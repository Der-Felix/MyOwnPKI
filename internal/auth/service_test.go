package auth

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
)

var t0 = time.Date(2026, 10, 15, 8, 0, 0, 0, time.UTC)

const (
	ip       = "192.0.2.10"
	password = "correct horse battery staple"
)

var console = keys.Who{Actor: audit.Actor{Type: audit.ActorUser, Name: "console"}, Principal: authz.Console()}

type env struct {
	s        *Service
	clk      *clock.Fake
	sys, ia  *sql.DB
	sysPath  string
	deliver  func()
	secrets  map[string][]byte // TOTP secrets by user name, decoded from the enrollment
	recovery map[string][]string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	l := store.Layout{DataDir: t.TempDir()}
	clk := clock.NewFake(t0)
	if _, err := store.Migrate(t.Context(), l, store.DefaultTenant, clk.Now); err != nil {
		t.Fatal(err)
	}
	open := func(path string) *sql.DB {
		db, err := store.Open(t.Context(), path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db.Write
	}
	v := &env{clk: clk, sysPath: l.SystemDB(), secrets: map[string][]byte{}, recovery: map[string][]string{}}
	v.sys, v.ia = open(l.SystemDB()), open(l.InstanceAuditDB())
	v.s = NewService(v.sys, v.ia, testKey(t), clk)
	v.s.Hasher = NewHasher(fastParams, 4, time.Second)
	d := &audit.Deliverer{
		Routes: []audit.Route{{Source: "system", From: v.sys, To: v.ia, Scope: store.InstanceScope}},
		Clock:  clk, Log: slog.New(slog.DiscardHandler),
	}
	v.deliver = func() {
		if _, err := d.DeliverPending(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	return v
}

// create makes a user as init would: by the console, roles in the default tenant.
func (v *env) create(t *testing.T, name string, admin bool, roles ...authz.Role) string {
	t.Helper()
	var bs []authz.Binding
	for _, r := range roles {
		bs = append(bs, authz.Binding{Tenant: store.DefaultTenant, Role: r})
	}
	enr, err := v.s.CreateUser(t.Context(), NewUserRequest{Username: name, Password: password, InstanceAdmin: admin, Roles: bs, Who: console})
	if err != nil {
		t.Fatal(err)
	}
	v.remember(t, enr)
	return enr.UserID
}

func (v *env) remember(t *testing.T, enr *Enrollment) {
	t.Helper()
	secret, err := totpBase32.DecodeString(strings.ReplaceAll(enr.Secret, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	v.secrets[enr.Username] = secret
	if enr.RecoveryCodes != nil {
		v.recovery[enr.Username] = enr.RecoveryCodes
	}
}

// code returns the TOTP code of name at the fake clock's time.
func (v *env) code(name string) string {
	return hotp(v.secrets[name], counter(v.clk.Now()), totpDigits)
}

// login signs name in fully and returns the session token. Each call moves
// the clock to the next TOTP step, so codes are never reused.
func (v *env) login(t *testing.T, name string) string {
	t.Helper()
	v.clk.Advance(totpPeriod * time.Second)
	res, err := v.s.Login(t.Context(), name, password, ip)
	if err != nil {
		t.Fatalf("login %s: %v", name, err)
	}
	full, err := v.s.LoginTOTP(t.Context(), res.Token, v.code(name), ip)
	if err != nil {
		t.Fatalf("totp %s: %v", name, err)
	}
	return full.Token
}

// actions lists "action/result reason" of the instance audit log.
func (v *env) actions(t *testing.T) []string {
	t.Helper()
	v.deliver()
	rows, err := v.ia.QueryContext(t.Context(), `SELECT action, result, actor_name, details_json FROM audit_entries ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var a, r, actor, d string
		if err := rows.Scan(&a, &r, &actor, &d); err != nil {
			t.Fatal(err)
		}
		out = append(out, a+"/"+r+" "+actor+" "+d)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestLoginWithTOTP(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.create(t, "alice", false, authz.Operator)

	res, err := v.s.Login(t.Context(), "alice", password, ip)
	if err != nil || !res.NeedsSecondFactor || !res.FirstTOTP {
		t.Fatalf("password step: %+v %v", res, err)
	}
	// A pending session is not signed in.
	if _, aerr := v.s.Authenticate(t.Context(), res.Token); !errors.Is(aerr, ErrNoSession) {
		t.Errorf("pending session authenticates: %v", aerr)
	}
	if _, lerr := v.s.LoginTOTP(t.Context(), res.Token, "000000", ip); !errors.Is(lerr, ErrInvalidCode) {
		t.Errorf("wrong code: %v", lerr)
	}
	full, err := v.s.LoginTOTP(t.Context(), res.Token, v.code("alice"), ip)
	if err != nil || !full.FirstTOTP {
		t.Fatalf("totp: %+v %v", full, err)
	}
	if full.Token == res.Token {
		t.Error("the session ID was not rotated after the second factor")
	}
	if _, perr := v.s.LoginTOTP(t.Context(), res.Token, v.code("alice"), ip); !errors.Is(perr, ErrNoSession) {
		t.Errorf("the pending session lives on: %v", perr)
	}
	sess, err := v.s.Authenticate(t.Context(), full.Token)
	if err != nil {
		t.Fatal(err)
	}
	p := sess.Principal
	if p.Username != "alice" || p.InstanceAdmin || len(p.Bindings) != 1 || p.Bindings[0].Role != authz.Operator || !p.StepUpAt.Equal(t0) {
		t.Errorf("principal %+v", p)
	}

	// The same code doesn't work twice (step-up right after the login).
	if _, err := v.s.StepUp(t.Context(), full.Token, v.code("alice"), ip); !errors.Is(err, ErrInvalidCode) {
		t.Errorf("replayed code: %v", err)
	}
	if err := v.s.Logout(t.Context(), full.Token, ip); err != nil {
		t.Fatal(err)
	}
	if _, err := v.s.Authenticate(t.Context(), full.Token); !errors.Is(err, ErrNoSession) {
		t.Errorf("after logout: %v", err)
	}
	got := strings.Join(v.actions(t), "\n")
	for _, want := range []string{"user.create/success console", "user.login/failure alice {\"reason\":\"wrong code\"}", "user.login/success alice", "\"first_totp\":true", "user.logout/success alice"} {
		if !strings.Contains(got, want) {
			t.Errorf("audit lacks %q:\n%s", want, got)
		}
	}
}

// TestUnknownUser: same answer as a wrong password, a full hash run, and the
// typed name never reaches the audit log.
func TestUnknownUser(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.create(t, "alice", false)
	_, errUnknown := v.s.Login(t.Context(), "Secret-Typed-Into-User-Field", password, ip)
	_, errWrong := v.s.Login(t.Context(), "alice", "wrong password, long", ip)
	if !errors.Is(errUnknown, ErrInvalidLogin) || errUnknown.Error() != errWrong.Error() {
		t.Errorf("unknown %v, wrong %v", errUnknown, errWrong)
	}
	got := strings.Join(v.actions(t), "\n")
	if strings.Contains(strings.ToLower(got), "secret-typed") || !strings.Contains(got, "user.login/failure unknown user {\"reason\":\"unknown user\"}") {
		t.Errorf("audit:\n%s", got)
	}
}

// TestLockout: ten failures in a row lock the account for 15 minutes (also
// for the right password); myownpki user unlock ends it early.
func TestLockout(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.create(t, "alice", false)
	for i := range LockAfter {
		// Different addresses: the per-(IP, user) throttle doesn't stop it first.
		if _, err := v.s.Login(t.Context(), "alice", "wrong password, long", fmt.Sprintf("192.0.2.%d", 100+i)); !errors.Is(err, ErrInvalidLogin) {
			t.Fatalf("attempt %d: %v", i+1, err)
		}
	}
	var locked *LockedError
	if _, err := v.s.Login(t.Context(), "alice", password, "198.51.100.1"); !errors.As(err, &locked) || locked.RetryAfter != LockFor {
		t.Fatalf("right password while locked: %v", err)
	}
	v.clk.Advance(LockFor)
	if _, err := v.s.Login(t.Context(), "alice", password, "198.51.100.1"); err != nil {
		t.Errorf("after the lock: %v", err)
	}
	for i := range LockAfter {
		_, _ = v.s.Login(t.Context(), "alice", "wrong password, long", fmt.Sprintf("192.0.2.%d", 120+i))
	}
	if err := v.s.Unlock(t.Context(), "alice", console); err != nil {
		t.Fatal(err)
	}
	if _, err := v.s.Login(t.Context(), "alice", password, "198.51.100.1"); err != nil {
		t.Errorf("after unlock: %v", err)
	}
	got := strings.Join(v.actions(t), "\n")
	if strings.Count(got, "user.locked/success") != 2 || !strings.Contains(got, `user.login/denied alice {"reason":"locked"}`) ||
		!strings.Contains(got, "user.unlock/success console") {
		t.Errorf("audit:\n%s", got)
	}
}

// TestThrottleComesBeforeTheHash: a throttled attempt is refused without a
// hash run – with every hash slot taken it is still answered at once.
func TestThrottleComesBeforeTheHash(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.create(t, "alice", false)
	for range strictRule.free {
		_, _ = v.s.Login(t.Context(), "alice", "wrong password, long", ip)
	}
	v.s.Hasher = NewHasher(fastParams, 1, time.Hour)
	if err := v.s.Hasher.acquire(t.Context()); err != nil {
		t.Fatal(err)
	}
	var locked *LockedError
	if _, err := v.s.Login(t.Context(), "alice", password, ip); !errors.As(err, &locked) {
		t.Errorf("throttled login: %v", err)
	}
}

func TestRecoveryCodeLogin(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.create(t, "alice", false)
	code := v.recovery["alice"][3]
	typed := strings.ToLower(strings.ReplaceAll(code, "-", " "))
	res, _ := v.s.Login(t.Context(), "alice", password, ip)
	full, err := v.s.LoginRecoveryCode(t.Context(), res.Token, typed, ip)
	if err != nil || full.RecoveryCodesLeft != 9 {
		t.Fatalf("recovery login: %+v %v", full, err)
	}
	res, _ = v.s.Login(t.Context(), "alice", password, ip)
	if _, err := v.s.LoginRecoveryCode(t.Context(), res.Token, code, ip); !errors.Is(err, ErrInvalidCode) {
		t.Errorf("code used twice: %v", err)
	}
	if !strings.Contains(strings.Join(v.actions(t), "\n"), `{"codes_left":9,"factor":"recovery_code"}`) {
		t.Error("recovery code use not audited")
	}
}

// TestSessionTimeouts: pending 5 minutes, idle 30 minutes, absolute 12 hours.
func TestSessionTimeouts(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.create(t, "alice", false)

	res, _ := v.s.Login(t.Context(), "alice", password, ip)
	v.clk.Advance(PendingTTL)
	if _, err := v.s.LoginTOTP(t.Context(), res.Token, v.code("alice"), ip); !errors.Is(err, ErrNoSession) {
		t.Errorf("second factor after 5 minutes: %v", err)
	}

	token := v.login(t, "alice")
	v.clk.Advance(IdleTimeout - time.Minute)
	if _, err := v.s.Authenticate(t.Context(), token); err != nil {
		t.Fatalf("29 minutes idle: %v", err)
	}
	v.clk.Advance(IdleTimeout - time.Minute) // the last use above counts
	if _, err := v.s.Authenticate(t.Context(), token); err != nil {
		t.Fatalf("activity keeps the session: %v", err)
	}
	v.clk.Advance(IdleTimeout)
	if _, err := v.s.Authenticate(t.Context(), token); !errors.Is(err, ErrNoSession) {
		t.Errorf("30 minutes idle: %v", err)
	}

	token = v.login(t, "alice")
	for range AbsoluteTimeout / (20 * time.Minute) {
		v.clk.Advance(20 * time.Minute)
		if _, err := v.s.Authenticate(t.Context(), token); err != nil {
			break
		}
	}
	if _, err := v.s.Authenticate(t.Context(), token); !errors.Is(err, ErrNoSession) {
		t.Errorf("after 12 hours: %v", err)
	}
	if n, err := v.s.PruneSessions(t.Context()); err != nil || n < 0 {
		t.Errorf("prune: %d %v", n, err)
	}
}

func TestStepUp(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.create(t, "alice", false, authz.Admin)
	token := v.login(t, "alice")
	res := authz.Resource{Tenant: store.DefaultTenant, CA: "issuing"}
	v.clk.Advance(authz.StepUpWindow + time.Second)
	sess, _ := v.s.Authenticate(t.Context(), token)
	if err := sess.Principal.Check(authz.RevokeCert, res, v.clk.Now()); !errors.Is(err, authz.ErrStepUpRequired) {
		t.Errorf("old step-up: %v", err)
	}
	sess, err := v.s.StepUp(t.Context(), token, v.code("alice"), ip)
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Principal.Check(authz.RevokeCert, res, v.clk.Now()); err != nil {
		t.Errorf("after step-up: %v", err)
	}
}

func TestOwnChangesNeedTheCurrentPassword(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.create(t, "alice", false)
	other := v.login(t, "alice")
	token := v.login(t, "alice")

	if err := v.s.ChangePassword(t.Context(), token, "wrong password, long", "a new long passphrase", ip); !errors.Is(err, ErrInvalidLogin) {
		t.Errorf("wrong current password: %v", err)
	}
	if err := v.s.ChangePassword(t.Context(), token, password, "short", ip); !errors.Is(err, ErrWeakPassword) {
		t.Errorf("weak new password: %v", err)
	}
	if err := v.s.ChangePassword(t.Context(), token, password, "a new long passphrase", ip); err != nil {
		t.Fatal(err)
	}
	if _, err := v.s.Authenticate(t.Context(), other); !errors.Is(err, ErrNoSession) {
		t.Errorf("other session survives a password change: %v", err)
	}
	if _, err := v.s.Authenticate(t.Context(), token); err != nil {
		t.Errorf("own session ended: %v", err)
	}
	if _, err := v.s.Login(t.Context(), "alice", "a new long passphrase", ip); err != nil {
		t.Errorf("new password: %v", err)
	}

	// New authenticator: the old one works until the new one is confirmed.
	if _, err := v.s.StartTOTPChange(t.Context(), token, password, ip); !errors.Is(err, ErrInvalidLogin) {
		t.Errorf("TOTP change with the old password: %v", err)
	}
	enr, err := v.s.StartTOTPChange(t.Context(), token, "a new long passphrase", ip)
	if err != nil {
		t.Fatal(err)
	}
	oldSecret := v.secrets["alice"]
	v.remember(t, enr)
	v.clk.Advance(totpPeriod * time.Second)
	if cerr := v.s.ConfirmTOTPChange(t.Context(), token, hotp(oldSecret, counter(v.clk.Now()), 6), ip); !errors.Is(cerr, ErrInvalidCode) {
		t.Errorf("confirmed with the old authenticator: %v", cerr)
	}
	if cerr := v.s.ConfirmTOTPChange(t.Context(), token, v.code("alice"), ip); cerr != nil {
		t.Fatal(cerr)
	}
	v.clk.Advance(totpPeriod * time.Second)
	if _, serr := v.s.StepUp(t.Context(), token, hotp(oldSecret, counter(v.clk.Now()), 6), ip); !errors.Is(serr, ErrInvalidCode) {
		t.Errorf("old authenticator after the change: %v", serr)
	}

	codes, err := v.s.NewRecoveryCodes(t.Context(), token, "a new long passphrase", ip)
	if err != nil || len(codes) != RecoveryCodeCount || codes[0] == v.recovery["alice"][0] {
		t.Errorf("new recovery codes: %v %v", codes, err)
	}
	got := strings.Join(v.actions(t), "\n")
	for _, want := range []string{"user.password_change/success alice", "user.totp_change/success alice", "user.recovery_codes_renew/success alice"} {
		if !strings.Contains(got, want) {
			t.Errorf("audit lacks %q", want)
		}
	}
}

// TestUserManagement: instance admins with step-up only; role changes and
// disabling end the user's sessions.
func TestUserManagement(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	adminID := v.create(t, "root-admin", true)
	bobID := v.create(t, "bob", false, authz.Viewer)
	v.create(t, "tenant-admin", false, authz.Admin)

	who := func(name string) keys.Who {
		sess, err := v.s.Authenticate(t.Context(), v.login(t, name))
		if err != nil {
			t.Fatal(err)
		}
		return keys.Who{Actor: audit.Actor{Type: audit.ActorUser, ID: sess.UserID, Name: name}, SourceIP: ip, Principal: sess.Principal}
	}
	req := NewUserRequest{Username: "carol", Password: password, Roles: []authz.Binding{{Tenant: store.DefaultTenant, Role: authz.Viewer}}}
	req.Who = who("tenant-admin")
	if _, err := v.s.CreateUser(t.Context(), req); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("tenant admin creates a user: %v", err)
	}
	admin := who("root-admin")
	v.clk.Advance(authz.StepUpWindow + time.Second)
	req.Who = admin
	if _, err := v.s.CreateUser(t.Context(), req); !errors.Is(err, authz.ErrStepUpRequired) {
		t.Errorf("without a fresh second factor: %v", err)
	}
	admin.Principal.StepUpAt = v.clk.Now()
	req.Who = admin
	if _, err := v.s.CreateUser(t.Context(), req); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]NewUserRequest{
		"taken":      {Username: "carol", Password: password},
		"upper case": {Username: "Carol", Password: password},
		"weak":       {Username: "dave", Password: "passwordpassword"},
		"no tenant":  {Username: "dave", Password: password, Roles: []authz.Binding{{Tenant: "nope", Role: authz.Viewer}}},
		"no role":    {Username: "dave", Password: password, Roles: []authz.Binding{{Tenant: store.DefaultTenant, Role: "root"}}},
	} {
		bad.Who = admin
		if _, err := v.s.CreateUser(t.Context(), bad); !errors.Is(err, ErrRefused) {
			t.Errorf("%s: %v", name, err)
		}
	}

	bobToken := v.login(t, "bob")
	if err := v.s.SetRole(t.Context(), bobID, authz.Binding{Tenant: store.DefaultTenant, CA: "issuing", Role: authz.Operator}, admin); err != nil {
		t.Fatal(err)
	}
	if _, err := v.s.Authenticate(t.Context(), bobToken); !errors.Is(err, ErrNoSession) {
		t.Errorf("session survives a role change: %v", err)
	}
	sess, _ := v.s.Authenticate(t.Context(), v.login(t, "bob"))
	if len(sess.Principal.Bindings) != 2 {
		t.Errorf("bindings %+v", sess.Principal.Bindings)
	}
	if err := v.s.RemoveRole(t.Context(), bobID, store.DefaultTenant, "issuing", admin); err != nil {
		t.Fatal(err)
	}
	if err := v.s.DisableUser(t.Context(), adminID, admin); !errors.Is(err, ErrRefused) {
		t.Errorf("disable yourself: %v", err)
	}
	bobToken = v.login(t, "bob")
	if err := v.s.DisableUser(t.Context(), bobID, admin); err != nil {
		t.Fatal(err)
	}
	if _, err := v.s.Authenticate(t.Context(), bobToken); !errors.Is(err, ErrNoSession) {
		t.Errorf("disabled user's session: %v", err)
	}
	if _, err := v.s.Login(t.Context(), "bob", password, ip); !errors.Is(err, ErrInvalidLogin) {
		t.Errorf("disabled user logs in: %v", err)
	}
	if _, err := v.sys.ExecContext(t.Context(), `DELETE FROM users WHERE id = ?`, bobID); err == nil {
		t.Error("a user was deleted")
	}
	got := strings.Join(v.actions(t), "\n")
	for _, want := range []string{"user.create/denied tenant-admin", "user.create/success root-admin", "user.role_set/success root-admin",
		"user.role_remove/success root-admin", "user.disable/success root-admin", `user.login/denied bob {"reason":"disabled"}`} {
		if !strings.Contains(got, want) {
			t.Errorf("audit lacks %q", want)
		}
	}
}

// TestResetTOTPAfterLostAuthKey: with another auth key no TOTP secret opens;
// reset-2fa gives a new secret and new recovery codes, and only that secret
// completes the next login.
func TestResetTOTPAfterLostAuthKey(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.create(t, "alice", true)
	token := v.login(t, "alice")
	oldRecovery := v.recovery["alice"]

	v.s.Key = testKey(t) // auth.key lost, a new one created
	res, _ := v.s.Login(t.Context(), "alice", password, ip)
	if _, err := v.s.LoginTOTP(t.Context(), res.Token, v.code("alice"), ip); !errors.Is(err, ErrUnreadableSecret) {
		t.Fatalf("old secret with a new key: %v", err)
	}
	enr, err := v.s.ResetTOTP(t.Context(), "alice", console)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.s.Authenticate(t.Context(), token); !errors.Is(err, ErrNoSession) {
		t.Errorf("session survives reset-2fa: %v", err)
	}
	oldSecret := v.secrets["alice"]
	v.remember(t, enr)
	res, _ = v.s.Login(t.Context(), "alice", password, ip)
	if !res.FirstTOTP {
		t.Error("the new secret must be confirmed at the next login")
	}
	if _, err := v.s.LoginTOTP(t.Context(), res.Token, hotp(oldSecret, counter(v.clk.Now()), 6), ip); !errors.Is(err, ErrInvalidCode) {
		t.Errorf("old secret after reset: %v", err)
	}
	if _, err := v.s.LoginTOTP(t.Context(), res.Token, v.code("alice"), ip); err != nil {
		t.Errorf("new secret: %v", err)
	}
	res, _ = v.s.Login(t.Context(), "alice", password, ip)
	if _, err := v.s.LoginRecoveryCode(t.Context(), res.Token, oldRecovery[0], ip); !errors.Is(err, ErrInvalidCode) {
		t.Errorf("old recovery code after reset: %v", err)
	}
	if !strings.Contains(strings.Join(v.actions(t), "\n"), "user.totp_reset/success console") {
		t.Error("reset not audited")
	}
}

// TestNoSecretInTheDatabase: neither the password, the TOTP secret, a
// recovery code nor a session token is stored in the clear.
func TestNoSecretInTheDatabase(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.create(t, "alice", false)
	token := v.login(t, "alice")
	if _, err := v.sys.ExecContext(t.Context(), `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(v.sysPath)
	if err != nil {
		t.Fatal(err)
	}
	secret := v.secrets["alice"]
	needles := map[string][]byte{
		"password": []byte(password), "token": []byte(token), "TOTP secret": secret,
		"TOTP secret (base32)": []byte(totpBase32.EncodeToString(secret)),
	}
	for _, c := range v.recovery["alice"] {
		canon, _ := normalizeRecoveryCode(c)
		needles["recovery code "+c] = []byte(canon)
		needles["recovery code with dashes "+c] = []byte(c)
	}
	for name, n := range needles {
		if bytes.Contains(data, n) {
			t.Errorf("%s in system.db", name)
		}
	}
}

// TestLastAdminsStay: the last active instance admin and the last active
// tenant admin can't be disabled or lose the role – also not by another
// admin (owner 2026-10-15).
func TestLastAdminsStay(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	rootID := v.create(t, "root-admin", true)             // the only instance admin
	pkiID := v.create(t, "pki-admin", false, authz.Admin) // the only tenant admin
	otherID := v.create(t, "other-admin", true, authz.Admin)

	// With a second admin of each kind every change is allowed – first take
	// the second ones away.
	if err := v.s.SetRole(t.Context(), otherID, authz.Binding{Tenant: store.DefaultTenant, Role: authz.Viewer}, console); err != nil {
		t.Fatalf("downgrade while another admin exists: %v", err)
	}
	if err := v.s.DisableUser(t.Context(), otherID, console); err != nil {
		t.Fatalf("disable while another instance admin exists: %v", err)
	}

	for name, err := range map[string]error{
		"disable the last instance admin":   v.s.DisableUser(t.Context(), rootID, console),
		"disable the last tenant admin":     v.s.DisableUser(t.Context(), pkiID, console),
		"remove the last tenant admin role": v.s.RemoveRole(t.Context(), pkiID, store.DefaultTenant, "", console),
		"downgrade the last tenant admin":   v.s.SetRole(t.Context(), pkiID, authz.Binding{Tenant: store.DefaultTenant, Role: authz.Operator}, console),
	} {
		if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "last active") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A CA-scoped role of the last tenant admin may change; it doesn't keep the tenant running.
	if err := v.s.SetRole(t.Context(), pkiID, authz.Binding{Tenant: store.DefaultTenant, CA: "issuing", Role: authz.Viewer}, console); err != nil {
		t.Errorf("CA role of the last tenant admin: %v", err)
	}
	// Once there is another admin, the change works.
	if err := v.s.SetRole(t.Context(), rootID, authz.Binding{Tenant: store.DefaultTenant, Role: authz.Admin}, console); err != nil {
		t.Fatal(err)
	}
	if err := v.s.RemoveRole(t.Context(), pkiID, store.DefaultTenant, "", console); err != nil {
		t.Errorf("remove with another tenant admin: %v", err)
	}
}

// TestSignInIsFailClosed: when the audit entry can't be written, there is no
// session and no step-up (owner 2026-10-16).
func TestSignInIsFailClosed(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.create(t, "alice", false, authz.Admin)
	token := v.login(t, "alice")
	ro, err := store.OpenReadOnly(t.Context(), store.Layout{DataDir: filepath.Dir(v.sysPath)}.InstanceAuditDB())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ro.Close() })
	v.s.Audit = ro.Read

	v.clk.Advance(totpPeriod * time.Second)
	res, err := v.s.Login(t.Context(), "alice", password, ip)
	if err != nil {
		t.Fatal(err)
	}
	if _, lerr := v.s.LoginTOTP(t.Context(), res.Token, v.code("alice"), ip); lerr == nil {
		t.Error("signed in without an audit entry")
	}
	var full int
	if cerr := v.sys.QueryRowContext(t.Context(), `SELECT count(*) FROM sessions WHERE state = 'full'`).Scan(&full); cerr != nil || full != 1 {
		t.Errorf("%d full sessions (only the one from before), %v", full, cerr)
	}
	v.clk.Advance(authz.StepUpWindow + totpPeriod*time.Second)
	if _, serr := v.s.StepUp(t.Context(), token, v.code("alice"), ip); serr == nil {
		t.Error("step-up without an audit entry")
	}
	sess, err := v.s.Authenticate(t.Context(), token)
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Principal.Check(authz.ManageCA, authz.Resource{Tenant: store.DefaultTenant}, v.clk.Now()); !errors.Is(err, authz.ErrStepUpRequired) {
		t.Errorf("step-up took effect without its audit entry: %v", err)
	}
}
