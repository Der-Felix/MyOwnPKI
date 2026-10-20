package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/store/systemdb"
)

// Lockout (the persistent stage after the in-memory throttle): after
// LockAfter failures in a row the account is locked for LockFor, then the
// count starts again. Never for good – otherwise anybody could lock the
// admin out by typing wrong passwords (myownpki user unlock ends it early).
const (
	LockAfter = 10
	LockFor   = 15 * time.Minute
)

// Errors. ErrInvalidLogin is the same for an unknown user, a wrong password
// and a disabled account: the answer doesn't tell which names exist.
var (
	ErrInvalidLogin = errors.New("wrong user name or password")
	ErrInvalidCode  = errors.New("wrong or already used code")
	ErrLocked       = errors.New("too many failed attempts")
)

// LockedError carries how long the caller must wait (HTTP 429 Retry-After).
type LockedError struct{ RetryAfter time.Duration }

func (e *LockedError) Error() string {
	return fmt.Sprintf("%v – try again in %v", ErrLocked, e.RetryAfter.Round(time.Second))
}

func (e *LockedError) Unwrap() error { return ErrLocked }

// Service signs users in and manages their sessions and second factors.
type Service struct {
	System   *sql.DB // writer of system.db
	Audit    *sql.DB // writer of the instance audit log (<data>/audit.db)
	Key      *Key
	Hasher   *Hasher
	Throttle *Throttle
	Clock    clock.Clock
	Rand     io.Reader // nil = crypto/rand
	// Issuer is the name authenticator apps show; "" = "MyOwnPKI".
	Issuer string
	// Wake, if set, is called after an audit event was written to the outbox.
	Wake func()
	// Passkeys is the WebAuthn relying party; nil = no passkeys (TOTP only).
	Passkeys *Passkeys
}

// NewService returns a service with the production hasher and throttle.
func NewService(system, auditLog *sql.DB, key *Key, clk clock.Clock) *Service {
	return &Service{
		System: system, Audit: auditLog, Key: key, Clock: clk,
		Hasher: NewHasher(DefaultParams, MaxParallelHashes, HashWait), Throttle: NewThrottle(),
	}
}

func (s *Service) now() time.Time { return s.Clock.Now().UTC() }

func (s *Service) issuer() string {
	if s.Issuer != "" {
		return s.Issuer
	}
	return "MyOwnPKI"
}

// LoginResult is the outcome of a sign-in step.
type LoginResult struct {
	// Token is the new cookie value (SessionCookie). After the password it is
	// a pending session; after the second factor a full one.
	Token   string
	Session *Session
	// NeedsSecondFactor: the password was right, a TOTP code (or a recovery
	// code) must follow.
	NeedsSecondFactor bool
	// FirstTOTP: the authenticator was never confirmed – the setup from init
	// or reset-2fa is completed by this login.
	FirstTOTP bool
	// Factor is the second factor used: "totp" or "recovery_code".
	Factor string
	// RecoveryCodesLeft after a sign-in with a recovery code.
	RecoveryCodesLeft int
	// DeviceCookie is a new device cookie value after a complete sign-in
	// (DeviceCookie); renewed at every one.
	DeviceCookie string
	Warnings     []string
}

// Login checks user name and password and opens a pending session.
func (s *Service) Login(ctx context.Context, username, password, ip string) (*LoginResult, error) {
	return s.LoginFrom(ctx, username, password, Client{IP: ip})
}

// LoginFrom is Login with the client's device cookie: a known device is
// judged by its own counter instead of the user lockout.
func (s *Service) LoginFrom(ctx context.Context, username, password string, c Client) (*LoginResult, error) {
	now := s.now()
	ip := c.IP
	// The name lookup is cheap and comes first: unknown names share one
	// throttle counter per address and never get entries of their own.
	q := systemdb.New(s.System)
	u, found, err := s.userByName(ctx, q, username)
	if err != nil {
		return nil, err
	}
	var device string
	if found {
		device = s.trustedDevice(c, u, now)
	}
	if wait := s.wait(c, username, found, device, now); wait > 0 {
		var who *systemdb.User
		if found {
			who = &u
		}
		return nil, s.refuse(ctx, who, ip, "user.login", audit.ResultDenied, "throttled", &LockedError{RetryAfter: wait})
	}
	if !found {
		if derr := s.Hasher.VerifyDummy(ctx, password); derr != nil {
			return nil, derr
		}
		s.Throttle.Failure(ip, username, false, now)
		// The typed name is not logged: it may be a password typed into
		// the wrong field, and the audit log can't be cleaned.
		return nil, s.refuse(ctx, nil, ip, "user.login", audit.ResultFailure, "unknown user", ErrInvalidLogin)
	}
	if wait := lockedFor(u, now); wait > 0 && device == "" {
		// A hash like for an unknown name: the answer time must not tell that
		// this name exists and was locked by others (owner 2026-10-17).
		if derr := s.Hasher.VerifyDummy(ctx, password); derr != nil {
			return nil, derr
		}
		return nil, s.refuse(ctx, &u, ip, "user.login", audit.ResultDenied, "locked", &LockedError{RetryAfter: wait})
	}
	ok, rehash, err := s.Hasher.Verify(ctx, u.PasswordHash, password)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, s.failedFrom(ctx, u, c, device, "user.login", "wrong password", ErrInvalidLogin)
	}
	if u.DisabledAt.Valid {
		return nil, s.refuse(ctx, &u, ip, "user.login", audit.ResultDenied, "disabled", ErrInvalidLogin)
	}
	if rehash {
		if herr := s.rehash(ctx, q, u, password, now); herr != nil {
			return nil, herr
		}
	}
	token, err := s.insertSession(ctx, q, u.ID, statePassword, now)
	if err != nil {
		return nil, err
	}
	sess, err := q.GetSession(ctx, hashToken(token))
	if err != nil {
		return nil, err
	}
	return &LoginResult{Token: token, Session: sessionOf(sess, u, nil), NeedsSecondFactor: true, FirstTOTP: !u.TotpConfirmedAt.Valid}, nil
}

// LoginTOTP completes a sign-in with a TOTP code. The pending session is
// replaced by a new full one: a new session ID after every privilege change.
func (s *Service) LoginTOTP(ctx context.Context, pendingToken, code, ip string) (*LoginResult, error) {
	return s.loginTOTP(ctx, pendingToken, code, Client{IP: ip})
}

// LoginRecoveryCode completes a sign-in with a recovery code (lost phone).
// Each code works once.
func (s *Service) LoginRecoveryCode(ctx context.Context, pendingToken, code, ip string) (*LoginResult, error) {
	return s.loginRecoveryCode(ctx, pendingToken, code, Client{IP: ip})
}

// SecondFactor completes a sign-in with what the user typed: six digits are
// a TOTP code, anything else is tried as a recovery code. Failures of both
// count in the same throttle and lockout as wrong passwords.
func (s *Service) SecondFactor(ctx context.Context, pendingToken, code string, c Client) (*LoginResult, error) {
	if looksLikeTOTP(code) {
		return s.loginTOTP(ctx, pendingToken, code, c)
	}
	return s.loginRecoveryCode(ctx, pendingToken, code, c)
}

func (s *Service) loginTOTP(ctx context.Context, pendingToken, code string, c Client) (*LoginResult, error) {
	now := s.now()
	q := systemdb.New(s.System)
	row, u, device, err := s.pending(ctx, q, pendingToken, c, now)
	if err != nil {
		return nil, err
	}
	ok, first, err := s.useTOTP(ctx, q, u, code, now)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, s.failedFrom(ctx, u, c, device, "user.login", "wrong code", ErrInvalidCode)
	}
	res, err := s.completeLogin(ctx, u, row, c, device, now, map[string]any{"factor": "totp", "first_totp": first})
	if err != nil {
		return nil, err
	}
	res.FirstTOTP, res.Factor = first, "totp"
	return res, nil
}

func (s *Service) loginRecoveryCode(ctx context.Context, pendingToken, code string, c Client) (*LoginResult, error) {
	now := s.now()
	q := systemdb.New(s.System)
	row, u, device, err := s.pending(ctx, q, pendingToken, c, now)
	if err != nil {
		return nil, err
	}
	canon, ok := normalizeRecoveryCode(code)
	if ok {
		n, uerr := q.UseRecoveryCode(ctx, systemdb.UseRecoveryCodeParams{
			UsedAt: sql.NullString{String: formatTime(now), Valid: true}, UserID: u.ID, CodeHash: s.Key.recoveryHash(u.ID, canon),
		})
		if uerr != nil {
			return nil, uerr
		}
		ok = n == 1
	}
	if !ok {
		return nil, s.failedFrom(ctx, u, c, device, "user.login", "wrong recovery code", ErrInvalidCode)
	}
	left, err := q.CountUnusedRecoveryCodes(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	res, err := s.completeLogin(ctx, u, row, c, device, now, map[string]any{"factor": "recovery_code", "codes_left": left})
	if err != nil {
		return nil, err
	}
	res.RecoveryCodesLeft, res.Factor = int(left), "recovery_code"
	if left <= 3 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("only %d recovery code(s) left – create new ones", left))
	}
	return res, nil
}

// pending loads a pending session and its user and applies throttle, lock
// and disabled state before any code is checked. device is the counter key
// of a valid device cookie ("" = none).
func (s *Service) pending(ctx context.Context, q *systemdb.Queries, token string, c Client, now time.Time) (systemdb.Session, systemdb.User, string, error) {
	row, err := s.loadSession(ctx, q, token, statePassword, now)
	if err != nil {
		return row, systemdb.User{}, "", err
	}
	u, err := q.GetUser(ctx, row.UserID)
	if err != nil {
		return row, u, "", err
	}
	device := s.trustedDevice(c, u, now)
	if wait := s.wait(c, u.Username, true, device, now); wait > 0 {
		return row, u, "", s.refuse(ctx, &u, c.IP, "user.login", audit.ResultDenied, "throttled", &LockedError{RetryAfter: wait})
	}
	if wait := lockedFor(u, now); wait > 0 && device == "" {
		_ = q.DeleteSession(ctx, row.IDHash)
		return row, u, "", s.refuse(ctx, &u, c.IP, "user.login", audit.ResultDenied, "locked", &LockedError{RetryAfter: wait})
	}
	if u.DisabledAt.Valid {
		_ = q.DeleteSession(ctx, row.IDHash)
		return row, u, "", s.refuse(ctx, &u, c.IP, "user.login", audit.ResultDenied, "disabled", ErrInvalidLogin)
	}
	return row, u, device, nil
}

// completeLogin swaps the pending session for a full one, resets the
// failure count, audits the sign-in and issues a new device cookie. A lock
// that strangers caused stays when a known device signs in: they must not
// get their attempts back.
func (s *Service) completeLogin(ctx context.Context, u systemdb.User, pending systemdb.Session, c Client, device string, now time.Time, details map[string]any) (*LoginResult, error) {
	var token string
	keepLock := s.keepLock(u, device, now)
	err := s.inTx(ctx, func(q *systemdb.Queries, _ *sql.Tx) error {
		if err := q.DeleteSession(ctx, pending.IDHash); err != nil {
			return err
		}
		if err := q.SetLoginFailures(ctx, systemdb.SetLoginFailuresParams{FailedLogins: 0, LockedUntil: keepLock, UpdatedAt: formatTime(now), ID: u.ID}); err != nil {
			return err
		}
		var err error
		token, err = s.insertSession(ctx, q, u.ID, stateFull, now)
		return err
	})
	if err != nil {
		return nil, err
	}
	s.Throttle.Success(c.IP, u.Username)
	details["known_device"] = device != ""
	if aerr := s.direct(ctx, &u, c.IP, "user.login", audit.ResultSuccess, details); aerr != nil {
		// No sign-in without its audit entry.
		_ = systemdb.New(s.System).DeleteSession(ctx, hashToken(token))
		return nil, aerr
	}
	sess, err := s.Authenticate(ctx, token)
	if err != nil {
		return nil, err
	}
	cookie, err := s.Key.newDevice(s.Rand, u, now)
	if err != nil {
		return nil, err
	}
	return &LoginResult{Token: token, Session: sess, DeviceCookie: cookie}, nil
}

// keepLock is the lock to keep after a success: none, unless a known device
// signed in while strangers had locked the account.
func (s *Service) keepLock(u systemdb.User, device string, now time.Time) sql.NullString {
	if device != "" && lockedFor(u, now) > 0 {
		return u.LockedUntil
	}
	return sql.NullString{}
}

// StepUp confirms a sensitive action with a fresh TOTP code (security.md):
// the session's step-up time is set, authz accepts it for StepUpWindow.
func (s *Service) StepUp(ctx context.Context, token, code, ip string) (*Session, error) {
	return s.StepUpFrom(ctx, token, code, Client{IP: ip})
}

// StepUpFrom is StepUp with the client's device cookie.
func (s *Service) StepUpFrom(ctx context.Context, token, code string, c Client) (*Session, error) {
	now := s.now()
	sess, u, device, err := s.signedInFrom(ctx, token, c, "user.step_up", now)
	if err != nil {
		return nil, err
	}
	q := systemdb.New(s.System)
	ok, _, err := s.useTOTP(ctx, q, u, code, now)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, s.failedFrom(ctx, u, c, device, "user.step_up", "wrong code", ErrInvalidCode)
	}
	// Fail-closed: no step-up without its audit entry.
	if err := s.direct(ctx, &u, c.IP, "user.step_up", audit.ResultSuccess, nil); err != nil {
		return nil, fmt.Errorf("step-up refused – the audit entry can't be written: %w", err)
	}
	if err := q.SetStepUp(ctx, systemdb.SetStepUpParams{StepupAt: sql.NullString{String: formatTime(now), Valid: true}, IDHash: sess.idHash}); err != nil {
		return nil, err
	}
	if err := q.SetLoginFailures(ctx, systemdb.SetLoginFailuresParams{FailedLogins: 0, LockedUntil: s.keepLock(u, device, now), UpdatedAt: formatTime(now), ID: u.ID}); err != nil {
		return nil, err
	}
	s.Throttle.Success(c.IP, u.Username)
	return s.Authenticate(ctx, token)
}

// signedIn returns the session and user of token and applies throttle and
// lock – for actions that check a secret again (step-up, own changes).
func (s *Service) signedIn(ctx context.Context, token, ip, action string, now time.Time) (*Session, systemdb.User, error) {
	sess, u, _, err := s.signedInFrom(ctx, token, Client{IP: ip}, action, now)
	return sess, u, err
}

func (s *Service) signedInFrom(ctx context.Context, token string, c Client, action string, now time.Time) (*Session, systemdb.User, string, error) {
	sess, err := s.Authenticate(ctx, token)
	if err != nil {
		return nil, systemdb.User{}, "", err
	}
	u, err := systemdb.New(s.System).GetUser(ctx, sess.UserID)
	if err != nil {
		return nil, u, "", err
	}
	device := s.trustedDevice(c, u, now)
	if wait := s.wait(c, u.Username, true, device, now); wait > 0 {
		return nil, u, "", s.refuse(ctx, &u, c.IP, action, audit.ResultDenied, "throttled", &LockedError{RetryAfter: wait})
	}
	if wait := lockedFor(u, now); wait > 0 && device == "" {
		return nil, u, "", s.refuse(ctx, &u, c.IP, action, audit.ResultDenied, "locked", &LockedError{RetryAfter: wait})
	}
	return sess, u, device, nil
}

// wait is the throttle for an attempt: a known device only meets the strict
// (IP, user) counter.
func (s *Service) wait(c Client, username string, known bool, device string, now time.Time) time.Duration {
	if device != "" {
		return s.Throttle.WaitDevice(c.IP, username, now)
	}
	return s.Throttle.Wait(c.IP, username, known, now)
}

// failedFrom counts a failure. With a known device it counts against
// (IP, user) and the device cookie only, never against the user: strangers
// can't lock the real user out through it. Otherwise it is failed.
func (s *Service) failedFrom(ctx context.Context, u systemdb.User, c Client, device, action, reason string, cause error) error {
	if device == "" {
		return s.failed(ctx, u, c.IP, action, reason, cause)
	}
	s.Throttle.FailureDevice(c.IP, u.Username, device, s.now())
	if aerr := s.direct(ctx, &u, c.IP, action, audit.ResultFailure, map[string]any{"reason": reason, "known_device": true}); aerr != nil {
		return errors.Join(cause, aerr)
	}
	return cause
}

// Logout ends the session of token.
func (s *Service) Logout(ctx context.Context, token, ip string) error {
	q := systemdb.New(s.System)
	row, err := q.GetSession(ctx, hashToken(token))
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if derr := q.DeleteSession(ctx, row.IDHash); derr != nil {
		return derr
	}
	if row.State != stateFull {
		return nil
	}
	u, err := q.GetUser(ctx, row.UserID)
	if err != nil {
		return err
	}
	return s.direct(ctx, &u, ip, "user.logout", audit.ResultSuccess, nil)
}

// ChangePassword sets a new password; it needs the current one. Every other
// session of the user ends.
func (s *Service) ChangePassword(ctx context.Context, token, current, next, ip string) error {
	now := s.now()
	sess, u, err := s.checkCurrentPassword(ctx, token, current, ip, "user.password_change", now)
	if err != nil {
		return err
	}
	if perr := CheckPassword(u.Username, next); perr != nil {
		return perr
	}
	hash, err := s.Hasher.Hash(ctx, next)
	if err != nil {
		return err
	}
	return s.inTx(ctx, func(q *systemdb.Queries, tx *sql.Tx) error {
		if err := q.SetPassword(ctx, systemdb.SetPasswordParams{PasswordHash: hash, PasswordChangedAt: formatTime(now), UpdatedAt: formatTime(now), ID: u.ID}); err != nil {
			return err
		}
		n, err := q.DeleteOtherUserSessions(ctx, systemdb.DeleteOtherUserSessionsParams{UserID: u.ID, IDHash: sess.idHash})
		if err != nil {
			return err
		}
		return s.enqueue(ctx, tx, selfWho(u, ip), "user.password_change", u, map[string]any{"sessions_ended": n})
	})
}

// StartTOTPChange creates a new authenticator secret for the signed-in user;
// it needs the current password. The old secret stays valid until
// ConfirmTOTPChange.
func (s *Service) StartTOTPChange(ctx context.Context, token, currentPassword, ip string) (*Enrollment, error) {
	now := s.now()
	_, u, err := s.checkCurrentPassword(ctx, token, currentPassword, ip, "user.totp_change", now)
	if err != nil {
		return nil, err
	}
	secret, err := newTOTPSecret(s.Rand)
	if err != nil {
		return nil, err
	}
	defer clear(secret)
	sealed, err := s.Key.sealTOTP(s.Rand, u.ID, secret)
	if err != nil {
		return nil, err
	}
	if err := systemdb.New(s.System).SetTOTPPending(ctx, systemdb.SetTOTPPendingParams{TotpPending: sealed, UpdatedAt: formatTime(now), ID: u.ID}); err != nil {
		return nil, err
	}
	return newEnrollment(s.issuer(), u.ID, u.Username, secret), nil
}

// ConfirmTOTPChange switches to the new secret once a code from it works.
// Every other session of the user ends.
func (s *Service) ConfirmTOTPChange(ctx context.Context, token, code, ip string) error {
	now := s.now()
	sess, u, err := s.signedIn(ctx, token, ip, "user.totp_change", now)
	if err != nil {
		return err
	}
	if u.TotpPending == nil {
		return errors.New("no authenticator change was started")
	}
	secret, err := s.Key.openTOTP(u.ID, u.TotpPending)
	if err != nil {
		return err
	}
	defer clear(secret)
	step, ok := matchTOTP(secret, normalizeTOTPCode(code), now, 0)
	if !ok {
		return s.failed(ctx, u, ip, "user.totp_change", "wrong code", ErrInvalidCode)
	}
	return s.inTx(ctx, func(q *systemdb.Queries, tx *sql.Tx) error {
		n, err := q.ApplyTOTPPending(ctx, systemdb.ApplyTOTPPendingParams{
			TotpConfirmedAt: sql.NullString{String: formatTime(now), Valid: true}, TotpLastStep: step, UpdatedAt: formatTime(now), ID: u.ID,
		})
		if err != nil {
			return err
		}
		if n != 1 {
			return errors.New("the authenticator change was replaced meanwhile – start again")
		}
		ended, err := q.DeleteOtherUserSessions(ctx, systemdb.DeleteOtherUserSessionsParams{UserID: u.ID, IDHash: sess.idHash})
		if err != nil {
			return err
		}
		return s.enqueue(ctx, tx, selfWho(u, ip), "user.totp_change", u, map[string]any{"sessions_ended": ended})
	})
}

// NewRecoveryCodes replaces all recovery codes of the signed-in user; it
// needs the current password. Show the codes once.
func (s *Service) NewRecoveryCodes(ctx context.Context, token, currentPassword, ip string) ([]string, error) {
	now := s.now()
	_, u, err := s.checkCurrentPassword(ctx, token, currentPassword, ip, "user.recovery_codes_renew", now)
	if err != nil {
		return nil, err
	}
	var codes []string
	err = s.inTx(ctx, func(q *systemdb.Queries, tx *sql.Tx) error {
		var rerr error
		if codes, rerr = s.replaceRecoveryCodes(ctx, q, u.ID, now); rerr != nil {
			return rerr
		}
		return s.enqueue(ctx, tx, selfWho(u, ip), "user.recovery_codes_renew", u, nil)
	})
	return codes, err
}

// checkCurrentPassword: own changes need the current password (owner
// decision g); failures count like failed logins.
func (s *Service) checkCurrentPassword(ctx context.Context, token, password, ip, action string, now time.Time) (*Session, systemdb.User, error) {
	sess, u, err := s.signedIn(ctx, token, ip, action, now)
	if err != nil {
		return nil, u, err
	}
	ok, _, err := s.Hasher.Verify(ctx, u.PasswordHash, password)
	if err != nil {
		return nil, u, err
	}
	if !ok {
		return nil, u, s.failed(ctx, u, ip, action, "wrong password", ErrInvalidLogin)
	}
	return sess, u, nil
}

// useTOTP checks code and takes its time step in the same statement, so a
// code works once even when two requests race. first: the secret was never
// confirmed before.
func (s *Service) useTOTP(ctx context.Context, q *systemdb.Queries, u systemdb.User, code string, now time.Time) (ok, first bool, err error) {
	secret, err := s.Key.openTOTP(u.ID, u.TotpSecret)
	if err != nil {
		return false, false, err
	}
	defer clear(secret)
	step, ok := matchTOTP(secret, normalizeTOTPCode(code), now, u.TotpLastStep)
	if !ok {
		return false, false, nil
	}
	n, err := q.UseTOTPStep(ctx, systemdb.UseTOTPStepParams{
		TotpLastStep: step, TotpConfirmedAt: sql.NullString{String: formatTime(now), Valid: true}, UpdatedAt: formatTime(now),
		ID: u.ID, TotpLastStep_2: step,
	})
	if err != nil || n != 1 {
		return false, false, err
	}
	return true, !u.TotpConfirmedAt.Valid, nil
}

// failed counts a failure in the throttle and in the database, locks the
// account at LockAfter and audits.
func (s *Service) failed(ctx context.Context, u systemdb.User, ip, action, reason string, cause error) error {
	now := s.now()
	s.Throttle.Failure(ip, u.Username, true, now)
	locked := false
	err := s.inTx(ctx, func(q *systemdb.Queries, _ *sql.Tx) error {
		cur, err := q.GetUser(ctx, u.ID)
		if err != nil {
			return err
		}
		p := systemdb.SetLoginFailuresParams{FailedLogins: cur.FailedLogins + 1, LockedUntil: cur.LockedUntil, UpdatedAt: formatTime(now), ID: u.ID}
		if p.FailedLogins >= LockAfter {
			p.FailedLogins, locked = 0, true
			p.LockedUntil = sql.NullString{String: formatTime(now.Add(LockFor)), Valid: true}
		}
		return q.SetLoginFailures(ctx, p)
	})
	if err != nil {
		return errors.Join(cause, err)
	}
	if aerr := s.direct(ctx, &u, ip, action, audit.ResultFailure, map[string]any{"reason": reason}); aerr != nil {
		return errors.Join(cause, aerr)
	}
	if locked {
		if aerr := s.direct(ctx, &u, ip, "user.locked", audit.ResultSuccess, map[string]any{"for_minutes": int(LockFor.Minutes()), "after_failures": LockAfter}); aerr != nil {
			return errors.Join(cause, aerr)
		}
	}
	return cause
}

// refuse audits a refusal without counting it as a failure and returns cause.
func (s *Service) refuse(ctx context.Context, u *systemdb.User, ip, action string, result audit.Result, reason string, cause error) error {
	if err := s.direct(ctx, u, ip, action, result, map[string]any{"reason": reason}); err != nil {
		return errors.Join(cause, err)
	}
	return cause
}

func (s *Service) userByName(ctx context.Context, q *systemdb.Queries, name string) (systemdb.User, bool, error) {
	// An invalid name can't exist: it is an unknown user, not an error.
	if !validUsername(name) {
		return systemdb.User{}, false, nil
	}
	u, err := q.GetUserByName(ctx, name)
	if errors.Is(err, sql.ErrNoRows) {
		return u, false, nil
	}
	return u, err == nil, err
}

func (s *Service) rehash(ctx context.Context, q *systemdb.Queries, u systemdb.User, password string, now time.Time) error {
	hash, err := s.Hasher.Hash(ctx, password)
	if err != nil {
		return err
	}
	return q.RehashPassword(ctx, systemdb.RehashPasswordParams{PasswordHash: hash, UpdatedAt: formatTime(now), ID: u.ID})
}

func (s *Service) replaceRecoveryCodes(ctx context.Context, q *systemdb.Queries, userID string, now time.Time) ([]string, error) {
	codes, err := newRecoveryCodes(s.Rand, RecoveryCodeCount)
	if err != nil {
		return nil, err
	}
	return codes, s.storeRecoveryCodes(ctx, q, userID, codes, now)
}

// storeRecoveryCodes replaces the codes of userID with codes (hashed).
func (s *Service) storeRecoveryCodes(ctx context.Context, q *systemdb.Queries, userID string, codes []string, now time.Time) error {
	if err := q.DeleteRecoveryCodes(ctx, userID); err != nil {
		return err
	}
	for _, c := range codes {
		canon, ok := normalizeRecoveryCode(c)
		if !ok {
			return fmt.Errorf("malformed recovery code")
		}
		if err := q.InsertRecoveryCode(ctx, systemdb.InsertRecoveryCodeParams{UserID: userID, CodeHash: s.Key.recoveryHash(userID, canon), CreatedAt: formatTime(now)}); err != nil {
			return err
		}
	}
	return nil
}

func lockedFor(u systemdb.User, now time.Time) time.Duration {
	if !u.LockedUntil.Valid {
		return 0
	}
	return max(parseTime(u.LockedUntil.String).Sub(now), 0)
}

func (s *Service) inTx(ctx context.Context, fn func(q *systemdb.Queries, tx *sql.Tx) error) (err error) {
	tx, err := s.System.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if err = fn(systemdb.New(tx), tx); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	if s.Wake != nil {
		s.Wake()
	}
	return nil
}

// direct appends an event without a business change (sign-in, refusals) to
// the instance audit log. u nil: unknown user – the typed name is not kept.
func (s *Service) direct(ctx context.Context, u *systemdb.User, ip, action string, result audit.Result, details map[string]any) error {
	actor := audit.Actor{Type: audit.ActorUser, Name: "unknown user"}
	target := audit.Target{Type: "user"}
	if u != nil {
		actor = audit.Actor{Type: audit.ActorUser, ID: u.ID, Name: u.Username}
		target.ID = u.ID
	}
	_, _, err := audit.Append(ctx, s.Audit, store.InstanceScope, audit.Entry{
		Time: s.now(), Actor: actor, Action: action, Target: target, Result: result, SourceIP: ip, Details: details,
	}, "")
	return err
}
