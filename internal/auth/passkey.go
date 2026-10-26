package auth

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/ids"
	"github.com/Der-Felix/MyOwnPKI/internal/store/systemdb"
)

// Passkeys (WebAuthn, PHASE1 step 17) are a second factor after the
// password and work for step-up. A passkey is bound to the RP ID – the host
// name users open the admin UI with (auth.passkey_origin) – and needs user
// verification, so the device asks for its PIN or fingerprint. The
// challenge of a ceremony lives in memory, bound to the session that
// started it.

// Limits.
const (
	MaxPasskeys    = 10
	ceremonyTTL    = 5 * time.Minute
	maxCeremonies  = 10_000
	maxPasskeyBody = 64 << 10
)

// Errors of the passkey ceremonies.
var (
	ErrPasskeysOff     = errors.New("passkeys are not set up on this server (auth.passkey_origin)")
	ErrNoPasskey       = errors.New("no passkey is registered for this user")
	ErrNoCeremony      = errors.New("no passkey request is open for this session – start again")
	ErrTooManyPasskeys = fmt.Errorf("at most %d passkeys per user – remove one first", MaxPasskeys)
)

// Passkeys holds the WebAuthn relying party and the open ceremonies.
type Passkeys struct {
	wa *webauthn.WebAuthn
	// RPID is the host name passkeys are bound to.
	RPID string

	mu         sync.Mutex
	ceremonies map[string]ceremony
}

type ceremony struct {
	data    webauthn.SessionData
	userID  string
	expires time.Time
}

// Ceremony kinds; a key is the kind and the hash of the session cookie.
const (
	ceremonyRegister = "register"
	ceremonyLogin    = "login"
	ceremonyStepUp   = "step_up"
)

// NewPasskeys sets up the relying party for rpID and origin (both from
// config.PasskeyRPID and auth.passkey_origin).
func NewPasskeys(rpID, origin string) (*Passkeys, error) {
	wa, err := webauthn.New(&webauthn.Config{
		RPID: rpID, RPDisplayName: "MyOwnPKI", RPOrigins: []string{origin},
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationRequired,
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("passkeys: %w", err)
	}
	return &Passkeys{wa: wa, RPID: rpID, ceremonies: map[string]ceremony{}}, nil
}

func (p *Passkeys) put(kind, token string, c ceremony) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.ceremonies) >= maxCeremonies {
		for k, v := range p.ceremonies {
			if !c.expires.Add(-ceremonyTTL).Before(v.expires) {
				delete(p.ceremonies, k)
			}
		}
		if len(p.ceremonies) >= maxCeremonies {
			return errors.New("too many passkey requests at once – try again in a few minutes")
		}
	}
	p.ceremonies[kind+":"+hashToken(token)] = c
	return nil
}

// take removes and returns the ceremony of kind for token: every challenge
// is answered at most once.
func (p *Passkeys) take(kind, token string, now time.Time) (ceremony, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := kind + ":" + hashToken(token)
	c, ok := p.ceremonies[key]
	delete(p.ceremonies, key)
	if !ok || now.After(c.expires) {
		return ceremony{}, ErrNoCeremony
	}
	return c, nil
}

// waUser is a user as the WebAuthn library sees it. The user handle is the
// opaque user ID: no name or address goes into the authenticator.
type waUser struct {
	u     systemdb.User
	creds []webauthn.Credential
}

func (w waUser) WebAuthnID() []byte                         { return []byte(w.u.ID) }
func (w waUser) WebAuthnName() string                       { return w.u.Username }
func (w waUser) WebAuthnDisplayName() string                { return w.u.Username }
func (w waUser) WebAuthnCredentials() []webauthn.Credential { return w.creds }

// Passkey is a registered passkey as the owner sees it.
type Passkey struct {
	ID, Name   string
	CreatedAt  time.Time
	LastUsedAt time.Time // zero = never
}

func (s *Service) passkeyUser(ctx context.Context, q *systemdb.Queries, u systemdb.User) (waUser, []systemdb.WebauthnCredential, error) {
	rows, err := q.ListPasskeys(ctx, u.ID)
	if err != nil {
		return waUser{}, nil, err
	}
	w := waUser{u: u}
	for _, r := range rows {
		var c webauthn.Credential
		if err := json.Unmarshal([]byte(r.Credential), &c); err != nil {
			return waUser{}, nil, fmt.Errorf("passkey %s can't be read: %w", r.ID, err)
		}
		w.creds = append(w.creds, c)
	}
	return w, rows, nil
}

// HasPasskeys tells whether a sign-in may offer the passkey method.
func (s *Service) HasPasskeys(ctx context.Context, userID string) (bool, error) {
	if s.Passkeys == nil {
		return false, nil
	}
	n, err := systemdb.New(s.System).CountPasskeys(ctx, userID)
	return n > 0, err
}

// ListPasskeys lists the passkeys of the signed-in user.
func (s *Service) ListPasskeys(ctx context.Context, token string) ([]Passkey, error) {
	sess, err := s.Authenticate(ctx, token)
	if err != nil {
		return nil, err
	}
	rows, err := systemdb.New(s.System).ListPasskeys(ctx, sess.UserID)
	if err != nil {
		return nil, err
	}
	out := []Passkey{}
	for _, r := range rows {
		out = append(out, Passkey{ID: r.ID, Name: r.Name, CreatedAt: parseTime(r.CreatedAt), LastUsedAt: parseNullTime(r.LastUsedAt)})
	}
	return out, nil
}

// BeginPasskeyRegistration starts adding a passkey: it needs a fresh
// step-up (checked by the caller with authz) and the current password
// (decision 45). The options go unchanged to navigator.credentials.create().
func (s *Service) BeginPasskeyRegistration(ctx context.Context, token, currentPassword, ip string) (json.RawMessage, error) {
	if s.Passkeys == nil {
		return nil, ErrPasskeysOff
	}
	now := s.now()
	_, u, err := s.checkCurrentPassword(ctx, token, currentPassword, ip, "user.passkey_add", now)
	if err != nil {
		return nil, err
	}
	w, rows, err := s.passkeyUser(ctx, systemdb.New(s.System), u)
	if err != nil {
		return nil, err
	}
	if len(rows) >= MaxPasskeys {
		return nil, ErrTooManyPasskeys
	}
	var exclude []protocol.CredentialDescriptor
	for i := range w.creds {
		exclude = append(exclude, w.creds[i].Descriptor())
	}
	creation, data, err := s.Passkeys.wa.BeginRegistration(w, webauthn.WithExclusions(exclude))
	if err != nil {
		return nil, fmt.Errorf("passkey registration: %w", err)
	}
	if err := s.Passkeys.put(ceremonyRegister, token, ceremony{data: *data, userID: u.ID, expires: now.Add(ceremonyTTL)}); err != nil {
		return nil, err
	}
	return json.Marshal(creation)
}

// FinishPasskeyRegistration stores the passkey the browser created. The
// credentials epoch rises (device cookies void) and the user's other
// sessions end, as for every new authenticator.
func (s *Service) FinishPasskeyRegistration(ctx context.Context, token, name string, body []byte, ip string) (*Passkey, error) {
	if s.Passkeys == nil {
		return nil, ErrPasskeysOff
	}
	now := s.now()
	name = strings.TrimSpace(name)
	if name == "" {
		name = "Passkey"
	}
	if utf8.RuneCountInString(name) > 64 || strings.ContainsFunc(name, isControl) {
		return nil, refused("the passkey name must be at most 64 characters without control characters")
	}
	sess, u, err := s.signedIn(ctx, token, ip, "user.passkey_add", now)
	if err != nil {
		return nil, err
	}
	c, err := s.Passkeys.take(ceremonyRegister, token, now)
	if err != nil {
		return nil, err
	}
	if c.userID != u.ID {
		return nil, ErrNoCeremony
	}
	if len(body) > maxPasskeyBody {
		return nil, refused("the passkey answer is larger than %d KiB", maxPasskeyBody>>10)
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(body))
	if err != nil {
		return nil, s.refuse(ctx, &u, ip, "user.passkey_add", audit.ResultFailure, "unreadable answer", refused("the passkey answer can't be read: %v", protocolDetail(err)))
	}
	q := systemdb.New(s.System)
	w, rows, err := s.passkeyUser(ctx, q, u)
	if err != nil {
		return nil, err
	}
	if len(rows) >= MaxPasskeys {
		return nil, ErrTooManyPasskeys
	}
	cred, err := s.Passkeys.wa.CreateCredential(w, c.data, parsed)
	if err != nil {
		return nil, s.refuse(ctx, &u, ip, "user.passkey_add", audit.ResultFailure, "verification failed", refused("the passkey can't be verified: %v", protocolDetail(err)))
	}
	if !cred.Flags.UserVerified {
		return nil, s.refuse(ctx, &u, ip, "user.passkey_add", audit.ResultDenied, "no user verification", refused("the authenticator didn't verify the user (PIN or biometrics) – use a passkey or security key with user verification"))
	}
	data, err := json.Marshal(cred)
	if err != nil {
		return nil, err
	}
	id, err := ids.New("pk", now, s.Rand)
	if err != nil {
		return nil, err
	}
	err = s.inTx(ctx, func(q *systemdb.Queries, tx *sql.Tx) error {
		if ierr := q.InsertPasskey(ctx, systemdb.InsertPasskeyParams{
			ID: id, UserID: u.ID, CredentialID: cred.ID, Credential: string(data), Name: name,
			SignCount: int64(cred.Authenticator.SignCount), CreatedAt: formatTime(now),
		}); ierr != nil {
			return ierr
		}
		if berr := q.BumpCredentialsEpoch(ctx, systemdb.BumpCredentialsEpochParams{UpdatedAt: formatTime(now), ID: u.ID}); berr != nil {
			return berr
		}
		ended, derr := q.DeleteOtherUserSessions(ctx, systemdb.DeleteOtherUserSessionsParams{UserID: u.ID, IDHash: sess.idHash})
		if derr != nil {
			return derr
		}
		return s.enqueue(ctx, tx, selfWho(u, ip), "user.passkey_add", u, map[string]any{
			"passkey": id, "name": name, "aaguid": fmt.Sprintf("%x", cred.Authenticator.AAGUID), "sessions_ended": ended,
		})
	})
	if err != nil {
		return nil, err
	}
	return &Passkey{ID: id, Name: name, CreatedAt: now}, nil
}

// DeletePasskey removes one of the signed-in user's passkeys; it needs the
// current password (and a fresh step-up, checked by the caller).
func (s *Service) DeletePasskey(ctx context.Context, token, passkeyID, currentPassword, ip string) error {
	now := s.now()
	_, u, err := s.checkCurrentPassword(ctx, token, currentPassword, ip, "user.passkey_remove", now)
	if err != nil {
		return err
	}
	return s.inTx(ctx, func(q *systemdb.Queries, tx *sql.Tx) error {
		n, err := q.DeletePasskey(ctx, systemdb.DeletePasskeyParams{ID: passkeyID, UserID: u.ID})
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrNoPasskey
		}
		if err := q.BumpCredentialsEpoch(ctx, systemdb.BumpCredentialsEpochParams{UpdatedAt: formatTime(now), ID: u.ID}); err != nil {
			return err
		}
		return s.enqueue(ctx, tx, selfWho(u, ip), "user.passkey_remove", u, map[string]any{"passkey": passkeyID})
	})
}

// BeginPasskeyLogin starts an assertion: after the password (pending
// session) it is the second factor, while signed in it is a step-up.
func (s *Service) BeginPasskeyLogin(ctx context.Context, token string, c Client) (json.RawMessage, error) {
	if s.Passkeys == nil {
		return nil, ErrPasskeysOff
	}
	now := s.now()
	q := systemdb.New(s.System)
	kind := ceremonyLogin
	var u systemdb.User
	if _, _, _, err := s.pendingPeek(ctx, q, token, now); err == nil {
		_, u, _, err = s.pending(ctx, q, token, c, now)
		if err != nil {
			return nil, err
		}
	} else {
		kind = ceremonyStepUp
		var serr error
		_, u, _, serr = s.signedInFrom(ctx, token, c, "user.step_up", now)
		if serr != nil {
			return nil, serr
		}
	}
	w, _, err := s.passkeyUser(ctx, q, u)
	if err != nil {
		return nil, err
	}
	if len(w.creds) == 0 {
		return nil, ErrNoPasskey
	}
	assertion, data, err := s.Passkeys.wa.BeginLogin(w)
	if err != nil {
		return nil, fmt.Errorf("passkey sign-in: %w", err)
	}
	if err := s.Passkeys.put(kind, token, ceremony{data: *data, userID: u.ID, expires: now.Add(ceremonyTTL)}); err != nil {
		return nil, err
	}
	return json.Marshal(assertion)
}

// pendingPeek tells whether token is a pending session, without side effects.
func (s *Service) pendingPeek(ctx context.Context, q *systemdb.Queries, token string, now time.Time) (systemdb.Session, systemdb.User, string, error) {
	row, err := s.loadSession(ctx, q, token, statePassword, now)
	return row, systemdb.User{}, "", err
}

// FinishPasskeyLogin checks the assertion. For a pending session it
// completes the sign-in (a new session ID, like a TOTP code); while signed
// in it refreshes the step-up time. A wrong assertion counts like a wrong
// code; a sign counter that goes back is refused as a cloned authenticator.
func (s *Service) FinishPasskeyLogin(ctx context.Context, token string, body []byte, c Client) (*LoginResult, error) {
	if s.Passkeys == nil {
		return nil, ErrPasskeysOff
	}
	now := s.now()
	q := systemdb.New(s.System)
	kind, action := ceremonyLogin, "user.login"
	var row systemdb.Session
	var sess *Session
	var u systemdb.User
	var device string
	var err error
	if _, _, _, perr := s.pendingPeek(ctx, q, token, now); perr == nil {
		if row, u, device, err = s.pending(ctx, q, token, c, now); err != nil {
			return nil, err
		}
	} else {
		kind, action = ceremonyStepUp, "user.step_up"
		if sess, u, device, err = s.signedInFrom(ctx, token, c, action, now); err != nil {
			return nil, err
		}
	}
	cer, err := s.Passkeys.take(kind, token, now)
	if err != nil {
		return nil, err
	}
	if cer.userID != u.ID {
		return nil, ErrNoCeremony
	}
	if len(body) > maxPasskeyBody {
		return nil, s.failedFrom(ctx, u, c, device, action, "passkey answer too large", ErrInvalidCode)
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(body))
	if err != nil {
		return nil, s.failedFrom(ctx, u, c, device, action, "unreadable passkey answer", ErrInvalidCode)
	}
	w, rows, err := s.passkeyUser(ctx, q, u)
	if err != nil {
		return nil, err
	}
	cred, err := s.Passkeys.wa.ValidateLogin(w, cer.data, parsed)
	if err != nil {
		return nil, s.failedFrom(ctx, u, c, device, action, "passkey not accepted", ErrInvalidCode)
	}
	if !cred.Flags.UserVerified {
		return nil, s.failedFrom(ctx, u, c, device, action, "passkey without user verification", ErrInvalidCode)
	}
	var stored *systemdb.WebauthnCredential
	for i := range rows {
		if bytes.Equal(rows[i].CredentialID, cred.ID) {
			stored = &rows[i]
		}
	}
	if stored == nil {
		return nil, s.failedFrom(ctx, u, c, device, action, "unknown passkey", ErrInvalidCode)
	}
	data, err := json.Marshal(cred)
	if err != nil {
		return nil, err
	}
	n, err := q.UsePasskey(ctx, systemdb.UsePasskeyParams{
		Credential: string(data), SignCount: int64(cred.Authenticator.SignCount),
		LastUsedAt: sql.NullString{String: formatTime(now), Valid: true}, ID: stored.ID,
	})
	if err != nil {
		return nil, err
	}
	if n != 1 || cred.Authenticator.CloneWarning {
		return nil, s.failedFrom(ctx, u, c, device, action, "cloned", errors.New("the passkey's signature counter went back – the authenticator may be cloned; remove this passkey"))
	}
	if kind == ceremonyLogin {
		res, cerr := s.completeLogin(ctx, u, row, c, device, now, map[string]any{"factor": "passkey", "passkey": stored.ID})
		if cerr != nil {
			return nil, cerr
		}
		res.Factor = "passkey"
		return res, nil
	}
	if aerr := s.direct(ctx, &u, c.IP, "user.step_up", audit.ResultSuccess, map[string]any{"factor": "passkey", "passkey": stored.ID}); aerr != nil {
		return nil, fmt.Errorf("step-up refused – the audit entry can't be written: %w", aerr)
	}
	stepUpMinutes, err := q.GetStepUpMinutes(ctx, s.Tenant)
	if err != nil {
		return nil, err
	}
	if serr := q.SetStepUp(ctx, systemdb.SetStepUpParams{
		StepupAt: sql.NullString{String: formatTime(now), Valid: true}, StepupMinutes: stepUpMinutes, IDHash: sess.idHash,
	}); serr != nil {
		return nil, serr
	}
	if lerr := q.SetLoginFailures(ctx, systemdb.SetLoginFailuresParams{FailedLogins: 0, LockedUntil: s.keepLock(u, device, now), UpdatedAt: formatTime(now), ID: u.ID}); lerr != nil {
		return nil, lerr
	}
	s.Throttle.Success(c.IP, u.Username)
	fresh, err := s.Authenticate(ctx, token)
	if err != nil {
		return nil, err
	}
	return &LoginResult{Token: token, Session: fresh, Factor: "passkey"}, nil
}

// protocolDetail keeps the library's explanation, not its internals.
func protocolDetail(err error) string {
	var pe *protocol.Error
	if errors.As(err, &pe) && pe.Details != "" {
		return short(pe.Details)
	}
	return short(err.Error())
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) }
