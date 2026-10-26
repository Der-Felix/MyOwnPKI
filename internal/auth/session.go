package auth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/store/systemdb"
)

// Session timing (PHASE1 step 10, owner decision e).
const (
	// PendingTTL: after the password, the second factor must follow within this time.
	PendingTTL = 5 * time.Minute
	// IdleTimeout ends a session nobody used for this long.
	IdleTimeout = 30 * time.Minute
	// AbsoluteTimeout ends every session, used or not.
	AbsoluteTimeout = 12 * time.Hour
	// touchEvery: last_seen_at is written at most this often, not on every click.
	touchEvery = time.Minute
	tokenBytes = 32 // 256 random bits
)

// CookieName has the __Host- prefix: the browser only accepts it with Secure,
// Path=/ and no Domain, so a sibling host can't set or overwrite it.
const CookieName = "__Host-myownpki_session"

// Session states.
const (
	statePassword = "password" // only the second factor may follow
	stateFull     = "full"
)

// ErrNoSession: no valid session – sign in (again).
var ErrNoSession = errors.New("not signed in or the session has ended – sign in again")

// timeFormat is fixed-width, so the database compares times as text.
const timeFormat = "2006-01-02T15:04:05.000Z"

func formatTime(t time.Time) string { return t.UTC().Format(timeFormat) }

func parseTime(s string) time.Time {
	t, err := time.Parse(timeFormat, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func parseNullTime(s sql.NullString) time.Time {
	if !s.Valid {
		return time.Time{}
	}
	return parseTime(s.String)
}

// Session is a signed-in user (or one between password and second factor).
type Session struct {
	UserID         string
	Username       string
	CSRFToken      string
	CreatedAt      time.Time
	ExpiresAt      time.Time // absolute end (a pending session: PendingTTL)
	LastSeen       time.Time // last activity; the idle timeout counts from here
	StepUpAt       time.Time
	StepUpDuration time.Duration
	// Principal is what the session may do; nil for a pending session.
	Principal *authz.Principal
	// TokenID and TokenName are set when an API token signed the request in
	// (no cookie, no CSRF token, never a step-up).
	TokenID, TokenName string

	idHash  string
	pending bool
}

// IdleExpiresAt is when the session ends without further activity.
func (s *Session) IdleExpiresAt() time.Time {
	if idle := s.LastSeen.Add(IdleTimeout); !s.pending && idle.Before(s.ExpiresAt) {
		return idle
	}
	return s.ExpiresAt
}

// SessionCookie is the cookie for token. No Expires: the browser drops it at
// exit, the server ends it after IdleTimeout / AbsoluteTimeout anyway.
func SessionCookie(token string) *http.Cookie {
	return &http.Cookie{Name: CookieName, Value: token, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
}

// ClearSessionCookie removes the cookie (logout).
func ClearSessionCookie() *http.Cookie {
	return &http.Cookie{Name: CookieName, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1}
}

// hashToken: the database holds only this, never the cookie value.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (s *Service) newToken() (string, error) {
	b, err := randomBytes(s.Rand, tokenBytes)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// insertSession creates a session and returns its cookie value.
func (s *Service) insertSession(ctx context.Context, q *systemdb.Queries, userID, state string, now time.Time) (string, error) {
	token, err := s.newToken()
	if err != nil {
		return "", err
	}
	csrf, err := s.newToken()
	if err != nil {
		return "", err
	}
	expires := now.Add(AbsoluteTimeout)
	var stepUp sql.NullString
	stepUpMinutes := int64(authz.StepUpWindow / time.Minute)
	if state == statePassword {
		expires = now.Add(PendingTTL)
	} else {
		// The second factor was just entered: that counts as a step-up. Keep
		// its configured lifetime with the proof, not with the tenant.
		stepUp = sql.NullString{String: formatTime(now), Valid: true}
		stepUpMinutes, err = q.GetStepUpMinutes(ctx, s.Tenant)
		if err != nil {
			return "", err
		}
	}
	err = q.InsertSession(ctx, systemdb.InsertSessionParams{
		IDHash: hashToken(token), UserID: userID, State: state, CsrfToken: csrf,
		CreatedAt: formatTime(now), LastSeenAt: formatTime(now), ExpiresAt: formatTime(expires), StepupAt: stepUp, StepupMinutes: stepUpMinutes,
	})
	return token, err
}

// loadSession returns the live session of token in the given state; an
// expired one is deleted.
func (s *Service) loadSession(ctx context.Context, q *systemdb.Queries, token, state string, now time.Time) (systemdb.Session, error) {
	if token == "" {
		return systemdb.Session{}, ErrNoSession
	}
	row, err := q.GetSession(ctx, hashToken(token))
	if errors.Is(err, sql.ErrNoRows) {
		return row, ErrNoSession
	}
	if err != nil {
		return row, err
	}
	expired := !now.Before(parseTime(row.ExpiresAt)) ||
		(row.State == stateFull && !now.Before(parseTime(row.LastSeenAt).Add(IdleTimeout)))
	if expired {
		_ = q.DeleteSession(ctx, row.IDHash)
		return row, ErrNoSession
	}
	if row.State != state {
		return row, ErrNoSession
	}
	return row, nil
}

// Authenticate returns the signed-in session of token with its principal.
// It ends sessions of disabled users and records activity (at most once a
// minute), which moves the idle timeout.
func (s *Service) Authenticate(ctx context.Context, token string) (*Session, error) {
	return s.authenticate(ctx, token, true)
}

// AuthenticatePassive is Authenticate without counting as activity: for
// requests a page makes on its own (status polling), so an open browser tab
// still times out (owner 2026-10-17).
func (s *Service) AuthenticatePassive(ctx context.Context, token string) (*Session, error) {
	return s.authenticate(ctx, token, false)
}

func (s *Service) authenticate(ctx context.Context, token string, touch bool) (*Session, error) {
	now := s.now()
	q := systemdb.New(s.System)
	row, err := s.loadSession(ctx, q, token, stateFull, now)
	if err != nil {
		return nil, err
	}
	u, err := q.GetUser(ctx, row.UserID)
	if err != nil {
		return nil, err
	}
	if u.DisabledAt.Valid {
		_, _ = q.DeleteUserSessions(ctx, u.ID)
		return nil, ErrNoSession
	}
	bindings, err := q.ListRoleBindings(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	if touch && now.Sub(parseTime(row.LastSeenAt)) >= touchEvery {
		if err := q.TouchSession(ctx, systemdb.TouchSessionParams{LastSeenAt: formatTime(now), IDHash: row.IDHash}); err != nil {
			return nil, err
		}
		row.LastSeenAt = formatTime(now)
	}
	return sessionOf(row, u, bindings), nil
}

func sessionOf(row systemdb.Session, u systemdb.User, bindings []systemdb.RoleBinding) *Session {
	sess := &Session{
		UserID: u.ID, Username: u.Username, CSRFToken: row.CsrfToken, CreatedAt: parseTime(row.CreatedAt), LastSeen: parseTime(row.LastSeenAt),
		ExpiresAt: parseTime(row.ExpiresAt), StepUpAt: parseNullTime(row.StepupAt), StepUpDuration: time.Duration(row.StepupMinutes) * time.Minute,
		idHash: row.IDHash, pending: row.State == statePassword,
	}
	if !sess.pending {
		p := &authz.Principal{Kind: authz.KindUser, UserID: u.ID, Username: u.Username, InstanceAdmin: u.InstanceAdmin == 1,
			StepUpAt: sess.StepUpAt, StepUpDuration: sess.StepUpDuration}
		for _, b := range bindings {
			p.Bindings = append(p.Bindings, authz.Binding{Tenant: b.TenantID, CA: b.Ca, Role: authz.Role(b.Role)})
		}
		sess.Principal = p
	}
	return sess
}

// PruneSessions deletes ended sessions; the server runs it periodically.
func (s *Service) PruneSessions(ctx context.Context) (int64, error) {
	now := s.now()
	return systemdb.New(s.System).DeleteExpiredSessions(ctx, systemdb.DeleteExpiredSessionsParams{
		ExpiresAt: formatTime(now), LastSeenAt: formatTime(now.Add(-IdleTimeout)),
	})
}
