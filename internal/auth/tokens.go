package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ids"
	"github.com/Der-Felix/MyOwnPKI/internal/store/systemdb"
)

// API tokens (PHASE1 step 18, security.md): random, shown once, stored as
// SHA-256, scoped to a subset of the owner's roles, expiring. A token never
// satisfies step-up – revocations, key downloads and CA management need a
// person with a fresh second factor.

// Token limits.
const (
	TokenPrefix   = "mop_"
	MaxTokens     = 20
	MaxTokenLife  = 366 * 24 * time.Hour
	tokenTouchGap = time.Minute
)

// ErrNoToken: no such token of this user.
var ErrNoToken = errors.New("no such API token")

var tokenEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// Token is an API token as its owner sees it (never the secret).
type Token struct {
	ID, Name             string
	Roles                []authz.Binding
	CreatedAt, ExpiresAt time.Time
	LastUsedAt           time.Time // zero = never
}

type tokenRole struct {
	Tenant string `json:"tenant"`
	CA     string `json:"ca,omitempty"`
	Role   string `json:"role"`
}

var roleRank = map[authz.Role]int{authz.Viewer: 1, authz.Operator: 2, authz.Admin: 3}

// covers: the binding have grants at least want (same tenant, whole tenant
// or the same CA, a role as high or higher).
func covers(have, want authz.Binding) bool {
	return have.Tenant == want.Tenant && (have.CA == "" || have.CA == want.CA) && roleRank[have.Role] >= roleRank[want.Role]
}

func coveredBy(bs []authz.Binding, want authz.Binding) bool {
	for _, b := range bs {
		if covers(b, want) {
			return true
		}
	}
	return false
}

func tokenHash(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// CreateToken makes a token for the signed-in user with roles the user has
// (never more) and an end within a year. The secret is returned once.
func (s *Service) CreateToken(ctx context.Context, token, name string, roles []authz.Binding, expires time.Time, ip string) (string, *Token, error) {
	now := s.now()
	sess, err := s.Authenticate(ctx, token)
	if err != nil {
		return "", nil, err
	}
	if sess.TokenID != "" {
		return "", nil, refused("an API token can't create tokens")
	}
	name = strings.TrimSpace(name)
	var reasons []string
	if name == "" || utf8.RuneCountInString(name) > 64 || strings.ContainsFunc(name, isControl) {
		reasons = append(reasons, "the token name must be 1 to 64 characters without control characters")
	}
	switch {
	case expires.IsZero():
		reasons = append(reasons, "a token needs an end (expires_at) – at most one year")
	case !expires.After(now):
		reasons = append(reasons, "expires_at is in the past")
	case expires.Sub(now) > MaxTokenLife:
		reasons = append(reasons, "a token lives at most one year")
	}
	if len(roles) == 0 {
		reasons = append(reasons, "a token needs at least one role")
	}
	q := systemdb.New(s.System)
	have, err := q.ListRoleBindings(ctx, sess.UserID)
	if err != nil {
		return "", nil, err
	}
	var own []authz.Binding
	for _, b := range have {
		own = append(own, authz.Binding{Tenant: b.TenantID, CA: b.Ca, Role: authz.Role(b.Role)})
	}
	stored := []tokenRole{}
	for _, r := range roles {
		if _, ok := roleRank[r.Role]; !ok {
			reasons = append(reasons, fmt.Sprintf("unknown role %q", short(string(r.Role))))
			continue
		}
		if !coveredBy(own, r) {
			reasons = append(reasons, fmt.Sprintf("you don't have the role %s for %s yourself – a token never gets more than its owner", r.Role, scopeName(r)))
			continue
		}
		stored = append(stored, tokenRole{Tenant: r.Tenant, CA: r.CA, Role: string(r.Role)})
	}
	if n, cerr := q.CountTokens(ctx, sess.UserID); cerr != nil {
		return "", nil, cerr
	} else if n >= MaxTokens {
		reasons = append(reasons, fmt.Sprintf("at most %d tokens per user – revoke one first", MaxTokens))
	}
	if len(reasons) > 0 {
		return "", nil, &RefusedError{Reasons: reasons}
	}
	raw := make([]byte, 32)
	rnd := s.Rand
	if rnd == nil {
		rnd = rand.Reader
	}
	if _, rerr := io.ReadFull(rnd, raw); rerr != nil {
		return "", nil, rerr
	}
	secret := TokenPrefix + strings.ToLower(tokenEncoding.EncodeToString(raw))
	id, err := ids.New("tok", now, s.Rand)
	if err != nil {
		return "", nil, err
	}
	rolesJSON, err := json.Marshal(stored)
	if err != nil {
		return "", nil, err
	}
	u, err := q.GetUser(ctx, sess.UserID)
	if err != nil {
		return "", nil, err
	}
	err = s.inTx(ctx, func(q *systemdb.Queries, tx *sql.Tx) error {
		if ierr := q.InsertToken(ctx, systemdb.InsertTokenParams{
			ID: id, UserID: u.ID, Name: name, TokenHash: tokenHash(secret), RolesJson: string(rolesJSON),
			CreatedAt: formatTime(now), ExpiresAt: formatTime(expires.UTC()),
		}); ierr != nil {
			return ierr
		}
		return s.enqueue(ctx, tx, selfWho(u, ip), "user.token_create", u, map[string]any{
			"token_id": id, "name": name, "roles": bindingNames(roles), "expires_at": formatTime(expires.UTC()),
		})
	})
	if err != nil {
		return "", nil, err
	}
	return secret, &Token{ID: id, Name: name, Roles: roles, CreatedAt: now, ExpiresAt: expires.UTC()}, nil
}

func scopeName(b authz.Binding) string {
	if b.CA != "" {
		return fmt.Sprintf("CA %q in tenant %s", b.CA, b.Tenant)
	}
	return "tenant " + b.Tenant
}

func tokenOf(r systemdb.ApiToken) Token {
	t := Token{ID: r.ID, Name: r.Name, CreatedAt: parseTime(r.CreatedAt), ExpiresAt: parseTime(r.ExpiresAt), LastUsedAt: parseNullTime(r.LastUsedAt)}
	var roles []tokenRole
	_ = json.Unmarshal([]byte(r.RolesJson), &roles)
	for _, x := range roles {
		t.Roles = append(t.Roles, authz.Binding{Tenant: x.Tenant, CA: x.CA, Role: authz.Role(x.Role)})
	}
	return t
}

// ListTokens lists the signed-in user's tokens.
func (s *Service) ListTokens(ctx context.Context, token string) ([]Token, error) {
	sess, err := s.Authenticate(ctx, token)
	if err != nil {
		return nil, err
	}
	rows, err := systemdb.New(s.System).ListTokens(ctx, sess.UserID)
	if err != nil {
		return nil, err
	}
	out := []Token{}
	for _, r := range rows {
		out = append(out, tokenOf(r))
	}
	return out, nil
}

// RevokeToken deletes one of the signed-in user's tokens; it stops working
// at once.
func (s *Service) RevokeToken(ctx context.Context, token, id, ip string) error {
	sess, err := s.Authenticate(ctx, token)
	if err != nil {
		return err
	}
	u, err := systemdb.New(s.System).GetUser(ctx, sess.UserID)
	if err != nil {
		return err
	}
	return s.inTx(ctx, func(q *systemdb.Queries, tx *sql.Tx) error {
		n, derr := q.DeleteToken(ctx, systemdb.DeleteTokenParams{ID: id, UserID: u.ID})
		if derr != nil {
			return derr
		}
		if n != 1 {
			return ErrNoToken
		}
		return s.enqueue(ctx, tx, selfWho(u, ip), "user.token_revoke", u, map[string]any{"token_id": id})
	})
}

// AuthenticateToken turns a bearer secret into a session-like principal:
// the token's roles that the owner still has, no instance admin, no
// step-up. Expired tokens and tokens of disabled users don't work.
func (s *Service) AuthenticateToken(ctx context.Context, secret string) (*Session, error) {
	if !strings.HasPrefix(secret, TokenPrefix) || len(secret) > 128 {
		return nil, ErrNoSession
	}
	now := s.now()
	q := systemdb.New(s.System)
	row, err := q.GetTokenByHash(ctx, tokenHash(secret))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoSession
	}
	if err != nil {
		return nil, err
	}
	if !now.Before(parseTime(row.ExpiresAt)) {
		return nil, ErrNoSession
	}
	u, err := q.GetUser(ctx, row.UserID)
	if err != nil {
		return nil, err
	}
	if u.DisabledAt.Valid {
		return nil, ErrNoSession
	}
	have, err := q.ListRoleBindings(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	var own []authz.Binding
	for _, b := range have {
		own = append(own, authz.Binding{Tenant: b.TenantID, CA: b.Ca, Role: authz.Role(b.Role)})
	}
	t := tokenOf(row)
	p := &authz.Principal{Kind: authz.KindUser, UserID: u.ID, Username: u.Username}
	for _, b := range t.Roles {
		if coveredBy(own, b) {
			p.Bindings = append(p.Bindings, b)
		}
	}
	if !row.LastUsedAt.Valid || now.Sub(parseTime(row.LastUsedAt.String)) >= tokenTouchGap {
		_ = q.TouchToken(ctx, systemdb.TouchTokenParams{LastUsedAt: sql.NullString{String: formatTime(now), Valid: true}, ID: row.ID})
	}
	return &Session{UserID: u.ID, Username: u.Username, Principal: p, TokenID: row.ID, TokenName: row.Name, ExpiresAt: parseTime(row.ExpiresAt), LastSeen: now}, nil
}
