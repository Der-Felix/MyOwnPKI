package agents

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ids"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// TokenPrefix starts every join token, so secret scanners and people can
// tell one when it ends up somewhere it shouldn't.
const TokenPrefix = "mjt_"

// JoinToken is a join token without its secret (security.md "Agent trust":
// single-use, short-lived, scoped to name patterns, stored hashed).
type JoinToken struct {
	ID        string
	Label     string
	Patterns  []string
	ExpiresAt time.Time
	UsedAt    time.Time // zero = unused
	UsedBy    string    // the enrollment
	CreatedBy string
	CreatedAt time.Time
}

// Usable reports whether the token can still admit an agent at now.
func (t JoinToken) Usable(now time.Time) bool { return t.UsedAt.IsZero() && now.Before(t.ExpiresAt) }

// CreateJoinToken makes a token for hosts whose name matches one of
// patterns, valid for ttl (0 = DefaultTokenTTL). The secret is returned
// once; only its SHA-256 is stored, and the audit entry never holds it.
func (s *Service) CreateJoinToken(ctx context.Context, who keys.Who, label string, patterns []string, ttl time.Duration) (string, *JoinToken, error) {
	tok, jt, err := s.createJoinToken(ctx, who, label, patterns, ttl)
	return tok, jt, s.refused(ctx, who, ActionTokenCreate, audit.Target{Type: "join_token", ID: clip(label, 64)}, err)
}

func (s *Service) createJoinToken(ctx context.Context, who keys.Who, label string, patterns []string, ttl time.Duration) (string, *JoinToken, error) {
	if err := s.authorize(who, authz.ManageAgents); err != nil {
		return "", nil, err
	}
	label = strings.TrimSpace(label)
	if utf8.RuneCountInString(label) > 64 || strings.ContainsFunc(label, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "", nil, fmt.Errorf("%w: label: at most 64 characters, no control characters", ErrInvalid)
	}
	if len(patterns) == 0 || len(patterns) > 20 {
		return "", nil, fmt.Errorf("%w: names: 1 to 20 names or patterns the hostname must match, e.g. proxy1.homelab.lan or *.homelab.lan", ErrInvalid)
	}
	clean := make([]string, 0, len(patterns))
	for _, p := range patterns {
		cp, err := CheckPattern(p)
		if err != nil {
			return "", nil, err
		}
		clean = append(clean, cp)
	}
	if ttl == 0 {
		ttl = DefaultTokenTTL
	}
	if ttl < 5*time.Minute || ttl > MaxTokenTTL {
		return "", nil, fmt.Errorf("%w: a join token is valid for 5 minutes to 30 days", ErrInvalid)
	}
	now := s.now()
	id, err := ids.New("jtk", now, s.rnd())
	if err != nil {
		return "", nil, err
	}
	secret, err := randomText(s.rnd(), 32)
	if err != nil {
		return "", nil, err
	}
	token := TokenPrefix + secret
	jt := &JoinToken{ID: id, Label: label, Patterns: clean, ExpiresAt: now.Add(ttl), CreatedBy: who.Actor.Name, CreatedAt: now}
	pj, err := json.Marshal(clean)
	if err != nil {
		return "", nil, err
	}
	err = s.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		if ierr := q.InsertJoinToken(ctx, pkidb.InsertJoinTokenParams{
			ID: id, TokenHash: hashToken(token), Label: label, NamePatterns: string(pj), ExpiresAt: dbTime(jt.ExpiresAt),
			CreatedBy: who.Actor.Name, CreatedAt: dbTime(now),
		}); ierr != nil {
			return ierr
		}
		return enqueue(ctx, tx, now, who, ActionTokenCreate, audit.Target{Type: "join_token", ID: id},
			map[string]any{"label": label, "names": clean, "expires_at": dbTime(jt.ExpiresAt)})
	})
	if err != nil {
		return "", nil, err
	}
	return token, jt, nil
}

// ListJoinTokens returns every token, newest first (without secrets).
func (s *Service) ListJoinTokens(ctx context.Context, who keys.Who) ([]JoinToken, error) {
	if err := s.authorize(who, authz.ReadPKI); err != nil {
		return nil, err
	}
	rows, err := pkidb.New(s.PKI).ListJoinTokens(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]JoinToken, 0, len(rows))
	for _, r := range rows {
		out = append(out, toJoinToken(r))
	}
	return out, nil
}

// DeleteJoinToken withdraws an unused token; a used one stays as a record.
func (s *Service) DeleteJoinToken(ctx context.Context, who keys.Who, id string) error {
	return s.refused(ctx, who, ActionTokenDelete, audit.Target{Type: "join_token", ID: id}, s.deleteJoinToken(ctx, who, id))
}

func (s *Service) deleteJoinToken(ctx context.Context, who keys.Who, id string) error {
	if err := s.authorize(who, authz.ManageAgents); err != nil {
		return err
	}
	now := s.now()
	return s.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		row, err := q.GetJoinToken(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		n, err := q.DeleteJoinToken(ctx, id)
		if err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("%w: this join token was used already – it stays as a record", ErrConflict)
		}
		return enqueue(ctx, tx, now, who, ActionTokenDelete, audit.Target{Type: "join_token", ID: id}, map[string]any{"label": row.Label})
	})
}

func toJoinToken(r pkidb.JoinToken) JoinToken {
	var patterns []string
	_ = json.Unmarshal([]byte(r.NamePatterns), &patterns)
	return JoinToken{
		ID: r.ID, Label: r.Label, Patterns: patterns, ExpiresAt: parseTime(r.ExpiresAt), UsedAt: nullTime(r.UsedAt),
		UsedBy: r.UsedBy.String, CreatedBy: r.CreatedBy, CreatedAt: parseTime(r.CreatedAt),
	}
}

// hashToken is the stored form of a secret: SHA-256, hex. The secrets carry
// 256 random bits, so a slow password hash would add nothing.
func hashToken(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

// randomText returns n random bytes, base64url without padding.
func randomText(r io.Reader, n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
