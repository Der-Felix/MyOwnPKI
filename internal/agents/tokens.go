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
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/ids"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// Prefixes of the secrets, so secret scanners and people can tell one when it
// ends up somewhere it shouldn't, and tell a pass from a token.
const (
	TokenPrefix = "mjt_"
	PassPrefix  = "mjp_"
)

// Kinds of join token (join_tokens.kind): a plain token admits one host, an
// enrollment pass admits up to MaxPassUses hosts (docs/PHASE3.md section 11.2).
const (
	KindToken = "token"
	KindPass  = "pass"
)

// Limits of an enrollment pass (docs/PHASE3.md section 11.2). They are
// constants, not configuration: a leaked pass admits at most MaxPassUses
// hosts matching at most MaxPassPatterns patterns until it expires, and a
// larger fleet takes two passes.
const (
	MinPassUses     = 2
	MaxPassUses     = 25
	DefaultPassUses = 10
	MaxPassPatterns = 5
	MinPassTTL      = 5 * time.Minute
	MaxPassTTL      = 7 * 24 * time.Hour
	DefaultPassTTL  = 24 * time.Hour
)

// TokenState is where a join token or pass stands at a given time.
type TokenState string

// Token states. A revoked token reports revoked whatever else is true, a used
// up one used_up before it reports expired.
const (
	TokenActive  TokenState = "active"
	TokenUsedUp  TokenState = "used_up"
	TokenExpired TokenState = "expired"
	TokenRevoked TokenState = "revoked"
)

// JoinToken is a join token or enrollment pass without its secret
// (security.md "Agent trust": short-lived, scoped to name patterns, stored
// hashed; a plain token is single-use, a pass has a bounded number of uses).
type JoinToken struct {
	ID        string
	Label     string
	Kind      string // KindToken | KindPass
	Patterns  []string
	MaxUses   int
	UseCount  int
	ExpiresAt time.Time
	UsedAt    time.Time // the last use was taken; zero = uses left
	UsedBy    string    // the enrollment of the last use
	RevokedAt time.Time
	RevokedBy string
	CreatedBy string
	CreatedAt time.Time
	// Hosts are the enrollments a pass admitted or queued, oldest first
	// (ListJoinTokens fills them for passes only).
	Hosts []PassHost
}

// PassHost is one use of a pass: the enrollment it started and where that
// stands now.
type PassHost struct {
	Enrollment string
	Hostname   string
	State      string // the enrollment state
	AgentID    string // set once admitted
	At         time.Time
}

// State reports the state of the token at now.
func (t JoinToken) State(now time.Time) TokenState {
	switch {
	case !t.RevokedAt.IsZero():
		return TokenRevoked
	case t.UseCount >= t.MaxUses:
		return TokenUsedUp
	case !now.Before(t.ExpiresAt):
		return TokenExpired
	}
	return TokenActive
}

// Usable reports whether the token can still admit an agent at now.
func (t JoinToken) Usable(now time.Time) bool { return t.State(now) == TokenActive }

// problem says why the token doesn't count for host at now, in the words of
// the approval queue and of the agent's status ("" = it counts). The words
// are for whoever holds the secret; they name the reason (docs/PHASE3.md
// section 11.2). A plain token keeps the wording it always had.
func (t JoinToken) problem(now time.Time, host string) string {
	pass := t.Kind == KindPass
	switch t.State(now) {
	case TokenActive: // it counts, unless the name is not covered (below)
	case TokenRevoked:
		if pass {
			return "the pass was revoked"
		}
		return "the join token was revoked"
	case TokenUsedUp:
		if pass {
			return fmt.Sprintf("the enrollment pass has no uses left (%d of %d) – ask an admin for a new one", t.UseCount, t.MaxUses)
		}
		return "the join token was used already"
	case TokenExpired:
		if pass {
			return "the pass expired"
		}
		return "the join token expired"
	}
	if !MatchesAny(t.Patterns, host) {
		if pass {
			return "the pass is not for " + host
		}
		return "the join token is not for " + host
	}
	return ""
}

// NewToken is a join token or pass to create.
type NewToken struct {
	Kind     string // "" = KindToken
	Label    string
	Patterns []string
	TTL      time.Duration // 0 = the default of the kind
	MaxUses  int           // pass only; 0 = DefaultPassUses
}

// CreateJoinToken makes a single-use token for hosts whose name matches one
// of patterns, valid for ttl (0 = DefaultTokenTTL). The secret is returned
// once; only its SHA-256 is stored, and the audit entry never holds it.
func (s *Service) CreateJoinToken(ctx context.Context, who keys.Who, label string, patterns []string, ttl time.Duration) (string, *JoinToken, error) {
	return s.CreateToken(ctx, who, NewToken{Kind: KindToken, Label: label, Patterns: patterns, TTL: ttl})
}

// CreateEnrollmentPass makes a pass that admits up to maxUses hosts whose
// name matches one of patterns, valid for ttl (0 = DefaultPassTTL). It needs
// the same fresh second factor as a join token and, unlike one, only names
// that a domain covers.
func (s *Service) CreateEnrollmentPass(ctx context.Context, who keys.Who, label string, patterns []string, maxUses int, ttl time.Duration) (string, *JoinToken, error) {
	return s.CreateToken(ctx, who, NewToken{Kind: KindPass, Label: label, Patterns: patterns, TTL: ttl, MaxUses: maxUses})
}

// CreateToken creates a join token or an enrollment pass; the secret is
// returned once.
func (s *Service) CreateToken(ctx context.Context, who keys.Who, in NewToken) (string, *JoinToken, error) {
	tok, jt, err := s.createToken(ctx, who, in)
	return tok, jt, s.refused(ctx, who, ActionTokenCreate, audit.Target{Type: "join_token", ID: clip(in.Label, 64)}, err)
}

func (s *Service) createToken(ctx context.Context, who keys.Who, in NewToken) (string, *JoinToken, error) {
	if err := s.authorize(who, authz.ManageAgents); err != nil {
		return "", nil, err
	}
	pass := in.Kind == KindPass
	if in.Kind != "" && in.Kind != KindToken && !pass {
		return "", nil, fmt.Errorf("%w: kind: token or pass", ErrInvalid)
	}
	label := strings.TrimSpace(in.Label)
	if utf8.RuneCountInString(label) > 64 || strings.ContainsFunc(label, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "", nil, fmt.Errorf("%w: label: at most 64 characters, no control characters", ErrInvalid)
	}
	maxPatterns := 20
	if pass {
		maxPatterns = MaxPassPatterns
		if label == "" {
			return "", nil, fmt.Errorf("%w: label: required for a pass – it says on the list and in the audit log what the pass is for", ErrInvalid)
		}
	}
	if len(in.Patterns) == 0 || len(in.Patterns) > maxPatterns {
		return "", nil, fmt.Errorf("%w: names: 1 to %d names or patterns the hostname must match, e.g. proxy1.homelab.lan or *.homelab.lan", ErrInvalid, maxPatterns)
	}
	clean := make([]string, 0, len(in.Patterns))
	for _, p := range in.Patterns {
		cp, err := CheckPattern(p)
		if err != nil {
			return "", nil, err
		}
		clean = append(clean, cp)
	}
	ttl, maxUses := in.TTL, 1
	prefix, kind := TokenPrefix, KindToken
	if pass {
		prefix, kind = PassPrefix, KindPass
		if maxUses = in.MaxUses; maxUses == 0 {
			maxUses = DefaultPassUses
		}
		if maxUses < MinPassUses || maxUses > MaxPassUses {
			return "", nil, fmt.Errorf("%w: uses: a pass admits %d to %d hosts", ErrInvalid, MinPassUses, MaxPassUses)
		}
		if ttl == 0 {
			ttl = DefaultPassTTL
		}
		if ttl < MinPassTTL || ttl > MaxPassTTL {
			return "", nil, fmt.Errorf("%w: a pass is valid for 5 minutes to 7 days", ErrInvalid)
		}
		// The enrollment check needs a domain (Service.check): a pass for names
		// no domain covers could never admit anyone. A wildcard is asked with a
		// name below the suffix.
		for _, p := range clean {
			if err := s.coveredByDomain(ctx, p); err != nil {
				return "", nil, err
			}
		}
	} else {
		if ttl == 0 {
			ttl = DefaultTokenTTL
		}
		if ttl < 5*time.Minute || ttl > MaxTokenTTL {
			return "", nil, fmt.Errorf("%w: a join token is valid for 5 minutes to 30 days", ErrInvalid)
		}
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
	token := prefix + secret
	jt := &JoinToken{ID: id, Label: label, Kind: kind, Patterns: clean, MaxUses: maxUses, ExpiresAt: now.Add(ttl), CreatedBy: who.Actor.Name, CreatedAt: now}
	pj, err := json.Marshal(clean)
	if err != nil {
		return "", nil, err
	}
	err = s.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		if ierr := q.InsertJoinToken(ctx, pkidb.InsertJoinTokenParams{
			ID: id, TokenHash: hashToken(token), Label: label, NamePatterns: string(pj), ExpiresAt: dbTime(jt.ExpiresAt),
			CreatedBy: who.Actor.Name, CreatedAt: dbTime(now), Kind: kind, MaxUses: int64(maxUses),
		}); ierr != nil {
			return ierr
		}
		return enqueue(ctx, tx, now, who, ActionTokenCreate, audit.Target{Type: "join_token", ID: id},
			map[string]any{"label": label, "kind": kind, "max_uses": maxUses, "names": clean, "expires_at": dbTime(jt.ExpiresAt)})
	})
	if err != nil {
		return "", nil, err
	}
	return token, jt, nil
}

// coveredByDomain refuses a pattern that no domain covers: the exact name,
// or for "*.suffix" a name below it. The domain's address policy applies at
// the check, which looks the domain up again.
func (s *Service) coveredByDomain(ctx context.Context, pattern string) error {
	probe := pattern
	if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
		probe = "x." + suffix
	}
	d, err := s.Engine.DomainFor(ctx, "dns", probe)
	if err != nil && !errors.Is(err, ca.ErrNotFound) {
		return err
	}
	if d == nil {
		return fmt.Errorf("%w: names: no domain covers %s – an admin of the PKI must add one first (Domains)", ErrInvalid, pattern)
	}
	return nil
}

// ListJoinTokens returns every token and pass, newest first, without secrets.
// A pass comes with the enrollments it admitted or queued.
func (s *Service) ListJoinTokens(ctx context.Context, who keys.Who) ([]JoinToken, error) {
	if err := s.authorize(who, authz.ReadPKI); err != nil {
		return nil, err
	}
	q := pkidb.New(s.PKI)
	rows, err := q.ListJoinTokens(ctx)
	if err != nil {
		return nil, err
	}
	uses, err := q.ListPassEnrollments(ctx)
	if err != nil {
		return nil, err
	}
	hosts := map[string][]PassHost{}
	for _, u := range uses {
		hosts[u.TokenID.String] = append(hosts[u.TokenID.String], PassHost{
			Enrollment: u.ID, Hostname: u.Hostname, State: u.State, AgentID: u.AgentID.String, At: parseTime(u.CreatedAt),
		})
	}
	out := make([]JoinToken, 0, len(rows))
	for _, r := range rows {
		jt := toJoinToken(r)
		jt.Hosts = hosts[r.ID]
		out = append(out, jt)
	}
	return out, nil
}

// DeleteJoinToken withdraws a token or pass nobody has used; a used one
// stays as a record.
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
		return enqueue(ctx, tx, now, who, ActionTokenDelete, audit.Target{Type: "join_token", ID: id}, map[string]any{"label": row.Label, "kind": row.Kind})
	})
}

// RevokeJoinToken ends the use of a token or pass at once. It does not touch
// the enrollments and agents the token already produced: they stay, listed
// on the pass, for an admin to refuse or disable (docs/PHASE3.md section 11.2).
func (s *Service) RevokeJoinToken(ctx context.Context, who keys.Who, id string) error {
	return s.refused(ctx, who, ActionTokenRevoke, audit.Target{Type: "join_token", ID: id}, s.revokeJoinToken(ctx, who, id))
}

func (s *Service) revokeJoinToken(ctx context.Context, who keys.Who, id string) error {
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
		n, err := q.RevokeJoinToken(ctx, pkidb.RevokeJoinTokenParams{Now: nullString(dbTime(now)), By: nullString(who.Actor.Name), ID: id})
		if err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("%w: this %s can't admit anybody any more (%s) – nothing to revoke", ErrConflict, tokenNoun(row.Kind), strings.ReplaceAll(string(toJoinToken(row).State(now)), "_", " "))
		}
		return enqueue(ctx, tx, now, who, ActionTokenRevoke, audit.Target{Type: "join_token", ID: id},
			map[string]any{"label": row.Label, "kind": row.Kind, "use": useText(row.UseCount, row.MaxUses)})
	})
}

func tokenNoun(kind string) string {
	if kind == KindPass {
		return "pass"
	}
	return "join token"
}

// useText is "3 of 10", as the audit entries and the pages say it.
func useText(used, max int64) string { return fmt.Sprintf("%d of %d", used, max) }

func toJoinToken(r pkidb.JoinToken) JoinToken {
	var patterns []string
	_ = json.Unmarshal([]byte(r.NamePatterns), &patterns)
	return JoinToken{
		ID: r.ID, Label: r.Label, Kind: r.Kind, Patterns: patterns, MaxUses: int(r.MaxUses), UseCount: int(r.UseCount),
		ExpiresAt: parseTime(r.ExpiresAt), UsedAt: nullTime(r.UsedAt), UsedBy: r.UsedBy.String,
		RevokedAt: nullTime(r.RevokedAt), RevokedBy: r.RevokedBy.String, CreatedBy: r.CreatedBy, CreatedAt: parseTime(r.CreatedAt),
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
