// Package agents is the server side of myownpki-agent (docs/PHASE3.md): join
// tokens, enrollment with proof of control (ADR-18), the agents' 7-day
// certificates from the agent CA, their names, disable and revoke.
//
// Everything an agent sends is attacker input. Before it is admitted, an
// agent can only create a pending enrollment – limited in number, expiring,
// never an agent – and nothing it reports is ever used as a path or a
// command here.
package agents

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/predecessor"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// Audit actions.
const (
	ActionEnroll      = "agent.enroll"       // an enrollment arrived (anonymous, with the source address)
	ActionAdmit       = "agent.admit"        // admitted by the mode or an admin
	ActionDeny        = "agent.deny"         // refused by an admin
	ActionDisable     = "agent.disable"      // and agent.enable
	ActionEnable      = "agent.enable"       //
	ActionRevoke      = "agent.revoke"       // its certificates on the CRL, cut off
	ActionNames       = "agent.names"        // a name added or removed
	ActionTokenCreate = "agent.token.create" // a join token made (shown once)
	ActionTokenDelete = "agent.token.delete" // an unused join token withdrawn
)

// Limits (docs/PHASE3.md §6.1).
const (
	// CertificateDays is the validity of an agent certificate; the agent
	// renews it at 2/3.
	CertificateDays = 7
	// MaxOpenWithoutToken: pending enrollments without a valid join token
	// per tenant. An enrollment with a valid token is never refused by it.
	MaxOpenWithoutToken = 100
	// ShortExpiry: pending without a valid token and without a passed check.
	ShortExpiry = 24 * time.Hour
	// LongExpiry: every other pending enrollment.
	LongExpiry = 7 * 24 * time.Hour
	// MaxTokenTTL and DefaultTokenTTL bound a join token's life.
	MaxTokenTTL     = 30 * 24 * time.Hour
	DefaultTokenTTL = 24 * time.Hour
	// Per source address: enrollments per 10 minutes, status polls per hour
	// (a pending agent polls every 30 s; several may share one NAT address).
	enrollPerWindow = 30
	statusPerHour   = 1200
	// Renewals of the agent certificate per agent and hour.
	renewPerHour = 6
	// Authenticated reports and desired-state watches per agent and 10 minutes.
	reportPerWindow = 60
	watchPerWindow  = 120
)

// Errors the transport maps to its codes.
var (
	ErrNotFound     = ca.ErrNotFound
	ErrInvalid      = errors.New("invalid request")
	ErrQueueFull    = errors.New("too many enrollments wait for approval – ask an admin for a join token")
	ErrRateLimited  = errors.New("too many requests from this address – try again later")
	ErrUnknownAgent = errors.New("this certificate belongs to no active agent")
	ErrConflict     = errors.New("conflict")
	errNoAgentCA    = errors.New("no agent CA is configured")
)

// Checker proves control of host: it fetches
// http://host/.well-known/acme-challenge/<token> and compares the answer
// with want, under the address policy of the domain (acme.HTTP01Checker).
type Checker interface {
	Check(ctx context.Context, host, token, want, policy string) error
}

// Service is the agent service of one tenant.
type Service struct {
	PKI    *sql.DB // pki.db writer
	Tenant string  // the tenant these agents belong to
	Engine *ca.Engine
	// CA is agent.ca: the CA that signs the agents' certificates.
	CA string
	// Mode returns the tenant's enrollment mode (tenant.Store).
	Mode func(ctx context.Context) (string, error)
	// AgentPredecessor returns the tenant default for agent deployments.
	AgentPredecessor func(ctx context.Context) (predecessor.Policy, error)
	Checker          Checker
	Clock            clock.Clock
	Log              *slog.Logger
	Wake             func()
	Rand             io.Reader                                  // nil = crypto/rand
	Sleep            func(context.Context, time.Duration) error // nil = clock.Sleep

	limitOnce     sync.Once
	limits        *limiter
	watchMu       sync.Mutex
	watches       map[string]*watchSlot
	watchesClosed bool
}

// Agent is an admitted agent.
type Agent struct {
	ID              string
	Hostname        string
	Status          string // active | disabled | revoked
	EnrollmentMode  string
	Proof           string // JSON
	CertificateID   string
	CertSerial      string
	OS, Arch        string
	Version         string
	LastSeenAt      time.Time
	CreatedAt       time.Time
	ApprovedAt      time.Time
	ApprovedBy      string
	Predecessor     *predecessor.Policy
	EffectivePolicy predecessor.Policy
	Names           []Name
	Deployments     []Deployment
}

// Name is one entry of an agent's name list.
type Name struct {
	Pattern string
	Source  string // hostname | token | admin
	AddedBy string
	AddedAt time.Time
}

// Agent states.
const (
	StatusActive   = "active"
	StatusDisabled = "disabled"
	StatusRevoked  = "revoked"
)

func (s *Service) rnd() io.Reader {
	if s.Rand != nil {
		return s.Rand
	}
	return rand.Reader
}

func (s *Service) now() time.Time { return s.Clock.Now().UTC().Truncate(time.Second) }

func (s *Service) limiter() *limiter {
	s.limitOnce.Do(func() { s.limits = &limiter{seen: map[string][]time.Time{}} })
	return s.limits
}

// authorize checks perm on the tenant for who.
func (s *Service) authorize(who keys.Who, perm authz.Permission) error {
	return who.Principal.Check(perm, authz.Resource{Tenant: s.Tenant}, s.Clock.Now())
}

// inTx runs fn in one pki.db transaction and wakes the audit delivery.
func (s *Service) inTx(ctx context.Context, fn func(q *pkidb.Queries, tx *sql.Tx) error) error {
	tx, err := s.PKI.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := fn(pkidb.New(tx), tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if s.Wake != nil {
		s.Wake()
	}
	return nil
}

// enqueue writes an audit entry in tx (the outbox of pki.db).
func enqueue(ctx context.Context, tx *sql.Tx, now time.Time, who keys.Who, action string, target audit.Target, details map[string]any) error {
	return audit.Enqueue(ctx, tx, now, audit.Entry{
		Time: now, Actor: who.Actor, Action: action, Target: target, Result: audit.ResultSuccess,
		SourceIP: who.SourceIP, Details: details,
	})
}

// refused audits a refused administrative action (not the anonymous ones:
// junk from outside must not fill the audit log).
func (s *Service) refused(ctx context.Context, who keys.Who, action string, target audit.Target, err error) error {
	if err == nil || errors.Is(err, ErrNotFound) {
		return err
	}
	now := s.now()
	result := audit.ResultFailure
	if errors.Is(err, authz.ErrDenied) || errors.Is(err, authz.ErrStepUpRequired) {
		result = audit.ResultDenied
	}
	if _, _, aerr := audit.Append(ctx, s.Engine.Audit, s.Engine.Scope, audit.Entry{
		Time: now, Actor: who.Actor, Action: action, Target: target, Result: result, SourceIP: who.SourceIP,
		Details: map[string]any{"error": clip(err.Error(), 300)},
	}, ""); aerr != nil {
		return errors.Join(err, fmt.Errorf("audit: %w", aerr))
	}
	return err
}

// agentWho is an admitted agent as the actor of its own requests.
func agentWho(a pkidb.Agent, sourceIP string) keys.Who {
	return keys.Who{
		Actor:     audit.Actor{Type: audit.ActorAgent, ID: a.ID, Name: a.Hostname},
		Principal: authz.System("agent"), SourceIP: sourceIP,
	}
}

func dbTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

func parseTime(s string) time.Time {
	t, _ := time.Parse("2006-01-02T15:04:05Z", s)
	return t
}

func nullTime(n sql.NullString) time.Time {
	if !n.Valid {
		return time.Time{}
	}
	return parseTime(n.String)
}

func nullString(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// limiter counts requests per key in a sliding window (in memory: a restart
// forgets, which is fine for a limit against floods).
type limiter struct {
	mu   sync.Mutex
	seen map[string][]time.Time
}

func (l *limiter) allow(key string, max int, window time.Duration, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.seen) > 10000 { // never grows without bound
		for k, ts := range l.seen {
			if len(ts) == 0 || now.Sub(ts[len(ts)-1]) > window {
				delete(l.seen, k)
			}
		}
	}
	kept := l.seen[key][:0]
	for _, t := range l.seen[key] {
		if now.Sub(t) < window {
			kept = append(kept, t)
		}
	}
	if len(kept) >= max {
		l.seen[key] = kept
		return false
	}
	l.seen[key] = append(kept, now)
	return true
}
