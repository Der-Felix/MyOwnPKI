package agents

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// RegisterACMEAccount reserves the account key for an authenticated agent.
// The ACME request itself later proves possession of that key and binds
// the account. A reservation never transfers another agent's account.
func (s *Service) RegisterACMEAccount(ctx context.Context, c *Caller, thumbprint string) error {
	b, decodeErr := base64.RawURLEncoding.Strict().DecodeString(thumbprint)
	if decodeErr != nil || len(b) != 32 {
		return fmt.Errorf("%w: key_thumbprint: a base64url SHA-256 JWK thumbprint", ErrInvalid)
	}
	var refusal error
	txErr := s.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		a, err := q.GetAgent(ctx, c.Agent.ID)
		if err != nil {
			return err
		}
		if a.Status != StatusActive {
			return ErrUnknownAgent
		}
		if a.AcmeKeyThumbprint.Valid && a.AcmeKeyThumbprint.String == thumbprint {
			return nil // a repeat of the original reservation, even after newAccount
		}
		deny := func(reason string) error {
			refusal = fmt.Errorf("%w: %s", ErrConflict, reason)
			now := s.now()
			return audit.Enqueue(ctx, tx, now, audit.Entry{
				Time: now, Actor: c.Who.Actor, Action: "agent.acme.register", Target: audit.Target{Type: "agent", ID: a.ID},
				Result: audit.ResultDenied, SourceIP: c.Who.SourceIP,
				Details: map[string]any{"key_thumbprint": thumbprint, "reason": reason},
			})
		}
		if other, err := q.GetAgentByACMEThumbprint(ctx, nullString(thumbprint)); err == nil && other.ID != a.ID {
			return deny("the ACME key belongs to another agent")
		} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		// A thumbprint is public in http-01 responses. Reserving an
		// existing unlinked account would let an agent capture that account.
		if _, err := q.GetACMEAccountByThumbprint(ctx, thumbprint); err == nil {
			return deny("an ACME account already exists for this key; reserve a new key before creating its account")
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if a.AcmeKeyThumbprint.Valid {
			return deny("an ACME key is registered already; rotate it with ACME keyChange")
		}
		now := s.now()
		if err := q.SetAgentACMEThumbprint(ctx, pkidb.SetAgentACMEThumbprintParams{
			AcmeKeyThumbprint: nullString(thumbprint), UpdatedAt: dbTime(now), ID: a.ID,
		}); err != nil {
			return err
		}
		return enqueue(ctx, tx, now, c.Who, "agent.acme.register", audit.Target{Type: "agent", ID: a.ID},
			map[string]any{"key_thumbprint": thumbprint})
	})
	if txErr != nil {
		return txErr
	}
	return refusal // commit a denial's outbox entry before returning the refusal
}
