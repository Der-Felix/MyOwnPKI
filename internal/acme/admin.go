package acme

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// Admin actions on the ACME server (PHASE2 step 13): approvals and EAB
// keys. They need ca.manage on the tenant – with a fresh second factor –
// because an approval lets an account obtain certificates.

func (s *Server) authorize(who keys.Who) error {
	tenant := strings.TrimPrefix(s.engine.Scope, "tenant:")
	if err := who.Principal.Check(authz.ManageCA, authz.Resource{Tenant: tenant}, s.clk.Now()); err != nil {
		return &ca.DeniedError{Reasons: []string{err.Error()}, Cause: err}
	}
	return nil
}

// ErrNotFound: no such account, name or key.
var ErrNotFound = errors.New("not found")

// ApproveAccount lets an account order under the approval level "account".
func (s *Server) ApproveAccount(ctx context.Context, id string, who keys.Who) error {
	if err := s.authorize(who); err != nil {
		return err
	}
	now := s.now()
	return s.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		acct, err := q.GetACMEAccount(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if acct.Status != "valid" {
			return &ca.DeniedError{Reasons: []string{fmt.Sprintf("account %s is %s", id, acct.Status)}}
		}
		n, err := q.ApproveACMEAccount(ctx, pkidb.ApproveACMEAccountParams{
			ApprovedAt: sql.NullString{String: dbTime(now), Valid: true}, ApprovedBy: sql.NullString{String: who.Actor.Name, Valid: true},
			UpdatedAt: dbTime(now), ID: id,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return &ca.DeniedError{Reasons: []string{fmt.Sprintf("account %s is approved already", id)}}
		}
		return audit.Enqueue(ctx, tx, now, audit.Entry{
			Time: now, Actor: who.Actor, Action: ActionAccountApprove, Target: audit.Target{Type: "acme_account", ID: id},
			Result: audit.ResultSuccess, SourceIP: who.SourceIP, Details: map[string]any{"key_thumbprint": acct.KeyThumbprint},
		})
	})
}

// DecideName approves or refuses a name waiting under "new_name" ("dns:x"
// or "ip:x"). Approving a name nobody asked for yet is allowed too.
func (s *Server) DecideName(ctx context.Context, name string, approve bool, who keys.Who) error {
	if err := s.authorize(who); err != nil {
		return err
	}
	if !strings.HasPrefix(name, "dns:") && !strings.HasPrefix(name, "ip:") {
		return &ca.DeniedError{Reasons: []string{fmt.Sprintf("%q is not dns:<name> or ip:<address>", clip(name))}}
	}
	now := s.now()
	status := "refused"
	if approve {
		status = "approved"
	}
	return s.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		n, err := q.DecideACMEName(ctx, pkidb.DecideACMENameParams{Status: status, DecidedBy: sql.NullString{String: who.Actor.Name, Valid: true}, DecidedAt: sql.NullString{String: dbTime(now), Valid: true}, Name: name})
		if err != nil {
			return err
		}
		if n == 0 {
			if !approve {
				return ErrNotFound
			}
			if aerr := q.ApproveACMENameDirectly(ctx, pkidb.ApproveACMENameDirectlyParams{
				Name: name, RequestedBy: who.Actor.Name, RequestedAt: dbTime(now),
				DecidedBy: sql.NullString{String: who.Actor.Name, Valid: true}, DecidedAt: sql.NullString{String: dbTime(now), Valid: true},
			}); aerr != nil {
				return aerr
			}
		}
		return audit.Enqueue(ctx, tx, now, audit.Entry{
			Time: now, Actor: who.Actor, Action: ActionNameDecide, Target: audit.Target{Type: "acme_name", ID: name},
			Result: audit.ResultSuccess, SourceIP: who.SourceIP, Details: map[string]any{"decision": status},
		})
	})
}
