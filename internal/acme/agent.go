package acme

import (
	"context"
	"database/sql"
	"errors"
	"net/http"

	"github.com/Der-Felix/MyOwnPKI/internal/agents"
	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// bindVerifiedAccount runs only in newAccount, after verifying its JWS.
// It handles a restart after creating the account but before returning
// its registration. Unreserved accounts keep their old behavior.
func (s *Server) bindVerifiedAccount(ctx context.Context, account *pkidb.AcmeAccount) error {
	if account.AgentID.Valid {
		return nil
	}
	if _, err := pkidb.New(s.db).GetAgentByACMEThumbprint(ctx, sql.NullString{String: account.KeyThumbprint, Valid: true}); errors.Is(err, sql.ErrNoRows) {
		return nil
	} else if err != nil {
		return err
	}
	return s.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		current, err := q.GetACMEAccount(ctx, account.ID)
		if err != nil {
			return err
		}
		if err := s.bindAccount(ctx, q, tx, &current); err != nil {
			return err
		}
		*account = current
		return nil
	})
}

func (s *Server) bindAccount(ctx context.Context, q *pkidb.Queries, tx *sql.Tx, account *pkidb.AcmeAccount) error {
	a, err := q.GetAgentByACMEThumbprint(ctx, sql.NullString{String: account.KeyThumbprint, Valid: true})
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if account.AgentID.Valid {
		if account.AgentID.String != a.ID {
			return problemErr(http.StatusForbidden, "unauthorized", "the account key is bound to another agent")
		}
		return nil
	}
	now := s.now()
	if err := q.BindACMEAccount(ctx, pkidb.BindACMEAccountParams{
		AgentID: sql.NullString{String: a.ID, Valid: true}, ApprovedAt: sql.NullString{String: dbTime(now), Valid: true},
		ApprovedBy: sql.NullString{String: "agent:" + a.ID, Valid: true}, UpdatedAt: dbTime(now), ID: account.ID,
	}); err != nil {
		return err
	}
	account.AgentID = sql.NullString{String: a.ID, Valid: true}
	if !account.ApprovedAt.Valid {
		account.ApprovedAt = sql.NullString{String: dbTime(now), Valid: true}
		account.ApprovedBy = sql.NullString{String: "agent:" + a.ID, Valid: true}
	}
	return enqueue(ctx, tx, now, account.ID, "", "acme.account.bind_agent", audit.Target{Type: "acme_account", ID: account.ID}, audit.ResultSuccess,
		map[string]any{"agent": a.ID, "key_thumbprint": account.KeyThumbprint})
}

// checkAgentOrder is additional policy for linked accounts only. Every
// source of agent_names is approved for new_name, but domain coverage,
// challenges, CA constraints and validity still apply normally.
func (s *Server) checkAgentOrder(ctx context.Context, db pkidb.DBTX, account *pkidb.AcmeAccount, ids []identifier) error {
	q := pkidb.New(db)
	current, err := q.GetACMEAccount(ctx, account.ID)
	if err != nil {
		return err
	}
	account = &current
	if !account.AgentID.Valid {
		return nil
	}
	a, err := q.GetAgent(ctx, account.AgentID.String)
	if err != nil {
		return err
	}
	if a.Status != agents.StatusActive {
		return problemErr(http.StatusForbidden, "unauthorized", "the agent of this ACME account is %s", a.Status)
	}
	rows, err := q.ListAgentNames(ctx, a.ID)
	if err != nil {
		return err
	}
	patterns := make([]string, 0, len(rows))
	for _, row := range rows {
		patterns = append(patterns, row.Pattern)
	}
	for _, raw := range ids {
		id, err := normalize(raw)
		if err != nil {
			return err
		}
		if id.Type != "dns" || !agents.MatchesAny(patterns, id.Value) {
			return problemErr(http.StatusBadRequest, "rejectedIdentifier", "%s is not in this agent's allowed names", clip(id.Value))
		}
	}
	return nil
}
