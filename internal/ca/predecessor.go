package ca

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/predecessor"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

const (
	ActionPlanRevocation   = "certificate.revocation.plan"
	ActionCancelRevocation = "certificate.revocation.cancel"
)

// PlanRevocationRequest schedules a final superseded revocation.
type PlanRevocationRequest struct {
	CertificateID string
	PlannedAt     time.Time
	Who           keys.Who
}

// PlanRevocation schedules a certificate without changing its validity state.
func (e *Engine) PlanRevocation(ctx context.Context, req PlanRevocationRequest) error {
	now := e.now()
	info, err := e.Certificate(ctx, req.Who, req.CertificateID)
	if err != nil {
		return err
	}
	if info.Status == CertRevoked {
		return deny("certificate %s is revoked already", info.ID)
	}
	if info.Source == "external" || info.CAID == "" {
		return deny("only a certificate issued by this PKI can be revoked")
	}
	if err := e.authorize(req.Who, authz.RevokeCert, info.CAName, now); err != nil {
		return err
	}
	if req.PlannedAt.IsZero() || !req.PlannedAt.After(now) {
		return deny("the planned revocation time must not be in the past")
	}
	if req.PlannedAt.After(now.Add(30 * 24 * time.Hour)) {
		return deny("the planned revocation must be within 30 days")
	}
	planned := req.PlannedAt.UTC().Truncate(time.Second)
	return e.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		n, err := q.InsertRevocationPlan(ctx, pkidb.InsertRevocationPlanParams{
			CertificateID: info.ID, PlannedAt: planned.Format(time.RFC3339), CreatedAt: now.Format(audit.TimeFormat),
			CreatedBy: requestedBy(req.Who), Source: "explicit",
		})
		if err != nil {
			return err
		}
		if n != 1 {
			return deny("a revocation is already planned; cancel it before choosing another time")
		}
		return audit.Enqueue(ctx, tx, now, audit.Entry{
			Time: now, Actor: req.Who.Actor, Action: ActionPlanRevocation, Target: audit.Target{Type: "certificate", ID: info.ID},
			Result: audit.ResultSuccess, SourceIP: req.Who.SourceIP,
			Details: map[string]any{"reason": ReasonSuperseded, "planned_at": planned.Format(time.RFC3339)},
		})
	})
}

// CancelRevocationPlan removes only the pending plan.
func (e *Engine) CancelRevocationPlan(ctx context.Context, who keys.Who, certificateID string) error {
	now := e.now()
	info, err := e.Certificate(ctx, who, certificateID)
	if err != nil {
		return err
	}
	if err := e.authorize(who, authz.RevokeCert, info.CAName, now); err != nil {
		return err
	}
	return e.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		n, err := q.DeleteRevocationPlan(ctx, info.ID)
		if err != nil {
			return err
		}
		if n != 1 {
			return deny("no revocation is planned for this certificate")
		}
		return audit.Enqueue(ctx, tx, now, audit.Entry{
			Time: now, Actor: who.Actor, Action: ActionCancelRevocation, Target: audit.Target{Type: "certificate", ID: info.ID},
			Result: audit.ResultSuccess, SourceIP: who.SourceIP, Details: map[string]any{"reason": ReasonSuperseded},
		})
	})
}

// ApplyPredecessor revokes or plans one already authorized predecessor in the
// caller's pki.db transaction. Existing plans are preserved. The returned
// revocations still need CRL publication after the transaction commits.
func (e *Engine) ApplyPredecessor(ctx context.Context, q *pkidb.Queries, tx *sql.Tx, certificateID, successorID string,
	policy predecessor.Policy, source string, who keys.Who, now time.Time) ([]*RevokeResult, error) {
	policy = policy.Normalize()
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	if policy.Choice == predecessor.Never {
		return nil, nil
	}
	row, err := q.GetCertificate(ctx, certificateID)
	if err != nil {
		return nil, err
	}
	if row.Source == "external" || !row.CaID.Valid {
		return nil, deny("only a certificate issued by this PKI can be revoked")
	}
	if _, revocationErr := q.GetRevocation(ctx, certificateID); revocationErr == nil {
		return nil, nil
	} else if !errors.Is(revocationErr, sql.ErrNoRows) {
		return nil, revocationErr
	}
	if policy.Choice == predecessor.After {
		planned := now.Add(time.Duration(policy.Days) * 24 * time.Hour).UTC().Truncate(time.Second)
		n, insertErr := q.InsertRevocationPlan(ctx, pkidb.InsertRevocationPlanParams{
			CertificateID: certificateID, SuccessorID: sql.NullString{String: successorID, Valid: successorID != ""},
			PlannedAt: planned.Format(time.RFC3339), CreatedAt: now.Format(audit.TimeFormat), CreatedBy: requestedBy(who), Source: source,
		})
		if insertErr != nil {
			return nil, insertErr
		}
		if n == 0 {
			return nil, nil
		}
		if auditErr := audit.Enqueue(ctx, tx, now, audit.Entry{
			Time: now, Actor: who.Actor, Action: ActionPlanRevocation, Target: audit.Target{Type: "certificate", ID: certificateID},
			Result: audit.ResultSuccess, SourceIP: who.SourceIP,
			Details: map[string]any{"reason": ReasonSuperseded, "planned_at": planned.Format(time.RFC3339), "successor_id": successorID, "source": source},
		}); auditErr != nil {
			return nil, auditErr
		}
		return nil, nil
	}
	result, err := e.revokeStored(ctx, q, tx, row, RevokeRequest{CertificateID: certificateID, Reason: ReasonSuperseded, Who: who}, now)
	if err != nil {
		return nil, err
	}
	return []*RevokeResult{result}, nil
}

// PublishPredecessorRevocations signs CRLs after the business transaction.
func (e *Engine) PublishPredecessorRevocations(ctx context.Context, revocations []*RevokeResult, who keys.Who) {
	for _, result := range revocations {
		e.publishAfterRevocation(ctx, result, result.caID, result.caGeneration, who)
	}
}

// ExecuteDueRevocations executes persisted plans. It is safe after a restart
// or unseal: stored revocations work while sealed and CRL publication catches
// up through the normal unseal/CRL jobs.
func (e *Engine) ExecuteDueRevocations(ctx context.Context) error {
	who := keys.Who{Actor: audit.Actor{Type: audit.ActorSystem, Name: "revocation-scheduler"}, Principal: authz.System("revocation-scheduler")}
	for {
		rows, err := pkidb.New(e.PKI).ListDueRevocationPlans(ctx, pkidb.ListDueRevocationPlansParams{PlannedAt: e.now().Format(time.RFC3339), Limit: 100})
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return nil
		}
		for _, plan := range rows {
			if _, err := e.Revoke(ctx, RevokeRequest{CertificateID: plan.CertificateID, Reason: ReasonSuperseded, Who: who}); err != nil {
				return fmt.Errorf("execute planned revocation for %s: %w", plan.CertificateID, err)
			}
		}
		if len(rows) < 100 {
			return nil
		}
	}
}

// RevocationsDue counts pending plans through the next seven days that the
// caller may read, including overdue plans not yet executed.
func (e *Engine) RevocationsDue(ctx context.Context, who keys.Who) (int64, error) {
	rows, err := pkidb.New(e.PKI).ListRevocationPlansBefore(ctx, e.now().Add(7*24*time.Hour).Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	var count int64
	for _, row := range rows {
		if _, err := e.Certificate(ctx, who, row.CertificateID); err == nil {
			count++
		} else if !errors.Is(err, ErrNotFound) {
			return 0, err
		}
	}
	return count, nil
}
