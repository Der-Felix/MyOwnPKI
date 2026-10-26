package agents

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/predecessor"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

const ActionPredecessor = "agent.predecessor"

func policyFromRow(choice sql.NullString, days sql.NullInt64) *predecessor.Policy {
	if !choice.Valid {
		return nil
	}
	return &predecessor.Policy{Choice: choice.String, Days: int(days.Int64)}
}

func (s *Service) tenantPredecessor(ctx context.Context) (predecessor.Policy, error) {
	if s.AgentPredecessor == nil {
		return predecessor.DefaultAgent, nil
	}
	policy, err := s.AgentPredecessor(ctx)
	if err != nil {
		return predecessor.Policy{}, err
	}
	return policy.Normalize(), policy.Validate()
}

func effectivePolicy(a pkidb.Agent, d pkidb.AgentDeployment, tenant predecessor.Policy) predecessor.Policy {
	policy := tenant
	if override := policyFromRow(a.PredecessorChoice, a.PredecessorDays); override != nil {
		policy = *override
	}
	if override := policyFromRow(d.PredecessorChoice, d.PredecessorDays); override != nil {
		policy = *override
	}
	return policy.Normalize()
}

// SetPredecessorPolicy sets or clears an agent or deployment override. An
// empty deployment selects the agent-wide override.
func (s *Service) SetPredecessorPolicy(ctx context.Context, who keys.Who, id, deployment string, policy *predecessor.Policy) error {
	if err := s.authorize(who, authz.ManageAgents); err != nil {
		return err
	}
	if policy != nil {
		normalized := policy.Normalize()
		if err := normalized.Validate(); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalid, err)
		}
		policy = &normalized
	}
	now := s.now()
	err := s.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		if _, err := q.GetAgent(ctx, id); errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		choice, days := nullString(""), nullInt64(0)
		if policy != nil {
			choice = nullString(policy.Choice)
			if policy.Choice == predecessor.After {
				days = nullInt64(policy.Days)
			}
		}
		var n int64
		var err error
		if deployment == "" {
			n, err = q.SetAgentPredecessorPolicy(ctx, pkidb.SetAgentPredecessorPolicyParams{
				PredecessorChoice: choice, PredecessorDays: days, UpdatedAt: dbTime(now), ID: id,
			})
		} else {
			if !deploymentName.MatchString(deployment) {
				return ErrNotFound
			}
			n, err = q.SetDeploymentPredecessorPolicy(ctx, pkidb.SetDeploymentPredecessorPolicyParams{
				PredecessorChoice: choice, PredecessorDays: days, AgentID: id, Name: deployment,
			})
		}
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrNotFound
		}
		details := map[string]any{"deployment": deployment, "inherit": policy == nil}
		if policy != nil {
			details["choice"] = policy.Choice
			if policy.Choice == predecessor.After {
				details["days"] = policy.Days
			}
		}
		return enqueue(ctx, tx, now, who, ActionPredecessor, audit.Target{Type: "agent", ID: id}, details)
	})
	return s.refused(ctx, who, ActionPredecessor, audit.Target{Type: "agent", ID: id}, err)
}

func nullInt64(v int) sql.NullInt64 {
	if v == 0 {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(v), Valid: true}
}

// applyDeployed records exact history and handles predecessors only for a
// real serial transition to deployed. Mapping failures are deliberately not
// report failures: the replacement stays valid and no other certificate is touched.
//
//nolint:nilerr // Ambiguous untrusted mappings skip predecessor action without failing the report.
func (s *Service) applyDeployed(ctx context.Context, q *pkidb.Queries, tx *sql.Tx, a pkidb.Agent, old pkidb.AgentDeployment,
	d DeploymentReport, policy predecessor.Policy, now time.Time) ([]*ca.RevokeResult, error) {
	if d.State != "deployed" || d.Serial == "" || d.Fingerprint == "" {
		return nil, nil
	}
	ids, err := q.AgentCertificatesBySerial(ctx, pkidb.AgentCertificatesBySerialParams{AgentID: nullString(a.ID), SerialHex: strings.ToUpper(d.Serial)})
	if err != nil {
		return nil, err
	}
	if len(ids) != 1 {
		s.ambiguous(a, d, "reported serial does not map to one certificate of the agent account")
		return nil, nil
	}
	orders, err := q.ListAgentCertificateOrders(ctx, ids[0])
	if err != nil {
		return nil, err
	}
	if len(orders) != 1 || !strings.EqualFold(orders[0].FingerprintSha256, d.Fingerprint) {
		s.ambiguous(a, d, "certificate order or served fingerprint is not unique and exact")
		return nil, nil
	}
	account, err := q.GetACMEAccountByAgentID(ctx, nullString(a.ID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			s.ambiguous(a, d, "agent has no linked ACME account")
			return nil, nil
		}
		return nil, err
	}
	if orders[0].AccountID != account.ID {
		s.ambiguous(a, d, "certificate belongs to another ACME account")
		return nil, nil
	}
	names, nameErr := ca.DeploymentNameSet(d.Names)
	if nameErr != nil {
		s.ambiguous(a, d, "invalid deployment name set")
		return nil, nil
	}
	same, sameErr := ca.SameACMENameSet(orders[0].Identifiers, names)
	if sameErr != nil {
		s.ambiguous(a, d, "invalid order identifiers")
		return nil, nil
	}
	if !same {
		s.ambiguous(a, d, "order and deployment name sets differ")
		return nil, nil
	}
	if historyErr := q.UpsertAgentDeploymentCertificate(ctx, pkidb.UpsertAgentDeploymentCertificateParams{
		AgentID: a.ID, Deployment: d.Name, CertificateID: ids[0], FirstDeployedAt: dbTime(now), LastDeployedAt: dbTime(now),
	}); historyErr != nil {
		return nil, historyErr
	}
	if old.CertificateSerial.Valid && strings.EqualFold(old.CertificateSerial.String, d.Serial) {
		return nil, nil
	}
	if policy.Choice == predecessor.Never {
		return nil, nil
	}
	serving, err := q.ListAgentServingCertificateIDs(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	excluded := make(map[string]bool, len(serving)+1)
	for _, id := range serving {
		excluded[id] = true
	}
	excluded[ids[0]] = true
	rows, err := q.ListAgentPredecessorCandidates(ctx, pkidb.ListAgentPredecessorCandidatesParams{ID: account.ID, CreatedAt: orders[0].CreatedAt})
	if err != nil {
		return nil, err
	}
	type match struct {
		id        string
		duplicate bool
	}
	matches := map[string]*match{}
	for _, row := range rows {
		if excluded[row.ID] {
			continue
		}
		same, err := ca.SameACMENameSet(row.Identifiers, names)
		if err != nil {
			s.ambiguous(a, d, "invalid older order identifiers")
			continue
		}
		if !same {
			continue
		}
		if matches[row.ID] == nil {
			matches[row.ID] = &match{id: row.ID}
		} else {
			matches[row.ID].duplicate = true
		}
	}
	var revocations []*ca.RevokeResult
	for _, candidate := range matches {
		if candidate.duplicate {
			s.ambiguous(a, d, "older certificate has multiple order mappings")
			continue
		}
		results, err := s.Engine.ApplyPredecessor(ctx, q, tx, candidate.id, ids[0], policy, "agent", agentWho(a, ""), now)
		if err != nil {
			return nil, err
		}
		revocations = append(revocations, results...)
	}
	return revocations, nil
}

func (s *Service) ambiguous(a pkidb.Agent, d DeploymentReport, reason string) {
	if s.Log != nil {
		s.Log.Warn("ambiguous agent predecessor mapping", slog.String("agent", a.ID), slog.String("deployment", d.Name), slog.String("reason", reason))
	}
}
