package agents

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/predecessor"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

const (
	// MaxDeployments bounds the configured inventory per agent.
	MaxDeployments = 100
	// MaxReportDeployments also admits one removed result to drain per report.
	MaxReportDeployments = MaxDeployments + 1
)

var deploymentName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$`)

// ReportInput is display data, with identity supplied only by mTLS.
type ReportInput struct {
	Version, OS, Arch string
	PackageFormat     string
	Deployments       []DeploymentReport
}

type DeploymentReport struct {
	Name, Profile                                                          string
	Names                                                                  []string
	Challenge, State, Serial, NotAfter, Fingerprint, DeployedAt, LastError string
	HandledRenewalVersion                                                  int64
}

// Deployment is the current reported state and an optional renewal request.
type Deployment struct {
	Name, Profile                                                   string
	Names                                                           []string
	Challenge, State, Serial, CertificateID, Fingerprint, LastError string
	NotAfter, DeployedAt, LastReportAt, RenewRequestedAt            time.Time
	RenewRequestedBy                                                string
	RenewalVersion                                                  int64
	Removed                                                         bool
	Predecessor                                                     *predecessor.Policy
	EffectivePolicy                                                 predecessor.Policy
	RevocationPlannedAt                                             *time.Time
}

func bounded(s string, limit int) bool {
	return len(s) <= limit && utf8.ValidString(s) && !strings.ContainsRune(s, 0)
}

func reportTime(s string) string {
	if s == "" {
		return ""
	}
	t, _ := time.Parse(time.RFC3339, s)
	return dbTime(t)
}

func validReport(in ReportInput) error {
	bad := fmt.Errorf("%w: report fields exceed their limits or contain invalid data", ErrInvalid)
	if !bounded(in.Version, 64) || !bounded(in.OS, 32) || !bounded(in.Arch, 32) || len(in.Deployments) > MaxReportDeployments {
		return bad
	}
	if in.PackageFormat != "" && !slices.Contains([]string{"deb", "rpm", "tarball"}, in.PackageFormat) {
		return bad
	}
	seen := map[string]bool{}
	for _, d := range in.Deployments {
		if !deploymentName.MatchString(d.Name) || seen[d.Name] || !bounded(d.Profile, 32) || !bounded(d.Challenge, 32) ||
			!slices.Contains([]string{"pending", "deployed", "failed", "rolled_back"}, d.State) || !bounded(d.LastError, 1024) ||
			len(d.Names) > 100 || d.HandledRenewalVersion < 0 {
			return bad
		}
		seen[d.Name] = true
		for _, name := range d.Names {
			if !bounded(name, 253) {
				return bad
			}
		}
		for _, value := range []string{d.NotAfter, d.DeployedAt} {
			if value != "" {
				if len(value) > 35 {
					return bad
				}
				if _, err := time.Parse(time.RFC3339, value); err != nil {
					return bad
				}
			}
		}
		for _, value := range []string{d.Serial, d.Fingerprint} {
			if len(value) > 64 || len(value)%2 != 0 {
				return bad
			}
			if _, err := hex.DecodeString(value); err != nil {
				return bad
			}
		}
		if d.Fingerprint != "" && len(d.Fingerprint) != 64 {
			return bad
		}
	}
	return nil
}

// Report replaces only this agent's inventory. No agent ID, path or hook
// can be provided by the sender. Heartbeats do not fill the audit log.
func (s *Service) Report(ctx context.Context, caller *Caller, in ReportInput) error {
	if !s.limiter().allow("report:"+caller.Agent.ID, reportPerWindow, 10*time.Minute, s.now()) {
		return ErrRateLimited
	}
	if err := validReport(in); err != nil {
		return err
	}
	tenantPolicy, err := s.tenantPredecessor(ctx)
	if err != nil {
		return err
	}
	changed := false
	var revocations []*ca.RevokeResult
	err = s.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		a, agentErr := q.GetAgent(ctx, caller.Agent.ID)
		if agentErr != nil {
			return agentErr
		}
		if a.Status != StatusActive {
			return ErrUnknownAgent
		}
		now := s.now()
		format := in.PackageFormat
		if format == "" {
			format = "tarball"
		}
		if uerr := q.UpdateAgentReport(ctx, pkidb.UpdateAgentReportParams{ID: a.ID, LastSeenAt: nullString(dbTime(now)),
			Os: in.OS, Arch: in.Arch, AgentVersion: in.Version, PackageFormat: format}); uerr != nil {
			return uerr
		}
		if merr := q.MarkAgentDeploymentsUnreported(ctx, a.ID); merr != nil {
			return merr
		}
		for _, d := range in.Deployments {
			old, getErr := q.GetAgentDeployment(ctx, pkidb.GetAgentDeploymentParams{AgentID: a.ID, Name: d.Name})
			if getErr != nil && !errors.Is(getErr, sql.ErrNoRows) {
				return getErr
			}
			policy := effectivePolicy(a, old, tenantPolicy)
			if d.HandledRenewalVersion > 0 && old.RenewRequestedVersion.Valid && old.RenewRequestedVersion.Int64 == d.HandledRenewalVersion && old.RenewPredecessorChoice.Valid {
				policy = predecessor.Policy{Choice: old.RenewPredecessorChoice.String, Days: int(old.RenewPredecessorDays.Int64)}.Normalize()
			}
			nj, _ := json.Marshal(d.Names)
			if uerr := q.UpsertAgentDeployment(ctx, pkidb.UpsertAgentDeploymentParams{AgentID: a.ID, Name: d.Name, Profile: d.Profile,
				Names: string(nj), Challenge: d.Challenge, State: d.State, CertificateSerial: nullString(strings.ToUpper(d.Serial)),
				NotAfter: nullString(reportTime(d.NotAfter)), ServedFingerprint: nullString(strings.ToLower(d.Fingerprint)), DeployedAt: nullString(reportTime(d.DeployedAt)),
				LastError: nullString(d.LastError), LastReportAt: dbTime(now)}); uerr != nil {
				return uerr
			}
			results, aerr := s.applyDeployed(ctx, q, tx, a, old, d, policy, now)
			if aerr != nil {
				return aerr
			}
			revocations = append(revocations, results...)
			if old.State != d.State {
				if aerr := enqueue(ctx, tx, now, caller.Who, "agent.deployment.state", audit.Target{Type: "agent", ID: a.ID},
					map[string]any{"deployment": d.Name, "state": d.State}); aerr != nil {
					return aerr
				}
			}
			if d.HandledRenewalVersion > 0 {
				n, cerr := q.ClearDeploymentRenewal(ctx, pkidb.ClearDeploymentRenewalParams{AgentID: a.ID, Name: d.Name,
					RenewRequestedVersion: sql.NullInt64{Int64: d.HandledRenewalVersion, Valid: true}})
				if cerr != nil {
					return cerr
				}
				changed = changed || n > 0
			}
		}
		if derr := q.DeleteUnreportedDeployments(ctx, a.ID); derr != nil {
			return derr
		}
		if changed {
			return q.BumpDesiredVersion(ctx, pkidb.BumpDesiredVersionParams{ID: a.ID, UpdatedAt: dbTime(now)})
		}
		return nil
	})
	if err == nil {
		s.Engine.PublishPredecessorRevocations(ctx, revocations, caller.Who)
	}
	if err == nil && changed {
		s.notify(caller.Agent.ID)
	}
	return err
}

// RequestRenewal records an operator's request and snapshots its predecessor
// policy, never executable input. An omitted override uses the effective policy.
func (s *Service) RequestRenewal(ctx context.Context, who keys.Who, id, name string, overrides ...predecessor.Policy) error {
	err := s.requestRenewal(ctx, who, id, name, overrides...)
	if err == nil {
		s.notify(id)
	}
	return s.refused(ctx, who, "agent.renew.request", audit.Target{Type: "agent", ID: id}, err)
}

func (s *Service) requestRenewal(ctx context.Context, who keys.Who, id, name string, overrides ...predecessor.Policy) error {
	if err := s.authorize(who, authz.RenewAgent); err != nil {
		return err
	}
	if err := s.authorize(who, authz.RevokeCert); err != nil {
		return err
	}
	if !deploymentName.MatchString(name) || len(overrides) > 1 {
		return ErrNotFound
	}
	tenantPolicy, err := s.tenantPredecessor(ctx)
	if err != nil {
		return err
	}
	var override *predecessor.Policy
	if len(overrides) == 1 {
		policy := overrides[0].Normalize()
		if err := policy.Validate(); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalid, err)
		}
		override = &policy
	}
	return s.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		a, err := q.GetAgent(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if a.Status != StatusActive {
			return fmt.Errorf("%w: the agent is not active", ErrConflict)
		}
		d, err := q.GetAgentDeployment(ctx, pkidb.GetAgentDeploymentParams{AgentID: id, Name: name})
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if d.RenewRequestedAt.Valid {
			return fmt.Errorf("%w: renewal is already requested", ErrConflict)
		}
		policy := effectivePolicy(a, d, tenantPolicy)
		if override != nil {
			policy = *override
		}
		now := s.now()
		if berr := q.BumpDesiredVersion(ctx, pkidb.BumpDesiredVersionParams{ID: id, UpdatedAt: dbTime(now)}); berr != nil {
			return berr
		}
		n, err := q.RequestDeploymentRenewal(ctx, pkidb.RequestDeploymentRenewalParams{AgentID: id, Name: name,
			RenewRequestedAt: nullString(dbTime(now)), RenewRequestedBy: nullString(who.Actor.Name),
			RenewRequestedVersion:  sql.NullInt64{Int64: a.DesiredVersion + 1, Valid: true},
			RenewPredecessorChoice: nullString(policy.Choice), RenewPredecessorDays: nullInt64(policy.Days)})
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrConflict
		}
		details := map[string]any{"deployment": name, "predecessor_choice": policy.Choice}
		if policy.Choice == predecessor.After {
			details["predecessor_days"] = policy.Days
		}
		return enqueue(ctx, tx, now, who, "agent.renew.request", audit.Target{Type: "agent", ID: id}, details)
	})
}

// WithdrawRenewal removes an open request and wakes a waiting agent. A result
// already in flight is harmless: its version no longer matches an open row.
func (s *Service) WithdrawRenewal(ctx context.Context, who keys.Who, id, name string) error {
	err := s.withdrawRenewal(ctx, who, id, name)
	if err == nil {
		s.notify(id)
	}
	return s.refused(ctx, who, "agent.renew.withdraw", audit.Target{Type: "agent", ID: id}, err)
}

func (s *Service) withdrawRenewal(ctx context.Context, who keys.Who, id, name string) error {
	if err := s.authorize(who, authz.RenewAgent); err != nil {
		return err
	}
	if !deploymentName.MatchString(name) {
		return ErrNotFound
	}
	return s.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		d, err := q.GetAgentDeployment(ctx, pkidb.GetAgentDeploymentParams{AgentID: id, Name: name})
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if !d.RenewRequestedAt.Valid {
			return fmt.Errorf("%w: no renewal is requested", ErrConflict)
		}
		now := s.now()
		if berr := q.BumpDesiredVersion(ctx, pkidb.BumpDesiredVersionParams{ID: id, UpdatedAt: dbTime(now)}); berr != nil {
			return berr
		}
		n, err := q.WithdrawDeploymentRenewal(ctx, pkidb.WithdrawDeploymentRenewalParams{AgentID: id, Name: name})
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrConflict
		}
		return enqueue(ctx, tx, now, who, "agent.renew.withdraw", audit.Target{Type: "agent", ID: id}, map[string]any{"deployment": name})
	})
}

func (s *Service) deployments(ctx context.Context, id string) ([]Deployment, error) {
	q := pkidb.New(s.PKI)
	a, err := q.GetAgent(ctx, id)
	if err != nil {
		return nil, err
	}
	tenantPolicy, err := s.tenantPredecessor(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := q.ListAgentDeployments(ctx, id)
	if err != nil {
		return nil, err
	}
	planRows, err := q.ListRevocationPlansForAgent(ctx, id)
	if err != nil {
		return nil, err
	}
	plans := map[string]time.Time{}
	for _, row := range planRows {
		planned := parseTime(row.CertificateRevocationPlan.PlannedAt)
		if current, ok := plans[row.Deployment]; !ok || planned.Before(current) {
			plans[row.Deployment] = planned
		}
	}
	out := make([]Deployment, 0, len(rows))
	for _, row := range rows {
		d := Deployment{Name: row.Name, Profile: row.Profile, Challenge: row.Challenge, State: row.State, Serial: row.CertificateSerial.String,
			Fingerprint: row.ServedFingerprint.String, LastError: row.LastError.String, NotAfter: parseTime(row.NotAfter.String),
			DeployedAt: parseTime(row.DeployedAt.String), LastReportAt: parseTime(row.LastReportAt),
			RenewRequestedAt: parseTime(row.RenewRequestedAt.String), RenewRequestedBy: row.RenewRequestedBy.String,
			RenewalVersion: row.RenewRequestedVersion.Int64, Removed: row.Reported == 0,
			Predecessor: policyFromRow(row.PredecessorChoice, row.PredecessorDays), EffectivePolicy: effectivePolicy(a, row, tenantPolicy)}
		if planned, ok := plans[row.Name]; ok {
			d.RevocationPlannedAt = &planned
		}
		_ = json.Unmarshal([]byte(row.Names), &d.Names)
		if d.Serial != "" {
			ids, err := q.AgentCertificatesBySerial(ctx, pkidb.AgentCertificatesBySerialParams{AgentID: nullString(id), SerialHex: d.Serial})
			if err != nil {
				return nil, err
			}
			if len(ids) == 1 {
				d.CertificateID = ids[0]
			}
		}
		out = append(out, d)
	}
	return out, nil
}

// Silent reports three missed five-minute reports, including a host that
// has never reported since admission.
func (a Agent) Silent(now time.Time) bool {
	last := a.LastSeenAt
	if last.IsZero() {
		last = a.ApprovedAt
	}
	return a.Status == StatusActive && now.Sub(last) >= 15*time.Minute
}
