package agents

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// Enrollment is an enrollment as the approval queue shows it.
type Enrollment struct {
	ID, Hostname, State         string
	AgentID                     string // set when admitted, and for a known agent
	CheckMethod, CheckState     string
	CheckError                  string
	TokenValid                  bool
	TokenProblem                string
	KnownAgent                  bool
	OS, Arch, Version, SourceIP string
	CreatedAt, ExpiresAt        time.Time
	DecidedAt                   time.Time // zero = open
	DecidedBy                   string
}

// ListAgents returns every agent, by hostname.
func (s *Service) ListAgents(ctx context.Context, who keys.Who) ([]Agent, error) {
	if err := s.authorize(who, authz.ReadPKI); err != nil {
		return nil, err
	}
	rows, err := pkidb.New(s.PKI).ListAgents(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Agent, 0, len(rows))
	for _, r := range rows {
		out = append(out, toAgent(r))
	}
	return out, nil
}

// GetAgent returns one agent with its names.
func (s *Service) GetAgent(ctx context.Context, who keys.Who, id string) (*Agent, error) {
	if err := s.authorize(who, authz.ReadPKI); err != nil {
		return nil, err
	}
	q := pkidb.New(s.PKI)
	r, err := q.GetAgent(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	a := toAgent(r)
	tenantPolicy, err := s.tenantPredecessor(ctx)
	if err != nil {
		return nil, err
	}
	a.EffectivePolicy = effectivePolicy(r, pkidb.AgentDeployment{}, tenantPolicy)
	names, err := q.ListAgentNames(ctx, id)
	if err != nil {
		return nil, err
	}
	for _, n := range names {
		a.Names = append(a.Names, Name{Pattern: n.Pattern, Source: n.Source, AddedBy: n.AddedBy, AddedAt: parseTime(n.AddedAt)})
	}
	a.Deployments, err = s.deployments(ctx, id)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// ListEnrollments returns the open enrollments (the approval queue), or
// the last 200 of any state.
func (s *Service) ListEnrollments(ctx context.Context, who keys.Who, openOnly bool) ([]Enrollment, error) {
	if err := s.authorize(who, authz.ReadPKI); err != nil {
		return nil, err
	}
	q := pkidb.New(s.PKI)
	if _, err := q.ExpireEnrollments(ctx, dbTime(s.now())); err != nil {
		return nil, err
	}
	var rows []pkidb.AgentEnrollment
	var err error
	if openOnly {
		rows, err = q.ListOpenEnrollments(ctx)
	} else {
		rows, err = q.ListEnrollments(ctx, 200)
	}
	if err != nil {
		return nil, err
	}
	out := make([]Enrollment, 0, len(rows))
	for _, r := range rows {
		out = append(out, toEnrollment(r))
	}
	return out, nil
}

// Approve admits an enrollment from the queue (like `salt-key -A`).
func (s *Service) Approve(ctx context.Context, who keys.Who, enrollmentID string) error {
	return s.refused(ctx, who, ActionAdmit, audit.Target{Type: "agent_enrollment", ID: enrollmentID}, s.approve(ctx, who, enrollmentID))
}

func (s *Service) approve(ctx context.Context, who keys.Who, id string) error {
	if err := s.authorize(who, authz.ManageAgents); err != nil {
		return err
	}
	row, err := pkidb.New(s.PKI).GetEnrollment(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if row.State != StatePending {
		return fmt.Errorf("%w: this enrollment is %s – only one in the approval queue can be approved", ErrConflict, row.State)
	}
	mode, err := s.Mode(ctx)
	if err != nil {
		return err
	}
	return s.admit(ctx, id, mode, who.Actor.Name, who)
}

// Deny refuses an enrollment from the queue; the agent learns it at its
// next poll.
func (s *Service) Deny(ctx context.Context, who keys.Who, enrollmentID string) error {
	return s.refused(ctx, who, ActionDeny, audit.Target{Type: "agent_enrollment", ID: enrollmentID}, s.deny(ctx, who, enrollmentID))
}

func (s *Service) deny(ctx context.Context, who keys.Who, id string) error {
	if err := s.authorize(who, authz.ManageAgents); err != nil {
		return err
	}
	now := s.now()
	return s.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		row, err := q.GetEnrollment(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		n, err := q.DecideEnrollment(ctx, pkidb.DecideEnrollmentParams{
			State: StateDenied, AgentID: row.AgentID, DecidedAt: nullString(dbTime(now)), DecidedBy: nullString(who.Actor.Name), ID: id,
		})
		if err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("%w: this enrollment is %s", ErrConflict, row.State)
		}
		return enqueue(ctx, tx, now, who, ActionDeny, audit.Target{Type: "agent_enrollment", ID: id}, map[string]any{"hostname": row.Hostname})
	})
}

// SetDisabled disables an active agent or enables a disabled one. A
// disabled agent is cut off at its next call; its certificates stay valid.
func (s *Service) SetDisabled(ctx context.Context, who keys.Who, id string, disabled bool) error {
	action := ActionEnable
	if disabled {
		action = ActionDisable
	}
	err := s.setDisabled(ctx, who, id, disabled, action)
	if err == nil {
		s.notify(id)
	}
	return s.refused(ctx, who, action, audit.Target{Type: "agent", ID: id}, err)
}

func (s *Service) setDisabled(ctx context.Context, who keys.Who, id string, disabled bool, action string) error {
	if err := s.authorize(who, authz.ManageAgents); err != nil {
		return err
	}
	from, to := StatusDisabled, StatusActive
	if disabled {
		from, to = StatusActive, StatusDisabled
	}
	now := s.now()
	return s.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		a, err := q.GetAgent(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if a.Status != from {
			return fmt.Errorf("%w: agent %s is %s", ErrConflict, a.Hostname, a.Status)
		}
		if _, err := q.SetAgentStatus(ctx, pkidb.SetAgentStatusParams{Status: to, UpdatedAt: dbTime(now), ID: id}); err != nil {
			return err
		}
		return enqueue(ctx, tx, now, who, action, audit.Target{Type: "agent", ID: id}, map[string]any{"hostname": a.Hostname})
	})
}

// Revoke cuts an agent off for good: the status first (it takes effect at
// the agent's next call), then its agent certificates go on the agent CA's
// CRL. The certificates it deployed stay valid – revoking them would take
// services down; that is a separate step (owner 2026-10-24).
func (s *Service) Revoke(ctx context.Context, who keys.Who, id string) error {
	return s.refused(ctx, who, ActionRevoke, audit.Target{Type: "agent", ID: id}, s.revoke(ctx, who, id))
}

func (s *Service) revoke(ctx context.Context, who keys.Who, id string) error {
	if err := s.authorize(who, authz.ManageAgents); err != nil {
		return err
	}
	now := s.now()
	var a pkidb.Agent
	err := s.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		var err error
		a, err = q.GetAgent(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if a.Status == StatusRevoked {
			return fmt.Errorf("%w: agent %s is revoked already", ErrConflict, a.Hostname)
		}
		if _, err := q.SetAgentStatus(ctx, pkidb.SetAgentStatusParams{Status: StatusRevoked, UpdatedAt: dbTime(now), ID: id}); err != nil {
			return err
		}
		return enqueue(ctx, tx, now, who, ActionRevoke, audit.Target{Type: "agent", ID: id}, map[string]any{"hostname": a.Hostname})
	})
	if err != nil {
		return err
	}
	var errs []error
	s.notify(id)
	for _, cert := range []sql.NullString{a.CertID, a.PrevCertID} {
		if !cert.Valid {
			continue
		}
		_, rerr := s.Engine.Revoke(ctx, ca.RevokeRequest{CertificateID: cert.String, Reason: ca.ReasonCessationOfOperation, Who: who})
		var d *ca.DeniedError
		if rerr != nil && !errors.As(rerr, &d) { // already revoked or expired: nothing left to do
			errs = append(errs, rerr)
		}
	}
	if len(errs) > 0 {
		s.Log.Error("agent revoked, but not all of its certificates are on the CRL", slog.String("agent", id), slog.Any("error", errors.Join(errs...)))
		return fmt.Errorf("agent %s is revoked and cut off, but a certificate could not be put on the CRL: %w", a.Hostname, errors.Join(errs...))
	}
	return nil
}

// AddName lets an agent order for one more name or pattern.
func (s *Service) AddName(ctx context.Context, who keys.Who, id, pattern string) error {
	err := s.changeName(ctx, who, id, pattern, true)
	if err == nil {
		s.notify(id)
	}
	return s.refused(ctx, who, ActionNames, audit.Target{Type: "agent", ID: id}, err)
}

// RemoveName takes a name or pattern from an agent's list.
func (s *Service) RemoveName(ctx context.Context, who keys.Who, id, pattern string) error {
	err := s.changeName(ctx, who, id, pattern, false)
	if err == nil {
		s.notify(id)
	}
	return s.refused(ctx, who, ActionNames, audit.Target{Type: "agent", ID: id}, err)
}

func (s *Service) changeName(ctx context.Context, who keys.Who, id, pattern string, add bool) error {
	if err := s.authorize(who, authz.ManageAgents); err != nil {
		return err
	}
	p, err := CheckPattern(pattern)
	if err != nil {
		return err
	}
	now := s.now()
	return s.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		a, err := q.GetAgent(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if add {
			names, lerr := q.ListAgentNames(ctx, id)
			if lerr != nil {
				return lerr
			}
			if len(names) >= 200 {
				return fmt.Errorf("%w: an agent has at most 200 names – use a pattern such as *.homelab.lan", ErrInvalid)
			}
			if ierr := q.InsertAgentName(ctx, pkidb.InsertAgentNameParams{AgentID: id, Pattern: p, Source: "admin", AddedBy: who.Actor.Name, AddedAt: dbTime(now)}); ierr != nil {
				return ierr
			}
		} else {
			n, derr := q.DeleteAgentName(ctx, pkidb.DeleteAgentNameParams{AgentID: id, Pattern: p})
			if derr != nil {
				return derr
			}
			if n != 1 {
				return ErrNotFound
			}
		}
		if berr := q.BumpDesiredVersion(ctx, pkidb.BumpDesiredVersionParams{UpdatedAt: dbTime(now), ID: id}); berr != nil {
			return berr
		}
		change := "removed"
		if add {
			change = "added"
		}
		return enqueue(ctx, tx, now, who, ActionNames, audit.Target{Type: "agent", ID: id}, map[string]any{"hostname": a.Hostname, "name": p, "change": change})
	})
}

func toAgent(r pkidb.Agent) Agent {
	return Agent{
		ID: r.ID, Hostname: r.Hostname, Status: r.Status, EnrollmentMode: r.EnrollmentMode, Proof: r.Proof,
		CertificateID: r.CertID.String, CertSerial: r.CertSerial.String, OS: r.Os, Arch: r.Arch, Version: r.AgentVersion, PackageFormat: r.PackageFormat,
		LastSeenAt: nullTime(r.LastSeenAt), CreatedAt: parseTime(r.CreatedAt), ApprovedAt: parseTime(r.ApprovedAt), ApprovedBy: r.ApprovedBy,
		Predecessor: policyFromRow(r.PredecessorChoice, r.PredecessorDays),
	}
}

func toEnrollment(r pkidb.AgentEnrollment) Enrollment {
	return Enrollment{
		ID: r.ID, Hostname: r.Hostname, State: r.State, AgentID: r.AgentID.String, CheckMethod: r.CheckMethod,
		CheckState: r.CheckState, CheckError: r.CheckError.String, TokenValid: r.TokenValid == 1, TokenProblem: r.TokenProblem.String,
		KnownAgent: r.KnownAgent == 1, OS: r.Os, Arch: r.Arch, Version: r.AgentVersion, SourceIP: r.SourceIp,
		CreatedAt: parseTime(r.CreatedAt), ExpiresAt: parseTime(r.ExpiresAt), DecidedAt: nullTime(r.DecidedAt), DecidedBy: r.DecidedBy.String,
	}
}
