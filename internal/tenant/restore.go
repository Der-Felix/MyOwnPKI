package tenant

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/predecessor"
	"github.com/Der-Felix/MyOwnPKI/internal/settingsver"
	"github.com/Der-Felix/MyOwnPKI/internal/store/systemdb"
)

// History and restore of the tenant settings (PHASE3 section 16, step 63).
//
// Reading the history needs the audit right (versions name users; a
// tenant-wide admin). A restore turns the stored snapshot into Settings and
// runs the ordinary writer (set), so every check of a normal change applies
// with the same reasons, the permission is ManageTenant, and a change of the
// agent enrollment mode needs EnrollMode (a fresh second factor, never an API
// token).

// ActionSettingsRestore is the audit action of a restore.
const ActionSettingsRestore = "tenant.settings_restore"

// restoreOf says that a change is the restore of a stored version.
type restoreOf struct{ from int64 }

// RestoreCheck is the answer of a dry run: whether the restore would be
// accepted now and, if not, why.
type RestoreCheck struct {
	Restorable bool
	Problems   []string
}

// VersionPage is one page of the history.
type VersionPage struct {
	settingsver.Page
	// Changed holds, per version of the page, the keys of the settings it
	// changed; nil for a version whose snapshot cannot be read.
	Changed [][]string
	// Current is the newest version number, the ETag (0 = no history yet).
	Current int64
}

// VersionDetail is one version with its state, a diff and the answer to
// "could it be restored now".
type VersionDetail struct {
	Version    settingsver.Version
	Snapshot   settingsver.TenantSnapshot
	Comparison settingsver.Comparison
	Restore    RestoreCheck
	// Current is the newest version number, the ETag.
	Current int64
}

func (s *Store) checkAudit(tenant string, who keys.Who) error {
	return who.Principal.Check(authz.ReadAudit, authz.Resource{Tenant: tenant}, s.Clock.Now())
}

func (s *Store) backend() settingsver.Backend { return settingsver.SystemBackend(systemdb.New(s.DB)) }

// settingsOf is the Settings a snapshot stands for, every field set (the
// writer then changes everything, as the snapshot says).
func settingsOf(sn settingsver.TenantSnapshot) Settings {
	return Settings{
		AllowServerKeygen: sn.AllowServerKeygen, Organization: sn.Organization, OrganizationalUnit: sn.OrganizationalUnit,
		Locality: sn.Locality, State: sn.State, Country: sn.Country,
		ACME:      &ACMELimits{OrdersPerAccount: sn.ACME.OrdersPerAccount, FailedPerName: sn.ACME.FailedPerName, AccountsPerIP: sn.ACME.AccountsPerIP},
		TrustPage: &sn.TrustPage, AgentEnrollment: &sn.AgentEnrollment, StepUpMinutes: &sn.StepUpMinutes,
		AgentPredecessor: &predecessor.Policy{Choice: sn.AgentPredecessor.Choice, Days: sn.AgentPredecessor.Days},
		OtherPredecessor: &predecessor.Policy{Choice: sn.OtherPredecessor.Choice, Days: sn.OtherPredecessor.Days},
	}
}

// Versions returns the history of the settings, newest first (before = the
// cursor of the previous page, 0 = from the newest; limit 0 = the default).
func (s *Store) Versions(ctx context.Context, tenant string, who keys.Who, before int64, limit int) (*VersionPage, error) {
	if err := s.checkAudit(tenant, who); err != nil {
		return nil, err
	}
	b := s.backend()
	current, err := settingsver.Current(ctx, b, settingsver.KindTenant, tenant)
	if err != nil {
		return nil, err
	}
	page, err := settingsver.List(ctx, b, settingsver.KindTenant, tenant, before, limit)
	if err != nil {
		return nil, err
	}
	return &VersionPage{Page: page, Changed: settingsver.PageChanges(ctx, b, page.Versions), Current: current}, nil
}

// VersionDetail returns one version. against is settingsver.AgainstPrevious,
// AgainstCurrent or a version number. settingsver.ErrNotFound if there is no
// such version; settingsver.ErrUnknownSchema or ErrCorrupt if its snapshot
// cannot be read.
func (s *Store) VersionDetail(ctx context.Context, tenant string, who keys.Who, number, against int64) (*VersionDetail, error) {
	if err := s.checkAudit(tenant, who); err != nil {
		return nil, err
	}
	b := s.backend()
	current, err := settingsver.Current(ctx, b, settingsver.KindTenant, tenant)
	if err != nil {
		return nil, err
	}
	live, err := s.read(ctx, tenant)
	if err != nil {
		return nil, err
	}
	v, snap, cmp, err := settingsver.Compare(ctx, b, settingsver.KindTenant, tenant, number, against, snapshot(live), current)
	if err != nil {
		return nil, err
	}
	check, err := s.RestoreCheck(ctx, tenant, who, number)
	if err != nil {
		return nil, err
	}
	return &VersionDetail{Version: v, Snapshot: snap.(settingsver.TenantSnapshot), Comparison: cmp, Restore: check, Current: current}, nil
}

// RestoreCheck asks whether Restore would accept a version now, from the same
// checks and without writing: the reasons are the ones the restore gives. The
// second factor is not asked for (the restore asks for it when the mode
// changes); a caller who may never restore (an API token that would change
// the mode) is told so.
func (s *Store) RestoreCheck(ctx context.Context, tenant string, who keys.Who, version int64) (RestoreCheck, error) {
	if err := s.checkAudit(tenant, who); err != nil {
		return RestoreCheck{}, err
	}
	v, err := settingsver.Get(ctx, s.backend(), settingsver.KindTenant, tenant, version)
	if err != nil {
		return RestoreCheck{}, err
	}
	decoded, err := v.Decoded()
	switch {
	case errors.Is(err, settingsver.ErrUnknownSchema), errors.Is(err, settingsver.ErrCorrupt):
		return RestoreCheck{Problems: []string{"this version cannot be read by this release: " + err.Error()}}, nil
	case err != nil:
		return RestoreCheck{}, err
	}
	snap := decoded.(settingsver.TenantSnapshot)
	live, err := s.read(ctx, tenant)
	if err != nil {
		return RestoreCheck{}, err
	}
	now := s.Clock.Now().UTC()
	problems := validate(settingsOf(snap), "")
	if err = who.Principal.Check(authz.ManageTenant, authz.Resource{Tenant: tenant}, now); err != nil {
		problems = append(problems, err.Error())
	}
	if snap.AgentEnrollment != *live.AgentEnrollment {
		if err = who.Principal.Check(authz.EnrollMode, authz.Resource{Tenant: tenant}, now); err != nil && !errors.Is(err, authz.ErrStepUpRequired) {
			problems = append(problems, err.Error())
		}
	}
	if settingsver.Same(snap, snapshot(live)) {
		problems = append(problems, "this version is the state the settings already have – there is nothing to restore")
	}
	return RestoreCheck{Restorable: len(problems) == 0, Problems: append([]string{}, problems...)}, nil
}

// Restore makes the settings look like a stored version again, as a new
// version (change "restore", restored_from = version), and returns its
// number. The snapshot goes through the ordinary writer, so every check of PUT
// /settings applies (ErrInvalid for settings that are not valid now, with the
// same reasons; settingsver.ErrNotFound for a missing version).
// opts.ExpectedVersion is required (settingsver.ErrPreconditionRequired after
// the permission checks) and must be the newest version number; a different
// one is settingsver.ErrConflict and nothing is written. A version that equals
// the current settings is settingsver.ErrIdentical. The audit entry is
// tenant.settings_restore with version, restored_from, changed_keys and
// snapshot_sha256; a refusal is audited (denied or failure) with the error.
func (s *Store) Restore(ctx context.Context, tenant string, version int64, opts ChangeOptions, who keys.Who) (int64, error) {
	now := s.Clock.Now().UTC()
	n, err := s.restore(ctx, tenant, version, opts, who, now)
	if err != nil && !errors.Is(err, settingsver.ErrNotFound) {
		if aerr := s.refuseRestore(ctx, tenant, version, who, now, err); aerr != nil {
			return 0, errors.Join(err, fmt.Errorf("audit: %w", aerr))
		}
	}
	return n, err
}

func (s *Store) restore(ctx context.Context, tenant string, version int64, opts ChangeOptions, who keys.Who, now time.Time) (int64, error) {
	if err := who.Principal.Check(authz.ManageTenant, authz.Resource{Tenant: tenant}, now); err != nil {
		return 0, err
	}
	b := s.backend()
	v, err := settingsver.Get(ctx, b, settingsver.KindTenant, tenant, version)
	if err != nil {
		return 0, err
	}
	decoded, err := v.Decoded()
	if err != nil {
		return 0, err
	}
	snap := decoded.(settingsver.TenantSnapshot)
	live, err := s.read(ctx, tenant)
	if err != nil {
		return 0, err
	}
	// A change of the enrollment mode weighs more than the rest: its permission
	// is checked before anything else is said about the request (set checks it
	// again inside its transaction).
	if snap.AgentEnrollment != *live.AgentEnrollment {
		if err = who.Principal.Check(authz.EnrollMode, authz.Resource{Tenant: tenant}, now); err != nil {
			return 0, err
		}
	}
	if opts.ExpectedVersion == nil {
		return 0, settingsver.ErrPreconditionRequired
	}
	// Early, so a stale caller hears 412 before a list of reasons; set checks
	// again inside its transaction.
	if err = settingsver.CheckExpected(ctx, b, settingsver.KindTenant, tenant, opts.ExpectedVersion); err != nil {
		return 0, err
	}
	return s.set(ctx, tenant, settingsOf(snap), opts, &restoreOf{from: version}, who)
}

// refuseRestore audits a refused restore. The entry is not part of a business
// transaction (nothing changed), so it has its own.
func (s *Store) refuseRestore(ctx context.Context, tenant string, version int64, who keys.Who, now time.Time, cause error) error {
	result := audit.ResultFailure
	if errors.Is(cause, authz.ErrDenied) || errors.Is(cause, authz.ErrStepUpRequired) {
		result = audit.ResultDenied
	}
	text := cause.Error()
	if len(text) > 512 {
		text = text[:512] + "…"
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err = audit.Enqueue(ctx, tx, now, audit.Entry{
		Time: now, Actor: who.Actor, Action: ActionSettingsRestore, Target: audit.Target{Type: "tenant", ID: tenant},
		Result: result, SourceIP: who.SourceIP, Details: map[string]any{"restored_from": version, "error": text},
	}); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	if s.Wake != nil {
		s.Wake()
	}
	return nil
}
