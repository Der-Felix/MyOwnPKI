package tenant

import (
	"context"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/settingsver"
	"github.com/Der-Felix/MyOwnPKI/internal/store/systemdb"
)

// ChangeOptions are the optional extras of a settings change (PHASE3
// section 16, step 62). The zero value is the behavior of the released API:
// no concurrency check, no reason.
type ChangeOptions struct {
	// ExpectedVersion, when set, is the version number the caller based the
	// change on (the ETag it read; 0 = the settings have no history yet).
	// When it is not the newest version, nothing is written and SetWith
	// returns an error that matches settingsver.ErrConflict.
	ExpectedVersion *int64
	// Reason is optional free text for the history (at most
	// settingsver.MaxReason characters, no control characters). It is kept
	// with the version and never goes to the audit log.
	Reason string
}

// snapshot is the versioned state of the tenant settings. s must be filled
// completely, as readFrom fills it.
func snapshot(s *Settings) settingsver.TenantSnapshot {
	return settingsver.TenantSnapshot{
		AllowServerKeygen: s.AllowServerKeygen, Organization: s.Organization, OrganizationalUnit: s.OrganizationalUnit,
		Locality: s.Locality, State: s.State, Country: s.Country,
		ACME: settingsver.ACMELimitsSnapshot{
			OrdersPerAccount: s.ACME.OrdersPerAccount, FailedPerName: s.ACME.FailedPerName, AccountsPerIP: s.ACME.AccountsPerIP,
		},
		TrustPage: *s.TrustPage, AgentEnrollment: *s.AgentEnrollment, StepUpMinutes: *s.StepUpMinutes,
		AgentPredecessor: settingsver.PredecessorSnapshot{Choice: s.AgentPredecessor.Choice, Days: s.AgentPredecessor.Days},
		OtherPredecessor: settingsver.PredecessorSnapshot{Choice: s.OtherPredecessor.Choice, Days: s.OtherPredecessor.Days},
	}
}

// versionActor is the actor of a version, taken from the audit actor of the
// request (the same person or token the audit entry names).
func versionActor(who keys.Who) settingsver.Actor {
	return settingsver.Actor{Type: string(who.Actor.Type), ID: who.Actor.ID, Name: who.Actor.Name}
}

// Version returns the newest version number of the tenant's settings, the
// number of their ETag: 0 when they have not been changed since the version
// history began. Reading needs the same right as Get.
func (s *Store) Version(ctx context.Context, tenant string, who keys.Who) (int64, error) {
	if err := who.Principal.Check(authz.ReadPKI, authz.Resource{Tenant: tenant}, s.Clock.Now()); err != nil && !anyRole(who.Principal, tenant) {
		return 0, err
	}
	return settingsver.Current(ctx, settingsver.SystemBackend(systemdb.New(s.DB)), settingsver.KindTenant, tenant)
}
