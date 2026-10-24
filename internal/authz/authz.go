// Package authz decides who may do what (security.md "Authorization", PHASE1
// step 10).
//
// Users get roles per tenant, optionally limited to one CA. Instance admins
// manage users and unseal the server; that alone gives no rights in a tenant.
// The services check permissions themselves (the CA engine, the keyring), so
// the API, the UI, ACME and the agent can't bypass them.
package authz

import (
	"errors"
	"fmt"
	"slices"
	"time"
)

// Errors. Both are refusals the caller can fix; the API maps ErrStepUpRequired
// to a prompt for the second factor.
var (
	ErrDenied         = errors.New("permission denied")
	ErrStepUpRequired = errors.New("confirm this action with your second factor first")
)

// Role is a tenant role.
type Role string

// Roles, from least to most.
const (
	Viewer   Role = "viewer"
	Operator Role = "operator"
	Admin    Role = "admin"
)

// Roles lists the valid roles.
var Roles = []Role{Viewer, Operator, Admin}

// Permission is one thing a principal may do.
type Permission string

// Tenant permissions.
const (
	ReadPKI      Permission = "pki.read"           // CAs, certificates, CRL status
	ReadAudit    Permission = "audit.read"         // the tenant audit log: user names and IPs are personal data
	IssueCert    Permission = "certificate.issue"  // also renew
	RevokeCert   Permission = "certificate.revoke" // step-up
	DownloadKey  Permission = "key.download"       // a server-generated private key; step-up
	ManageCA     Permission = "ca.manage"          // create, import, renew, retire, update, revoke, install; step-up
	UploadCRL    Permission = "crl.upload"         // the offline root's CRL; step-up
	ManageTenant Permission = "tenant.manage"      // tenant settings
	ManageAgents Permission = "agent.manage"       // join tokens, enrollment approvals, agent names, disable, revoke; step-up
)

// Instance permissions: instance admins only.
const (
	Unseal      Permission = "system.unseal" // and seal; the passphrase is the stronger proof, no step-up
	ManageUsers Permission = "user.manage"   // users, roles, 2FA reset, unlock; step-up
)

var rolePermissions = map[Role][]Permission{
	Viewer:   {ReadPKI},
	Operator: {ReadPKI, IssueCert, RevokeCert, DownloadKey},
	Admin:    {ReadPKI, ReadAudit, IssueCert, RevokeCert, DownloadKey, ManageCA, UploadCRL, ManageTenant, ManageAgents},
}

var instancePermissions = []Permission{Unseal, ManageUsers}

// stepUp: permissions that need a fresh second factor (security.md).
var stepUp = []Permission{RevokeCert, DownloadKey, ManageCA, UploadCRL, ManageUsers, ManageAgents}

// StepUpWindow is how long a fresh second factor counts.
const StepUpWindow = 5 * time.Minute

// NeedsStepUp reports whether p needs a fresh second factor.
func NeedsStepUp(p Permission) bool { return slices.Contains(stepUp, p) }

// Kind says where a principal comes from.
type Kind string

// Kinds.
const (
	// KindUser: signed in through the web UI or the API.
	KindUser Kind = "user"
	// KindConsole: a command on the server itself (myownpki ...). Whoever runs
	// it can read the data directory anyway; it may do everything.
	KindConsole Kind = "console"
	// KindSystem: the server's own jobs (CRL renewal, checkpoints).
	KindSystem Kind = "system"
)

// Binding is one role of a user in a tenant; CA "" covers the whole tenant.
type Binding struct {
	Tenant string
	CA     string
	Role   Role
}

// Principal is the authenticated caller.
type Principal struct {
	Kind          Kind
	UserID        string
	Username      string
	InstanceAdmin bool
	Bindings      []Binding
	// StepUpAt is the last fresh second factor of this session; zero = none.
	StepUpAt time.Time
	// ViaToken: the request carries an API token. A token never satisfies
	// step-up (step 18): those actions need a person with a fresh code.
	ViaToken bool
}

// Console returns the principal of a command run on the server.
func Console() *Principal { return &Principal{Kind: KindConsole, Username: "console"} }

// System returns the principal of the server's own jobs.
func System(job string) *Principal { return &Principal{Kind: KindSystem, Username: job} }

// Resource is what an action touches. CA "" is an action on the whole tenant
// (for example creating a CA): only a tenant-wide role allows it.
type Resource struct {
	Tenant string
	CA     string
}

// Check returns nil if p may do perm on res at now, an error wrapping
// ErrDenied or ErrStepUpRequired otherwise. A nil principal is denied.
func (p *Principal) Check(perm Permission, res Resource, now time.Time) error {
	if p == nil {
		return fmt.Errorf("%w: nobody is signed in", ErrDenied)
	}
	if p.Kind == KindConsole || p.Kind == KindSystem {
		return nil
	}
	if p.Kind != KindUser {
		return fmt.Errorf("%w: unknown principal kind %q", ErrDenied, p.Kind)
	}
	// Before the roles: whatever role a token carries, these need a person.
	if NeedsStepUp(perm) && p.ViaToken {
		return &TokenStepUpError{Action: stepUpActions[perm]}
	}
	if slices.Contains(instancePermissions, perm) {
		if !p.InstanceAdmin {
			return fmt.Errorf("%w: %s needs an instance admin", ErrDenied, perm)
		}
	} else if !p.hasTenantPermission(perm, res) {
		where := "tenant " + res.Tenant
		if res.CA != "" {
			where = fmt.Sprintf("CA %q in tenant %s", res.CA, res.Tenant)
		}
		return fmt.Errorf("%w: %s on %s needs the role %s", ErrDenied, perm, where, lowestRole(perm))
	}
	// Whole seconds: the CA engine works in seconds (like certificates),
	// sessions store milliseconds – a step-up in the same second must not
	// look like one from the future (live run finding 2026-10-17).
	stepUp := p.StepUpAt.Truncate(time.Second)
	if NeedsStepUp(perm) && (p.StepUpAt.IsZero() || now.Sub(stepUp) > StepUpWindow || now.Before(stepUp)) {
		return fmt.Errorf("%w (%s)", ErrStepUpRequired, perm)
	}
	return nil
}

// hasTenantPermission: a tenant-wide binding, or a binding for res.CA.
func (p *Principal) hasTenantPermission(perm Permission, res Resource) bool {
	for _, b := range p.Bindings {
		if b.Tenant != res.Tenant || (b.CA != "" && b.CA != res.CA) {
			continue
		}
		if slices.Contains(rolePermissions[b.Role], perm) {
			return true
		}
	}
	return false
}

// lowestRole names the least role with perm, for the denial message.
func lowestRole(perm Permission) Role {
	for _, r := range Roles {
		if slices.Contains(rolePermissions[r], perm) {
			return r
		}
	}
	return Admin
}

// ValidRole reports whether r is a tenant role.
func ValidRole(r Role) bool { return slices.Contains(Roles, r) }

// FreshStepUp checks only the step-up of a signed-in user – for changes to
// the own account (a new or removed passkey) that need no role.
func (p *Principal) FreshStepUp(now time.Time) error {
	if p == nil || p.Kind != KindUser {
		return fmt.Errorf("%w: not a signed-in user", ErrDenied)
	}
	if p.ViaToken {
		return &TokenStepUpError{Action: "change the sign-in of an account"}
	}
	stepUp := p.StepUpAt.Truncate(time.Second)
	if p.StepUpAt.IsZero() || now.Sub(stepUp) > StepUpWindow || now.Before(stepUp) {
		return fmt.Errorf("%w (own account)", ErrStepUpRequired)
	}
	return nil
}

// CanIssueSomewhere tells whether p may issue at one CA at least (or is the
// console) – for previews that belong to no CA yet.
func (p *Principal) CanIssueSomewhere() bool {
	if p == nil {
		return false
	}
	if p.Kind == KindConsole || p.Kind == KindSystem {
		return true
	}
	for _, b := range p.Bindings {
		if slices.Contains(rolePermissions[b.Role], IssueCert) {
			return true
		}
	}
	return false
}

// stepUpActions names the step-up permissions for a token's refusal.
var stepUpActions = map[Permission]string{
	RevokeCert:   "revoke certificates",
	DownloadKey:  "download private keys",
	ManageCA:     "manage CAs",
	UploadCRL:    "upload CRLs",
	ManageAgents: "manage agents",
	ManageUsers:  "manage users",
}

// TokenStepUpError refuses an action that needs step-up to an API token. It
// is a denial (ErrDenied), not a prompt: no POST /auth/step-up can ever make
// a token fresh, so step-up-required would send a script in circles.
type TokenStepUpError struct {
	Action string
}

func (e *TokenStepUpError) Error() string {
	return "an API token can't " + e.Action + " – sign in and confirm with a fresh code"
}

// Unwrap makes errors.Is(err, ErrDenied) true.
func (e *TokenStepUpError) Unwrap() error { return ErrDenied }
