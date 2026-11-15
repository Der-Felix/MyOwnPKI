// Package tenant holds the settings of a tenant (PHASE1 step 18): whether
// the server may generate keys, and the subject defaults that fill empty
// fields of a request – what pki.conf of legacy/pki.sh did.
package tenant

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/predecessor"
	"github.com/Der-Felix/MyOwnPKI/internal/settingsver"
	"github.com/Der-Felix/MyOwnPKI/internal/store/systemdb"
)

// ActionSettings is the audit action of a change.
const ActionSettings = "tenant.settings"

// Settings of a tenant.
type Settings struct {
	AllowServerKeygen  bool
	Organization       string
	OrganizationalUnit string
	Locality           string
	State              string
	Country            string
	// ACME: the rate limits of the ACME server. Get always fills it; in
	// Set, nil keeps the stored limits (a v0.1 client doesn't send them).
	ACME *ACMELimits
	// TrustPage: the public listener serves the trust page at / (v0.2.2,
	// default on). Get always fills it; in Set, nil keeps the stored value
	// (a v0.2 client doesn't send it).
	TrustPage *bool
	// AgentEnrollment: how agents are admitted (v0.3.0, ADR-18) – auto,
	// verified (default) or manual. Get always fills it; in Set, nil keeps
	// the stored value.
	AgentEnrollment *string
	// StepUpMinutes is the lifetime of new second-factor proofs (v0.3.1).
	// Get always fills it; in Set, nil keeps the stored value.
	StepUpMinutes *int
	// Separate predecessor defaults for agent deployments and other renewals.
	// In Set, nil keeps the corresponding stored policy.
	AgentPredecessor *predecessor.Policy
	OtherPredecessor *predecessor.Policy
	// Version is the newest version number of the settings, the number of
	// their ETag. Get sets it; Set ignores it (SetWith takes the expected
	// version as an option).
	Version int64
}

// DefaultStepUpMinutes preserves the lifetime used before v0.3.1.
const DefaultStepUpMinutes = 5

// StepUpMinuteValues lists the allowed proof lifetimes in minutes.
var StepUpMinuteValues = []int{5, 10, 15, 30, 60}

// Agent enrollment modes (docs/PHASE3.md §6.1).
const (
	EnrollAuto     = "auto"
	EnrollVerified = "verified"
	EnrollManual   = "manual"
)

// EnrollmentModes lists the valid modes.
var EnrollmentModes = []string{EnrollAuto, EnrollVerified, EnrollManual}

// ACMELimits are per hour (PHASE2 step 11).
type ACMELimits struct {
	OrdersPerAccount int // new orders per account
	FailedPerName    int // failed validations per name
	AccountsPerIP    int // new accounts per client address (IPv6: per /64)
}

// DefaultACMELimits are the limits of a new tenant (migration 0009).
var DefaultACMELimits = ACMELimits{OrdersPerAccount: 300, FailedPerName: 5, AccountsPerIP: 10}

// check returns the problems of the limits (same ranges as the schema).
func (l ACMELimits) check() []string {
	var problems []string
	for _, c := range []struct {
		field  string
		v, max int
	}{{"acme_limits.orders_per_account", l.OrdersPerAccount, 10000}, {"acme_limits.failed_per_name", l.FailedPerName, 100}, {"acme_limits.accounts_per_ip", l.AccountsPerIP, 1000}} {
		if c.v < 1 || c.v > c.max {
			problems = append(problems, fmt.Sprintf("%s: 1 to %d per hour", c.field, c.max))
		}
	}
	return problems
}

// Store reads and writes settings in system.db.
type Store struct {
	DB    *sql.DB // system.db writer
	Clock clock.Clock
	Wake  func()
}

// ErrInvalid wraps every refused value.
var ErrInvalid = errors.New("invalid settings")

// Get returns the settings; reading needs any role in the tenant.
func (s *Store) Get(ctx context.Context, tenant string, who keys.Who) (*Settings, error) {
	if err := who.Principal.Check(authz.ReadPKI, authz.Resource{Tenant: tenant}, s.Clock.Now()); err != nil && !anyRole(who.Principal, tenant) {
		return nil, err
	}
	// The version is read before the settings: a change between the two reads
	// leaves the number older than the body, so an If-Match built from it
	// fails instead of overwriting that change.
	version, err := settingsver.Current(ctx, settingsver.SystemBackend(systemdb.New(s.DB)), settingsver.KindTenant, tenant)
	if err != nil {
		return nil, err
	}
	v, err := s.read(ctx, tenant)
	if err != nil {
		return nil, err
	}
	v.Version = version
	return v, nil
}

// anyRole: a CA-scoped role reads the tenant's defaults too (the wizard
// needs them).
func anyRole(p *authz.Principal, tenant string) bool {
	if p == nil {
		return false
	}
	if p.Kind == authz.KindConsole || p.Kind == authz.KindSystem {
		return true
	}
	for _, b := range p.Bindings {
		if b.Tenant == tenant {
			return true
		}
	}
	return false
}

func (s *Store) read(ctx context.Context, tenant string) (*Settings, error) {
	return readFrom(ctx, systemdb.New(s.DB), tenant)
}

// readFrom reads through q, which may belong to a transaction.
func readFrom(ctx context.Context, q *systemdb.Queries, tenant string) (*Settings, error) {
	r, err := q.GetTenantSettings(ctx, tenant)
	if err != nil {
		return nil, err
	}
	trust := r.TrustPage == 1
	mode := r.AgentEnrollment
	stepUp := int(r.StepUpMinutes)
	agentPolicy := predecessor.Policy{Choice: r.AgentPredecessorChoice, Days: int(r.AgentPredecessorDays)}
	otherPolicy := predecessor.Policy{Choice: r.OtherPredecessorChoice, Days: int(r.OtherPredecessorDays)}
	return &Settings{AllowServerKeygen: r.AllowServerKeygen == 1, Organization: r.SubjectO, OrganizationalUnit: r.SubjectOu,
		Locality: r.SubjectL, State: r.SubjectSt, Country: r.SubjectC,
		ACME:      &ACMELimits{OrdersPerAccount: int(r.AcmeOrdersPerHour), FailedPerName: int(r.AcmeFailedPerName), AccountsPerIP: int(r.AcmeAccountsPerIp)},
		TrustPage: &trust, AgentEnrollment: &mode, StepUpMinutes: &stepUp,
		AgentPredecessor: &agentPolicy, OtherPredecessor: &otherPolicy}, nil
}

// AgentEnrollment returns how agents are admitted, without a permission
// check (the agent listener asks it per enrollment).
func (s *Store) AgentEnrollment(ctx context.Context, tenant string) (string, error) {
	return systemdb.New(s.DB).GetAgentEnrollment(ctx, tenant)
}

// TrustPage reports whether the public listener serves the trust page,
// without a permission check (the public listener asks it per request, so a
// change applies at once).
func (s *Store) TrustPage(ctx context.Context, tenant string) (bool, error) {
	v, err := systemdb.New(s.DB).GetTrustPage(ctx, tenant)
	return v == 1, err
}

// Defaults returns the settings without a permission check (for the
// services that fill requests).
func (s *Store) Defaults(ctx context.Context, tenant string) (*Settings, error) {
	return s.read(ctx, tenant)
}

// Set stores new settings; it needs tenant.manage (tenant admin).
func (s *Store) Set(ctx context.Context, tenant string, v Settings, who keys.Who) error {
	_, err := s.SetWith(ctx, tenant, v, ChangeOptions{}, who)
	return err
}

// SetWith is Set with the optional concurrency check and reason. Every
// change appends a version of the settings in the same transaction as the
// change and its audit entry (the first change of a tenant without history
// writes the baseline first), so nothing is half recorded. It returns the
// number of the version it wrote, the new ETag.
func (s *Store) SetWith(ctx context.Context, tenant string, v Settings, opts ChangeOptions, who keys.Who) (int64, error) {
	return s.set(ctx, tenant, v, opts, nil, who)
}

// validate returns the problems of new settings and of a reason, all at once.
func validate(v Settings, reason string) []string {
	var problems []string
	if settingsver.CheckReason(reason) != nil {
		problems = append(problems, fmt.Sprintf("reason: at most %d characters, no control or invisible formatting characters", settingsver.MaxReason))
	}
	check := func(field, value string, n int) {
		if utf8.RuneCountInString(value) > n || strings.ContainsFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			problems = append(problems, fmt.Sprintf("%s: at most %d characters, no control characters", field, n))
		}
	}
	check("organization", v.Organization, 64)
	check("organizational_unit", v.OrganizationalUnit, 64)
	check("locality", v.Locality, 128)
	check("state", v.State, 128)
	if v.Country != "" && (len(v.Country) != 2 || strings.Trim(v.Country, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") != "") {
		problems = append(problems, "country: two upper-case letters (ISO 3166-1), e.g. DE")
	}
	if v.ACME != nil {
		problems = append(problems, v.ACME.check()...)
	}
	if v.AgentEnrollment != nil && !slices.Contains(EnrollmentModes, *v.AgentEnrollment) {
		problems = append(problems, "agent_enrollment: auto, verified or manual")
	}
	if v.StepUpMinutes != nil && !slices.Contains(StepUpMinuteValues, *v.StepUpMinutes) {
		problems = append(problems, "step_up_minutes: 5, 10, 15, 30 or 60")
	}
	for _, p := range []struct {
		name   string
		policy *predecessor.Policy
	}{{"agent_predecessor", v.AgentPredecessor}, {"other_predecessor", v.OtherPredecessor}} {
		if p.policy != nil {
			if err := p.policy.Validate(); err != nil {
				problems = append(problems, p.name+": "+err.Error())
			}
		}
	}
	return problems
}

// set is SetWith and the restore of a version: rs is nil for an ordinary
// change. A restore runs exactly the same checks, then records the change
// "restore" (restored_from) and the audit action tenant.settings_restore.
func (s *Store) set(ctx context.Context, tenant string, v Settings, opts ChangeOptions, rs *restoreOf, who keys.Who) (int64, error) {
	now := s.Clock.Now().UTC()
	if err := who.Principal.Check(authz.ManageTenant, authz.Resource{Tenant: tenant}, now); err != nil {
		return 0, err
	}
	if problems := validate(v, opts.Reason); len(problems) > 0 {
		return 0, fmt.Errorf("%w: %s", ErrInvalid, strings.Join(problems, "; "))
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	// Read inside the (immediate) transaction: the check below compares with the
	// mode this write replaces, not with one another request changed meanwhile.
	before, err := readFrom(ctx, systemdb.New(tx), tenant)
	if err != nil {
		return 0, err
	}
	// The conflict check comes before anything is written, and before the
	// second-factor check: a form that is out of date should say so before it
	// asks for a confirmation that would be wasted.
	if cerr := settingsver.CheckExpected(ctx, settingsver.SystemBackend(systemdb.New(tx)), settingsver.KindTenant, tenant, opts.ExpectedVersion); cerr != nil {
		return 0, cerr
	}
	// In auto mode a host that passes the check is admitted without a person, so
	// the mode weighs as much as approving an enrollment: a fresh second factor,
	// never an API token. Leaving the mode as it is changes nothing and needs none.
	if v.AgentEnrollment != nil && *v.AgentEnrollment != *before.AgentEnrollment {
		if cerr := who.Principal.Check(authz.EnrollMode, authz.Resource{Tenant: tenant}, now); cerr != nil {
			return 0, cerr
		}
	}
	limits := *before.ACME
	if v.ACME != nil {
		limits = *v.ACME
	}
	trust := *before.TrustPage
	if v.TrustPage != nil {
		trust = *v.TrustPage
	}
	trustInt := int64(0)
	if trust {
		trustInt = 1
	}
	mode := *before.AgentEnrollment
	if v.AgentEnrollment != nil {
		mode = *v.AgentEnrollment
	}
	stepUp := *before.StepUpMinutes
	if v.StepUpMinutes != nil {
		stepUp = *v.StepUpMinutes
	}
	agentPolicy, otherPolicy := *before.AgentPredecessor, *before.OtherPredecessor
	if v.AgentPredecessor != nil {
		agentPolicy = *v.AgentPredecessor
	}
	if v.OtherPredecessor != nil {
		otherPolicy = *v.OtherPredecessor
	}
	for _, p := range []*predecessor.Policy{&agentPolicy, &otherPolicy} {
		if p.Choice != predecessor.After {
			p.Days = 7
		}
	}
	keygen := int64(0)
	if v.AllowServerKeygen {
		keygen = 1
	}
	after := Settings{AllowServerKeygen: v.AllowServerKeygen, Organization: v.Organization, OrganizationalUnit: v.OrganizationalUnit,
		Locality: v.Locality, State: v.State, Country: v.Country, ACME: &limits, TrustPage: &trust, AgentEnrollment: &mode,
		StepUpMinutes: &stepUp, AgentPredecessor: &agentPolicy, OtherPredecessor: &otherPolicy}
	if rs != nil && settingsver.Same(snapshot(before), snapshot(&after)) {
		return 0, settingsver.ErrIdentical
	}
	n, err := systemdb.New(tx).SetTenantSettings(ctx, systemdb.SetTenantSettingsParams{
		AllowServerKeygen: keygen, SubjectO: v.Organization, SubjectOu: v.OrganizationalUnit, SubjectL: v.Locality,
		SubjectSt: v.State, SubjectC: v.Country,
		AcmeOrdersPerHour: int64(limits.OrdersPerAccount), AcmeFailedPerName: int64(limits.FailedPerName), AcmeAccountsPerIp: int64(limits.AccountsPerIP),
		TrustPage: trustInt, AgentEnrollment: mode, StepUpMinutes: int64(stepUp), ID: tenant,
		AgentPredecessorChoice: agentPolicy.Choice, AgentPredecessorDays: int64(agentPolicy.Days),
		OtherPredecessorChoice: otherPolicy.Choice, OtherPredecessorDays: int64(otherPolicy.Days),
	})
	if err != nil {
		return 0, err
	}
	if n != 1 {
		return 0, fmt.Errorf("no tenant %q", tenant)
	}
	// The version, in the same transaction: the change, the version and the audit
	// entry commit or roll back together. The first change of a tenant without
	// history writes the baseline (the state in `before`) first.
	entry := settingsver.Entry{
		Kind: settingsver.KindTenant, ObjectID: tenant, Change: settingsver.ChangeUpdate,
		Before: snapshot(before), After: snapshot(&after), Actor: versionActor(who),
		Reason: opts.Reason, ExpectedVersion: opts.ExpectedVersion, Now: now,
	}
	action := ActionSettings
	if rs != nil {
		entry.Change, entry.RestoredFrom, action = settingsver.ChangeRestore, rs.from, ActionSettingsRestore
	}
	res, err := settingsver.Append(ctx, settingsver.SystemBackend(systemdb.New(tx)), entry)
	if err != nil {
		return 0, err
	}
	details := map[string]any{
		"allow_server_keygen": v.AllowServerKeygen, "was_allow_server_keygen": before.AllowServerKeygen,
		"subject": subjectText(v), "was_subject": subjectText(*before),
		"acme_limits": limitsText(limits), "was_acme_limits": limitsText(*before.ACME),
		"trust_page": trust, "was_trust_page": *before.TrustPage,
		"agent_enrollment": mode, "was_agent_enrollment": *before.AgentEnrollment,
		"step_up_minutes": stepUp, "was_step_up_minutes": *before.StepUpMinutes,
		"agent_predecessor": agentPolicy, "was_agent_predecessor": *before.AgentPredecessor,
		"other_predecessor": otherPolicy, "was_other_predecessor": *before.OtherPredecessor,
		"version": res.Version.Number, "snapshot_sha256": res.Version.SHA256,
	}
	if rs != nil {
		details["restored_from"] = rs.from
		details["changed_keys"] = strings.Join(settingsver.Keys(settingsver.Diff(entry.Before, entry.After)), ",")
	}
	if err := audit.Enqueue(ctx, tx, now, audit.Entry{
		Time: now, Actor: who.Actor, Action: action, Target: audit.Target{Type: "tenant", ID: tenant},
		Result: audit.ResultSuccess, SourceIP: who.SourceIP, Details: details,
	}); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	if s.Wake != nil {
		s.Wake()
	}
	return res.Version.Number, nil
}

func subjectText(v Settings) string {
	var parts []string
	for _, kv := range [][2]string{{"O", v.Organization}, {"OU", v.OrganizationalUnit}, {"L", v.Locality}, {"ST", v.State}, {"C", v.Country}} {
		if kv[1] != "" {
			parts = append(parts, kv[0]+"="+kv[1])
		}
	}
	return strings.Join(parts, ", ")
}

func limitsText(l ACMELimits) string {
	return fmt.Sprintf("orders/account %d, failed/name %d, accounts/ip %d per hour", l.OrdersPerAccount, l.FailedPerName, l.AccountsPerIP)
}

// ACMELimits returns the limits without a permission check (for the ACME
// server).
func (s *Store) ACMELimits(ctx context.Context, tenant string) (ACMELimits, error) {
	v, err := s.read(ctx, tenant)
	if err != nil {
		return DefaultACMELimits, err
	}
	return *v.ACME, nil
}
