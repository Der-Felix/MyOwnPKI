// Package tenant holds the settings of a tenant (PHASE1 step 18): whether
// the server may generate keys, and the subject defaults that fill empty
// fields of a request – what pki.conf of legacy/pki.sh did.
package tenant

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
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
}

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
	return s.read(ctx, tenant)
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
	r, err := systemdb.New(s.DB).GetTenantSettings(ctx, tenant)
	if err != nil {
		return nil, err
	}
	trust := r.TrustPage == 1
	return &Settings{AllowServerKeygen: r.AllowServerKeygen == 1, Organization: r.SubjectO, OrganizationalUnit: r.SubjectOu,
		Locality: r.SubjectL, State: r.SubjectSt, Country: r.SubjectC,
		ACME:      &ACMELimits{OrdersPerAccount: int(r.AcmeOrdersPerHour), FailedPerName: int(r.AcmeFailedPerName), AccountsPerIP: int(r.AcmeAccountsPerIp)},
		TrustPage: &trust}, nil
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
	now := s.Clock.Now().UTC()
	if err := who.Principal.Check(authz.ManageTenant, authz.Resource{Tenant: tenant}, now); err != nil {
		return err
	}
	var problems []string
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
	if len(problems) > 0 {
		return fmt.Errorf("%w: %s", ErrInvalid, strings.Join(problems, "; "))
	}
	before, err := s.read(ctx, tenant)
	if err != nil {
		return err
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
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	keygen := int64(0)
	if v.AllowServerKeygen {
		keygen = 1
	}
	n, err := systemdb.New(tx).SetTenantSettings(ctx, systemdb.SetTenantSettingsParams{
		AllowServerKeygen: keygen, SubjectO: v.Organization, SubjectOu: v.OrganizationalUnit, SubjectL: v.Locality,
		SubjectSt: v.State, SubjectC: v.Country,
		AcmeOrdersPerHour: int64(limits.OrdersPerAccount), AcmeFailedPerName: int64(limits.FailedPerName), AcmeAccountsPerIp: int64(limits.AccountsPerIP),
		TrustPage: trustInt, ID: tenant,
	})
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("no tenant %q", tenant)
	}
	if err := audit.Enqueue(ctx, tx, now, audit.Entry{
		Time: now, Actor: who.Actor, Action: ActionSettings, Target: audit.Target{Type: "tenant", ID: tenant},
		Result: audit.ResultSuccess, SourceIP: who.SourceIP, Details: map[string]any{
			"allow_server_keygen": v.AllowServerKeygen, "was_allow_server_keygen": before.AllowServerKeygen,
			"subject": subjectText(v), "was_subject": subjectText(*before),
			"acme_limits": limitsText(limits), "was_acme_limits": limitsText(*before.ACME),
			"trust_page": trust, "was_trust_page": *before.TrustPage,
		},
	}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if s.Wake != nil {
		s.Wake()
	}
	return nil
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
