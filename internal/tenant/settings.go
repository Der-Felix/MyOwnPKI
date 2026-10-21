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
	return &Settings{AllowServerKeygen: r.AllowServerKeygen == 1, Organization: r.SubjectO, OrganizationalUnit: r.SubjectOu,
		Locality: r.SubjectL, State: r.SubjectSt, Country: r.SubjectC}, nil
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
	if len(problems) > 0 {
		return fmt.Errorf("%w: %s", ErrInvalid, strings.Join(problems, "; "))
	}
	before, err := s.read(ctx, tenant)
	if err != nil {
		return err
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
		SubjectSt: v.State, SubjectC: v.Country, ID: tenant,
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
