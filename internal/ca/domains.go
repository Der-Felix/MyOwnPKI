package ca

import (
	"context"
	"database/sql"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca/preset"
	"github.com/Der-Felix/MyOwnPKI/internal/ids"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/settingsver"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// Domains (PHASE2 step 1): a name space this tenant issues for
// automatically – which CA signs, which challenges prove control, the
// approval level, preset and validity. A name is served by the most
// specific domain that covers it; ACME refuses names without one.

// Audit actions of domains.
const (
	ActionDomainCreate = "domain.create"
	ActionDomainUpdate = "domain.update"
	ActionDomainDelete = "domain.delete"
)

// Approval levels (PLAN §6.3).
const (
	ApprovalOpen    = "open"     // any ACME account that passes the challenge
	ApprovalAccount = "account"  // the account must be approved (or bound with EAB) – the default
	ApprovalNewName = "new_name" // the first issuance for a name needs approval
)

// Challenge types and address policies.
const (
	ChallengeHTTP01 = "http-01"
	ChallengeDNS01  = "dns-01"
	AddressInternal = "internal" // http-01 may reach private networks
	AddressPublic   = "public"   // http-01 may reach public addresses only
)

// DefaultACMEValidityDays: ACME issuances default to 90 days, capped by the
// CA's maximum (owner decision 6, 2026-10-13).
const DefaultACMEValidityDays = 90

// Approvals, Challenges and AddressPolicies list the valid values.
var (
	Approvals       = []string{ApprovalOpen, ApprovalAccount, ApprovalNewName}
	Challenges      = []string{ChallengeHTTP01, ChallengeDNS01}
	AddressPolicies = []string{AddressInternal, AddressPublic}
)

// Domain is a stored domain.
type Domain struct {
	ID                string
	Name              string
	CA                string // the CA's name
	CAID              string
	IncludeSubdomains bool
	Wildcards         bool
	ChallengeTypes    []string
	Approval          string
	Preset            string
	ValidityDays      int // 0 = DefaultACMEValidityDays
	AddressPolicy     string
	IPRanges          []netip.Prefix
	CreatedAt         time.Time
	UpdatedAt         time.Time
	// Version is the newest version number of the domain, the number of its
	// ETag. CreateDomain, UpdateDomain and GetDomain set it; the list and
	// DomainFor leave it 0 (they do not read the history).
	Version int64
}

// EffectiveValidityDays is the validity of an ACME certificate under d.
func (d *Domain) EffectiveValidityDays() int {
	if d.ValidityDays > 0 {
		return d.ValidityDays
	}
	return DefaultACMEValidityDays
}

// AllowsChallenge reports whether d allows the challenge type t.
func (d *Domain) AllowsChallenge(t string) bool { return slices.Contains(d.ChallengeTypes, t) }

// DomainSettings are the changeable parts of a domain. For a change, nil
// pointers and nil slices keep the current value; for a new domain they
// take the defaults.
type DomainSettings struct {
	CA                *string
	IncludeSubdomains *bool
	Wildcards         *bool
	ChallengeTypes    []string
	Approval          *string
	Preset            *string
	ValidityDays      *int // 0 = default
	AddressPolicy     *string
	IPRanges          []string
	// Options: the optional concurrency check and reason of the change.
	Options ChangeOptions
}

// DomainRequest creates a domain.
type DomainRequest struct {
	Name string
	DomainSettings
	Who keys.Who
}

// domainDefaults: sub-domains yes, wildcards no, both challenges, approval
// "account" (owner Q2), preset "server", 90 days, internal addresses.
func domainDefaults() Domain {
	return Domain{
		IncludeSubdomains: true, ChallengeTypes: []string{ChallengeHTTP01, ChallengeDNS01},
		Approval: ApprovalAccount, Preset: "server", AddressPolicy: AddressInternal,
	}
}

// apply puts the given settings over d.
func (s DomainSettings) apply(d *Domain) []string {
	var problems []string
	if s.CA != nil {
		d.CA = strings.TrimSpace(*s.CA)
	}
	if s.IncludeSubdomains != nil {
		d.IncludeSubdomains = *s.IncludeSubdomains
	}
	if s.Wildcards != nil {
		d.Wildcards = *s.Wildcards
	}
	if s.ChallengeTypes != nil {
		d.ChallengeTypes = slices.Clone(s.ChallengeTypes)
	}
	if s.Approval != nil {
		d.Approval = *s.Approval
	}
	if s.Preset != nil {
		d.Preset = *s.Preset
	}
	if s.ValidityDays != nil {
		d.ValidityDays = *s.ValidityDays
	}
	if s.AddressPolicy != nil {
		d.AddressPolicy = *s.AddressPolicy
	}
	if s.IPRanges != nil {
		d.IPRanges = nil
		for _, r := range s.IPRanges {
			p, err := parseIPRange(r)
			if err != nil {
				problems = append(problems, err.Error())
				continue
			}
			d.IPRanges = append(d.IPRanges, p)
		}
	}
	return problems
}

// parseIPRange takes an IP or a CIDR without host bits.
func parseIPRange(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "/") {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("IP range %q is not an IP or CIDR", short(s))
		}
		return netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("IP range %q is not a CIDR", short(s))
	}
	if p.Masked() != p {
		return netip.Prefix{}, fmt.Errorf("IP range %q has host bits set – did you mean %s?", short(s), p.Masked())
	}
	return p, nil
}

// lastAddr is the highest address of p.
func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Addr().AsSlice()
	bits := p.Bits()
	for i := range a {
		for b := 7; b >= 0; b-- {
			if i*8+(7-b) >= bits {
				a[i] |= 1 << b
			}
		}
	}
	out, _ := netip.AddrFromSlice(a)
	return out
}

// checkDomain checks a whole domain against the database: one problem per
// mistake, all at once.
func (e *Engine) checkDomain(ctx context.Context, q *pkidb.Queries, d *Domain) ([]string, *issuer, error) {
	var problems []string
	name, err := checkDNSName(d.Name, false)
	switch {
	case err != nil:
		problems = append(problems, err.Error())
	case name != d.Name:
		problems = append(problems, fmt.Sprintf("domain %q must be written as %q (lower case, punycode, no trailing dot)", short(d.Name), name))
	case !strings.Contains(name, "."):
		problems = append(problems, fmt.Sprintf("domain %q has one label – a domain needs at least two (homelab.example, not homelab)", short(d.Name)))
	}
	if !slices.Contains(Approvals, d.Approval) {
		problems = append(problems, fmt.Sprintf("approval %q is not one of %s", short(d.Approval), strings.Join(Approvals, ", ")))
	}
	if !slices.Contains(AddressPolicies, d.AddressPolicy) {
		problems = append(problems, fmt.Sprintf("address policy %q is not one of %s", short(d.AddressPolicy), strings.Join(AddressPolicies, ", ")))
	}
	switch {
	case len(d.ChallengeTypes) == 0:
		problems = append(problems, "at least one challenge type is needed (http-01, dns-01)")
	default:
		seen := map[string]bool{}
		for _, t := range d.ChallengeTypes {
			if !slices.Contains(Challenges, t) || seen[t] {
				problems = append(problems, fmt.Sprintf("challenge type %q is unknown or given twice (allowed: %s)", short(t), strings.Join(Challenges, ", ")))
			}
			seen[t] = true
		}
	}
	if d.Wildcards && !d.IncludeSubdomains {
		problems = append(problems, "wildcards cover sub-domains – they need include_subdomains")
	}
	if d.Wildcards && !d.AllowsChallenge(ChallengeDNS01) {
		problems = append(problems, "wildcards are proven by dns-01 only (RFC 8555 §7.1.3) – allow dns-01")
	}
	if len(d.IPRanges) > 0 && !d.AllowsChallenge(ChallengeHTTP01) {
		problems = append(problems, "IP identifiers are proven by http-01 only – allow http-01")
	}
	if d.ValidityDays < 0 {
		problems = append(problems, fmt.Sprintf("validity of %d days is not possible", d.ValidityDays))
	}
	p, ok := e.Presets.Get(d.Preset)
	switch {
	case !ok:
		problems = append(problems, fmt.Sprintf("there is no preset named %q", short(d.Preset)))
	case !slices.Contains(p.SubjectAltNames.Offered, preset.SANDNS):
		problems = append(problems, fmt.Sprintf("preset %q takes no DNS names – ACME needs a server preset", p.Name))
	case len(d.IPRanges) > 0 && !slices.Contains(p.SubjectAltNames.Offered, preset.SANIP):
		problems = append(problems, fmt.Sprintf("preset %q takes no IP addresses, but the domain has IP ranges", p.Name))
	case !slices.ContainsFunc(p.ExtKeyUsageOIDs(), func(o asn1.ObjectIdentifier) bool { return o.Equal(oidServerAuth) }):
		problems = append(problems, fmt.Sprintf("preset %q doesn't allow server authentication (serverAuth) – ACME certificates are TLS server certificates", p.Name))
	}

	// The CA: an active intermediate with an online key whose constraints
	// permit the domain.
	if d.CA == "" {
		return append(problems, "a domain needs the CA that signs for it"), nil, nil
	}
	is, err := loadIssuer(ctx, q, d.CA)
	var denied *DeniedError
	if errors.As(err, &denied) {
		return append(problems, denied.Reasons...), nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if denied := checkEKULimit(is.constraints, []asn1.ObjectIdentifier{oidServerAuth}); len(denied) > 0 {
		problems = append(problems, fmt.Sprintf("CA %q does not allow serverAuth required by preset %q", d.CA, d.Preset))
	}
	if is.ca.Kind == KindRoot {
		return append(problems, "a root CA only signs intermediate CAs – choose an intermediate"), nil, nil
	}
	d.CAID = is.ca.ID
	if d.ValidityDays > int(is.ca.MaxValidityDays) {
		problems = append(problems, fmt.Sprintf("validity of %d days exceeds the maximum of CA %q (%d days)", d.ValidityDays, d.CA, is.ca.MaxValidityDays))
	}
	if name != "" {
		probe := Names{DNS: []string{name}}
		if d.IncludeSubdomains {
			probe.DNS = append(probe.DNS, "sub."+name)
		}
		problems = append(problems, checkConstraints(is.constraints, probe, "")...)
	}
	for _, r := range d.IPRanges {
		problems = append(problems, checkConstraints(is.constraints, Names{IPs: []netip.Addr{r.Addr(), lastAddr(r)}}, "")...)
	}
	return problems, is, nil
}

// CreateDomain stores a new domain.
func (e *Engine) CreateDomain(ctx context.Context, req DomainRequest) (*Domain, error) {
	now := e.now()
	d, err := e.createDomain(ctx, req, now)
	return d, e.finishDomain(ctx, now, ActionDomainCreate, req.Who, "", req.Name, err)
}

func (e *Engine) createDomain(ctx context.Context, req DomainRequest, now time.Time) (*Domain, error) {
	if err := e.authorize(req.Who, authz.ManageCA, "", now); err != nil {
		return nil, err
	}
	q := pkidb.New(e.PKI)
	d := domainDefaults()
	d.Name = strings.TrimSpace(req.Name)
	problems := req.apply(&d)
	problems = append(problems, reasonProblems(req.Options)...)
	more, _, err := e.checkDomain(ctx, q, &d)
	if err != nil {
		return nil, err
	}
	problems = append(problems, more...)
	if _, gerr := q.GetDomainByName(ctx, d.Name); gerr == nil {
		problems = append(problems, fmt.Sprintf("domain %q exists already", short(d.Name)))
	} else if !errors.Is(gerr, sql.ErrNoRows) {
		return nil, gerr
	}
	if len(problems) > 0 {
		return nil, &DeniedError{Reasons: problems}
	}
	id, err := ids.New("dom", now, e.rand())
	if err != nil {
		return nil, err
	}
	d.ID, d.CreatedAt, d.UpdatedAt = id, now, now
	err = e.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		if cerr := settingsver.CheckExpected(ctx, settingsver.PKIBackend(q), settingsver.KindDomain, d.ID, req.Options.ExpectedVersion); cerr != nil {
			return cerr
		}
		if ierr := q.InsertDomain(ctx, domainRow(&d)); ierr != nil {
			return ierr
		}
		details := domainDetails(&d)
		res, rerr := recordDomain(ctx, q, settingsver.Entry{
			Kind: settingsver.KindDomain, ObjectID: d.ID, Change: settingsver.ChangeCreate, After: domainSnapshot(&d),
			Actor: versionActor(req.Who), Reason: req.Options.Reason, ExpectedVersion: req.Options.ExpectedVersion, Now: now,
		}, details)
		if rerr != nil {
			return rerr
		}
		d.Version = res.Version.Number
		return audit.Enqueue(ctx, tx, now, audit.Entry{
			Time: now, Actor: req.Who.Actor, Action: ActionDomainCreate, Target: audit.Target{Type: "domain", ID: d.ID},
			Result: audit.ResultSuccess, SourceIP: req.Who.SourceIP, Details: details,
		})
	})
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// reasonProblems is the problem list for a reason that is too long or holds a
// control character (a policy violation: 422 in the API, a message in the UI).
func reasonProblems(o ChangeOptions) []string {
	if settingsver.CheckReason(o.Reason) != nil {
		return []string{fmt.Sprintf("reason: at most %d characters, no control characters", settingsver.MaxReason)}
	}
	return nil
}

// UpdateDomain changes a domain; the name never changes.
func (e *Engine) UpdateDomain(ctx context.Context, id string, s DomainSettings, who keys.Who) (*Domain, error) {
	now := e.now()
	d, err := e.updateDomain(ctx, id, s, who, now)
	return d, e.finishDomain(ctx, now, ActionDomainUpdate, who, id, "", err)
}

func (e *Engine) updateDomain(ctx context.Context, id string, s DomainSettings, who keys.Who, now time.Time) (*Domain, error) {
	q := pkidb.New(e.PKI)
	d, err := e.loadDomain(ctx, q, who, id)
	if err != nil {
		return nil, err
	}
	if aerr := e.authorize(who, authz.ManageCA, d.CA, now); aerr != nil {
		return nil, aerr
	}
	before := domainDetails(d)
	problems := s.apply(d)
	problems = append(problems, reasonProblems(s.Options)...)
	more, _, err := e.checkDomain(ctx, q, d)
	if err != nil {
		return nil, err
	}
	if problems = append(problems, more...); len(problems) > 0 {
		return nil, &DeniedError{Reasons: problems}
	}
	if s.CA != nil && *s.CA != before["ca"] {
		// Moving to another CA needs the right on that CA as well.
		if aerr := e.authorize(who, authz.ManageCA, d.CA, now); aerr != nil {
			return nil, aerr
		}
	}
	d.UpdatedAt = now
	err = e.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		if cerr := settingsver.CheckExpected(ctx, settingsver.PKIBackend(q), settingsver.KindDomain, d.ID, s.Options.ExpectedVersion); cerr != nil {
			return cerr
		}
		// The state this write replaces, read inside the transaction: the
		// baseline of a domain without history, and the proof that it still
		// exists (it may have been deleted since it was loaded).
		current, berr := domainBefore(ctx, q, d.ID)
		if berr != nil {
			return berr
		}
		row := domainRow(d)
		if uerr := q.UpdateDomain(ctx, pkidb.UpdateDomainParams{
			CaID: row.CaID, IncludeSubdomains: row.IncludeSubdomains, Wildcards: row.Wildcards, ChallengeTypes: row.ChallengeTypes,
			Approval: row.Approval, Preset: row.Preset, ValidityDays: row.ValidityDays, AddressPolicy: row.AddressPolicy,
			IpRanges: row.IpRanges, UpdatedAt: row.UpdatedAt, ID: d.ID,
		}); uerr != nil {
			return uerr
		}
		details := map[string]any{"name": d.Name}
		after := domainDetails(d)
		for k, v := range after {
			if fmt.Sprint(before[k]) != fmt.Sprint(v) {
				details[k] = fmt.Sprintf("%v -> %v", before[k], v)
			}
		}
		res, rerr := recordDomain(ctx, q, settingsver.Entry{
			Kind: settingsver.KindDomain, ObjectID: d.ID, Change: settingsver.ChangeUpdate,
			Before: domainSnapshot(current), After: domainSnapshot(d), Actor: versionActor(who),
			Reason: s.Options.Reason, ExpectedVersion: s.Options.ExpectedVersion, Now: now,
		}, details)
		if rerr != nil {
			return rerr
		}
		d.Version = res.Version.Number
		return audit.Enqueue(ctx, tx, now, audit.Entry{
			Time: now, Actor: who.Actor, Action: ActionDomainUpdate, Target: audit.Target{Type: "domain", ID: d.ID},
			Result: audit.ResultSuccess, SourceIP: who.SourceIP, Details: details,
		})
	})
	if err != nil {
		return nil, err
	}
	return d, nil
}

// DeleteDomain removes a domain. Certificates already issued stay; open ACME
// orders for its names fail at finalize, which checks the domain again.
func (e *Engine) DeleteDomain(ctx context.Context, id string, who keys.Who) error {
	return e.DeleteDomainWith(ctx, id, ChangeOptions{}, who)
}

// DeleteDomainWith is DeleteDomain with the optional concurrency check and
// reason. The deleted state is kept as the last version of the domain.
func (e *Engine) DeleteDomainWith(ctx context.Context, id string, opts ChangeOptions, who keys.Who) error {
	now := e.now()
	_, err := e.deleteDomain(ctx, id, opts, who, now)
	return e.finishDomain(ctx, now, ActionDomainDelete, who, id, "", err)
}

func (e *Engine) deleteDomain(ctx context.Context, id string, opts ChangeOptions, who keys.Who, now time.Time) (*Domain, error) {
	q := pkidb.New(e.PKI)
	d, err := e.loadDomain(ctx, q, who, id)
	if err != nil {
		return nil, err
	}
	if aerr := e.authorize(who, authz.ManageCA, d.CA, now); aerr != nil {
		return nil, aerr
	}
	if problems := reasonProblems(opts); len(problems) > 0 {
		return nil, &DeniedError{Reasons: problems}
	}
	err = e.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		if cerr := settingsver.CheckExpected(ctx, settingsver.PKIBackend(q), settingsver.KindDomain, d.ID, opts.ExpectedVersion); cerr != nil {
			return cerr
		}
		// The deleted state, read inside the transaction.
		current, berr := domainBefore(ctx, q, d.ID)
		if berr != nil {
			return berr
		}
		if derr := q.DeleteDomain(ctx, d.ID); derr != nil {
			return derr
		}
		details := map[string]any{"name": d.Name, "ca": d.CA}
		snap := domainSnapshot(current)
		if _, rerr := recordDomain(ctx, q, settingsver.Entry{
			Kind: settingsver.KindDomain, ObjectID: d.ID, Change: settingsver.ChangeDelete, Before: snap, After: snap,
			Actor: versionActor(who), Reason: opts.Reason, ExpectedVersion: opts.ExpectedVersion, Now: now,
		}, details); rerr != nil {
			return rerr
		}
		return audit.Enqueue(ctx, tx, now, audit.Entry{
			Time: now, Actor: who.Actor, Action: ActionDomainDelete, Target: audit.Target{Type: "domain", ID: d.ID},
			Result: audit.ResultSuccess, SourceIP: who.SourceIP, Details: details,
		})
	})
	return d, err
}

// finishDomain audits a refused domain change.
func (e *Engine) finishDomain(ctx context.Context, now time.Time, action string, who keys.Who, id, name string, err error) error {
	if err == nil || errors.Is(err, ErrNotFound) {
		return err
	}
	target := id
	if target == "" {
		target = short(name)
	}
	if aerr := e.refuse(ctx, now, action, who, audit.Target{Type: "domain", ID: target}, map[string]any{"name": short(name)}, err); aerr != nil {
		return errors.Join(err, fmt.Errorf("audit: %w", aerr))
	}
	return err
}

// ListDomains returns the domains whose CA the caller may read, by name.
func (e *Engine) ListDomains(ctx context.Context, who keys.Who) ([]Domain, error) {
	q := pkidb.New(e.PKI)
	rows, err := q.ListDomains(ctx)
	if err != nil {
		return nil, err
	}
	names, err := caNames(ctx, q)
	if err != nil {
		return nil, err
	}
	now := e.now()
	out := make([]Domain, 0, len(rows))
	for _, r := range rows {
		d, derr := domainFromRow(r, names[r.CaID])
		if derr != nil {
			return nil, derr
		}
		if e.authorize(who, authz.ReadPKI, d.CA, now) == nil {
			out = append(out, *d)
		}
	}
	return out, nil
}

// GetDomain returns one domain; ErrNotFound when it doesn't exist or the
// caller may not read its CA (decision 64).
func (e *Engine) GetDomain(ctx context.Context, who keys.Who, id string) (*Domain, error) {
	q := pkidb.New(e.PKI)
	// The version is read before the domain: a change between the two reads
	// leaves the number older than the body, so an If-Match built from it
	// fails instead of overwriting that change.
	version, err := settingsver.Current(ctx, settingsver.PKIBackend(q), settingsver.KindDomain, id)
	if err != nil {
		return nil, err
	}
	d, err := e.loadDomain(ctx, q, who, id)
	if err != nil {
		return nil, err
	}
	d.Version = version
	return d, nil
}

func (e *Engine) loadDomain(ctx context.Context, q *pkidb.Queries, who keys.Who, id string) (*Domain, error) {
	r, err := q.GetDomain(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	ca, err := q.GetCA(ctx, r.CaID)
	if err != nil {
		return nil, err
	}
	if e.authorize(who, authz.ReadPKI, ca.Name, e.now()) != nil {
		return nil, ErrNotFound
	}
	return domainFromRow(r, ca.Name)
}

// DomainFor returns the most specific domain that covers a DNS name (a
// wildcard "*.x" counts as a name below x) or an IP address; nil without one.
func (e *Engine) DomainFor(ctx context.Context, identifierType, value string) (*Domain, error) {
	q := pkidb.New(e.PKI)
	rows, err := q.ListDomains(ctx)
	if err != nil {
		return nil, err
	}
	names, err := caNames(ctx, q)
	if err != nil {
		return nil, err
	}
	var best *Domain
	for _, r := range rows {
		d, derr := domainFromRow(r, names[r.CaID])
		if derr != nil {
			return nil, derr
		}
		if !d.Covers(identifierType, value) {
			continue
		}
		if best == nil || len(d.Name) > len(best.Name) {
			best = d
		}
	}
	return best, nil
}

// Covers reports whether d covers an identifier ("dns" or "ip"), with the
// domain's own rules for sub-domains, wildcards and IP ranges.
func (d *Domain) Covers(identifierType, value string) bool {
	switch identifierType {
	case "ip":
		a, err := netip.ParseAddr(value)
		if err != nil {
			return false
		}
		for _, r := range d.IPRanges {
			if r.Contains(a.Unmap()) {
				return true
			}
		}
		return false
	case "dns":
		name := strings.ToLower(value)
		if base, ok := strings.CutPrefix(name, "*."); ok {
			if !d.Wildcards {
				return false
			}
			return base == d.Name || strings.HasSuffix(base, "."+d.Name)
		}
		return name == d.Name || (d.IncludeSubdomains && strings.HasSuffix(name, "."+d.Name))
	}
	return false
}

func caNames(ctx context.Context, q *pkidb.Queries) (map[string]string, error) {
	cas, err := q.ListCAs(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(cas))
	for _, c := range cas {
		out[c.ID] = c.Name
	}
	return out, nil
}

func domainRow(d *Domain) pkidb.InsertDomainParams {
	ct, _ := json.Marshal(d.ChallengeTypes)
	ranges := make([]string, 0, len(d.IPRanges))
	for _, r := range d.IPRanges {
		ranges = append(ranges, r.String())
	}
	ir, _ := json.Marshal(ranges)
	v := sql.NullInt64{}
	if d.ValidityDays > 0 {
		v = sql.NullInt64{Int64: int64(d.ValidityDays), Valid: true}
	}
	return pkidb.InsertDomainParams{
		ID: d.ID, Name: d.Name, CaID: d.CAID, IncludeSubdomains: boolInt(d.IncludeSubdomains), Wildcards: boolInt(d.Wildcards),
		ChallengeTypes: string(ct), Approval: d.Approval, Preset: d.Preset, ValidityDays: v, AddressPolicy: d.AddressPolicy,
		IpRanges: string(ir), CreatedAt: d.CreatedAt.UTC().Format(dbTime), UpdatedAt: d.UpdatedAt.UTC().Format(dbTime),
	}
}

func domainFromRow(r pkidb.Domain, caName string) (*Domain, error) {
	d := &Domain{
		ID: r.ID, Name: r.Name, CA: caName, CAID: r.CaID, IncludeSubdomains: r.IncludeSubdomains == 1, Wildcards: r.Wildcards == 1,
		Approval: r.Approval, Preset: r.Preset, AddressPolicy: r.AddressPolicy,
	}
	if r.ValidityDays.Valid {
		d.ValidityDays = int(r.ValidityDays.Int64)
	}
	if err := json.Unmarshal([]byte(r.ChallengeTypes), &d.ChallengeTypes); err != nil {
		return nil, fmt.Errorf("domain %s: challenge types: %w", r.Name, err)
	}
	var ranges []string
	if err := json.Unmarshal([]byte(r.IpRanges), &ranges); err != nil {
		return nil, fmt.Errorf("domain %s: IP ranges: %w", r.Name, err)
	}
	for _, s := range ranges {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("domain %s: IP range %q: %w", r.Name, s, err)
		}
		d.IPRanges = append(d.IPRanges, p)
	}
	var err error
	if d.CreatedAt, err = time.Parse(dbTime, r.CreatedAt); err != nil {
		return nil, err
	}
	if d.UpdatedAt, err = time.Parse(dbTime, r.UpdatedAt); err != nil {
		return nil, err
	}
	return d, nil
}

func domainDetails(d *Domain) map[string]any {
	ranges := make([]string, 0, len(d.IPRanges))
	for _, r := range d.IPRanges {
		ranges = append(ranges, r.String())
	}
	return map[string]any{
		"name": d.Name, "ca": d.CA, "include_subdomains": d.IncludeSubdomains, "wildcards": d.Wildcards,
		"challenge_types": strings.Join(d.ChallengeTypes, ","), "approval": d.Approval, "preset": d.Preset,
		"validity_days": d.EffectiveValidityDays(), "address_policy": d.AddressPolicy, "ip_ranges": strings.Join(ranges, ","),
	}
}

// oidServerAuth is the TLS server authentication EKU (RFC 5280 §4.2.1.12).
var oidServerAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
