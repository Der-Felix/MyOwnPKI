// Package report builds the datasets of the Reports page and GET /reports
// (docs/PHASE3.md section 14): the expiry forecast, the issuances per week by
// source, the certificates per CA and status, the alert history and the
// agent fleet.
//
// Everything is computed from data the server already holds, through the
// existing services with a system principal, after the caller passed the
// tenant-wide authz.ReadPKI check (Service.Get). Nothing is stored and
// nothing leaves the server: the package imports no network package.
//
// Untrusted text. CA names, agent host names and similar strings come from
// operators and, one step removed, from CSRs, ACME clients and agents. The
// datasets carry them as raw strings and never as markup; escaping is the
// job of the template and of the JSON encoder that render them.
package report

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/agents"
	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/monitor"
	"github.com/Der-Felix/MyOwnPKI/internal/version"
)

// Shape of the datasets (docs/PHASE3.md D7).
const (
	// ExpiryWeeks: the current ISO week and 12 more.
	ExpiryWeeks = 13
	// IssuanceWeeks: 12 weeks ending with the current one.
	IssuanceWeeks = 12
	// AlertWeeks: the current week and 4 before it, which covers what the
	// store keeps.
	AlertWeeks = 5
	// AlertRetentionDays is how long the monitor keeps resolved alerts
	// (internal/server/monitor.go, monitorKeep). The report does not change it.
	AlertRetentionDays = 30
	// CacheTTL is how long a built report is reused: the monitor's period.
	CacheTTL = time.Minute
)

const week = 7 * 24 * time.Hour

// Window tells whether an expiry week lies inside a monitor window.
type Window string

// Windows of an expiry week: it starts inside the critical window, inside
// the warning window, or later.
const (
	WindowCritical Window = "critical"
	WindowWarning  Window = "warning"
	WindowNone     Window = "none"
)

// Report is the five datasets, all times UTC. A cached Report is shared by
// every caller: treat it as read-only.
type Report struct {
	GeneratedAt time.Time
	Expiry      Expiry
	Issuances   Issuances
	// Authorities: one entry per CA with certificates and per active CA,
	// sorted by name; the external certificates (no CA) come last.
	Authorities []Authority
	Alerts      Alerts
	// Agents is nil when the agent listener is off.
	Agents *Fleet
}

// Expiry is the expiry timeline: when the valid certificates end.
type Expiry struct {
	Weeks []ExpiryWeek // ExpiryWeeks entries, the current week first
}

// ExpiryWeek counts the certificates (imported and external ones included,
// agent identity certificates and revoked ones not) that end in one ISO
// week. The current week counts only those that end after now.
type ExpiryWeek struct {
	Start  time.Time // Monday 00:00 UTC
	Count  int
	Window Window
}

// Issuances is the number of certificates issued per week and source.
type Issuances struct {
	Weeks []IssuanceWeek // IssuanceWeeks entries, the oldest first
}

// IssuanceWeek counts the certificates of source "issued" created in one ISO
// week: ACME clients, agents and the UI or API (docs/PHASE3.md D6). The
// current week is partial.
type IssuanceWeek struct {
	Start       time.Time
	ACME, Agent int
	UI          int
}

// Total is every issuance of the week.
func (w IssuanceWeek) Total() int { return w.ACME + w.Agent + w.UI }

// Authority is a CA with its certificate counts.
type Authority struct {
	ID, Name string
	// External: the certificates without a CA; ID and Name are empty and the
	// page gives it a label.
	External bool
	// Valid includes Expiring (it ends within ca.ExpiringWindow), the same
	// as the Certificates page with status "valid"; a chart that stacks the
	// four draws Valid-Expiring, Expiring, Expired and Revoked.
	Valid, Expiring, Expired, Revoked int64
}

// Alerts is the alert history the store keeps.
type Alerts struct {
	RetentionDays int
	// Weeks counts the alerts opened per ISO week by severity (the severity
	// they have now), the oldest week first.
	Weeks []AlertWeek
	// Open is how many alerts hold right now.
	Open int
}

// AlertWeek counts the alerts that were first seen in one week.
type AlertWeek struct {
	Start             time.Time
	Warning, Critical int
}

// Fleet is the agent fleet. The counts of states cover every agent; the
// version and deployment counts cover the agents that are not disabled or
// revoked, like the rules of the monitor.
type Fleet struct {
	// Active agents reported within AgentSilentWarn (or have not reported
	// yet, as the monitor treats them); then the silent ones.
	Active, SilentWarning, SilentCritical int
	Disabled, Revoked                     int
	Version                               VersionCounts
	Deployments                           DeploymentCounts
}

// VersionCounts compare the agent versions with the server's. Current
// includes an agent that is newer. Unknown: the server runs a development
// build or a version is not strict semver.
type VersionCounts struct{ Current, Older, Unknown int }

// DeploymentCounts are the deployments (removed ones not) by state.
type DeploymentCounts struct{ Deployed, Pending, Failed, RolledBack int }

// Engine is what the report reads from the CA engine (*ca.Engine).
type Engine interface {
	CAs(ctx context.Context, who keys.Who) ([]ca.CAInfo, error)
	CertificateCounts(ctx context.Context, who keys.Who, filters ...ca.CertificateFilter) (ca.Counts, map[string]ca.Counts, error)
	ExpiryTimes(ctx context.Context, who keys.Who, after, until time.Time) ([]time.Time, error)
	IssuanceSources(ctx context.Context, who keys.Who, since, until time.Time) ([]ca.Issuance, error)
}

// Agents is what the report reads about agents (*agents.Service).
type Agents interface {
	ListAgents(ctx context.Context, who keys.Who) ([]agents.Agent, error)
	GetAgent(ctx context.Context, who keys.Who, id string) (*agents.Agent, error)
}

// AlertStore is the alert store (*monitor.Store).
type AlertStore interface {
	Since(ctx context.Context, since time.Time) ([]monitor.Alert, error)
}

// Deps are the inputs of one tenant's report.
type Deps struct {
	Tenant string // for the permission check of Service.Get
	Engine Engine
	Agents Agents // nil = the agent listener is off, no fleet
	Alerts AlertStore
	Rules  monitor.Rules
	// ServerVersion is the running version, compared with the agents'.
	ServerVersion string
	Clock         clock.Clock
	// Who reads the data: a system principal that may read the whole tenant.
	// The zero value means authz.System("report").
	Who keys.Who
}

func (d *Deps) who() keys.Who {
	if d.Who.Principal != nil {
		return d.Who
	}
	return keys.Who{Actor: audit.Actor{Type: audit.ActorSystem, Name: "report"}, Principal: authz.System("report")}
}

// WeekStart is the Monday 00:00 UTC of the ISO week that contains t.
func WeekStart(t time.Time) time.Time {
	t = t.UTC()
	back := (int(t.Weekday()) + 6) % 7 // Monday = 0
	return time.Date(t.Year(), t.Month(), t.Day()-back, 0, 0, 0, 0, time.UTC)
}

// WeekLabel is the ISO week of t as "2026-W47".
func WeekLabel(t time.Time) string {
	y, w := t.UTC().ISOWeek()
	return fmt.Sprintf("%d-W%02d", y, w)
}

// Build reads the data and computes the five datasets at now. It does no
// permission check: Service.Get does, and is the way in.
func Build(ctx context.Context, d Deps, now time.Time) (*Report, error) {
	now = now.UTC()
	who := d.who()
	r := &Report{GeneratedAt: now}
	var err error
	if r.Expiry, err = buildExpiry(ctx, &d, who, now); err != nil {
		return nil, fmt.Errorf("report: expiry: %w", err)
	}
	if r.Issuances, err = buildIssuances(ctx, &d, who, now); err != nil {
		return nil, fmt.Errorf("report: issuances: %w", err)
	}
	if r.Authorities, err = buildAuthorities(ctx, &d, who); err != nil {
		return nil, fmt.Errorf("report: authorities: %w", err)
	}
	if r.Alerts, err = buildAlerts(ctx, &d, now); err != nil {
		return nil, fmt.Errorf("report: alerts: %w", err)
	}
	if d.Agents != nil {
		if r.Agents, err = buildFleet(ctx, &d, who, now); err != nil {
			return nil, fmt.Errorf("report: agents: %w", err)
		}
	}
	return r, nil
}

func buildExpiry(ctx context.Context, d *Deps, who keys.Who, now time.Time) (Expiry, error) {
	first := WeekStart(now)
	times, err := d.Engine.ExpiryTimes(ctx, who, now, first.Add(ExpiryWeeks*week))
	if err != nil {
		return Expiry{}, err
	}
	out := Expiry{Weeks: make([]ExpiryWeek, ExpiryWeeks)}
	for i := range out.Weeks {
		start := first.Add(time.Duration(i) * week)
		out.Weeks[i] = ExpiryWeek{Start: start, Window: windowOf(start, now, d.Rules)}
	}
	for _, t := range times {
		if i := bucket(first, t, ExpiryWeeks); i >= 0 && t.After(now) {
			out.Weeks[i].Count++
		}
	}
	return out, nil
}

// windowOf: a week is critical when it starts inside the critical window
// (counted from now; the current week starts at now), warning inside the
// warning window, else none.
func windowOf(start, now time.Time, r monitor.Rules) Window {
	if start.Before(now) {
		start = now
	}
	switch {
	case start.Before(now.Add(r.ExpiryCrit)):
		return WindowCritical
	case start.Before(now.Add(r.ExpiryWarn)):
		return WindowWarning
	}
	return WindowNone
}

// bucket is the index of the week of t counted from first, or -1 outside
// [first, first + n weeks).
func bucket(first, t time.Time, n int) int {
	if t.Before(first) {
		return -1
	}
	i := int(t.Sub(first) / week)
	if i >= n {
		return -1
	}
	return i
}

func buildIssuances(ctx context.Context, d *Deps, who keys.Who, now time.Time) (Issuances, error) {
	current := WeekStart(now)
	first := current.Add(-(IssuanceWeeks - 1) * week)
	list, err := d.Engine.IssuanceSources(ctx, who, first, current.Add(week))
	if err != nil {
		return Issuances{}, err
	}
	out := Issuances{Weeks: make([]IssuanceWeek, IssuanceWeeks)}
	for i := range out.Weeks {
		out.Weeks[i].Start = first.Add(time.Duration(i) * week)
	}
	for _, is := range list {
		i := bucket(first, is.At, IssuanceWeeks)
		if i < 0 {
			continue
		}
		switch is.Source {
		case ca.SourceACME:
			out.Weeks[i].ACME++
		case ca.SourceAgent:
			out.Weeks[i].Agent++
		default:
			out.Weeks[i].UI++
		}
	}
	return out, nil
}

func buildAuthorities(ctx context.Context, d *Deps, who keys.Who) ([]Authority, error) {
	cas, err := d.Engine.CAs(ctx, who)
	if err != nil {
		return nil, err
	}
	_, perCA, err := d.Engine.CertificateCounts(ctx, who, ca.CertificateFilter{HideAgentCertificates: true})
	if err != nil {
		return nil, err
	}
	var out []Authority
	for _, c := range cas {
		n, has := perCA[c.ID]
		if !has && c.Status != ca.StatusActive {
			continue
		}
		out = append(out, Authority{ID: c.ID, Name: c.Name, Valid: n.Valid, Expiring: n.Expiring, Expired: n.Expired, Revoked: n.Revoked})
	}
	slices.SortFunc(out, func(a, b Authority) int { return strings.Compare(a.Name, b.Name) })
	if n, ok := perCA[""]; ok && n.Total() > 0 {
		out = append(out, Authority{External: true, Valid: n.Valid, Expiring: n.Expiring, Expired: n.Expired, Revoked: n.Revoked})
	}
	return out, nil
}

func buildAlerts(ctx context.Context, d *Deps, now time.Time) (Alerts, error) {
	first := WeekStart(now).Add(-(AlertWeeks - 1) * week)
	list, err := d.Alerts.Since(ctx, now.Add(-AlertRetentionDays*24*time.Hour))
	if err != nil {
		return Alerts{}, err
	}
	out := Alerts{RetentionDays: AlertRetentionDays, Weeks: make([]AlertWeek, AlertWeeks)}
	for i := range out.Weeks {
		out.Weeks[i].Start = first.Add(time.Duration(i) * week)
	}
	for _, a := range list {
		if a.Open() {
			out.Open++
		}
		i := bucket(first, a.FirstSeen.UTC(), AlertWeeks)
		if i < 0 {
			continue // opened before the first week, or in the future
		}
		if a.Severity == monitor.Critical {
			out.Weeks[i].Critical++
		} else {
			out.Weeks[i].Warning++
		}
	}
	return out, nil
}

func buildFleet(ctx context.Context, d *Deps, who keys.Who, now time.Time) (*Fleet, error) {
	list, err := d.Agents.ListAgents(ctx, who)
	if err != nil {
		return nil, err
	}
	f := &Fleet{}
	for _, a := range list {
		switch a.Status {
		case agents.StatusDisabled:
			f.Disabled++
			continue
		case agents.StatusRevoked:
			f.Revoked++
			continue
		}
		var silent time.Duration // never reported: not silent, as in the monitor
		if !a.LastSeenAt.IsZero() {
			silent = now.Sub(a.LastSeenAt)
		}
		switch {
		case silent >= d.Rules.AgentSilentCrit:
			f.SilentCritical++
		case silent >= d.Rules.AgentSilentWarn:
			f.SilentWarning++
		default:
			f.Active++
		}
		switch versionClass(a.Version, d.ServerVersion) {
		case versionCurrent:
			f.Version.Current++
		case versionOlder:
			f.Version.Older++
		default:
			f.Version.Unknown++
		}
		// ListAgents carries no deployments; the monitor reads them the same way.
		full, err := d.Agents.GetAgent(ctx, who, a.ID)
		if err != nil {
			return nil, err
		}
		for _, dep := range full.Deployments {
			if dep.Removed {
				continue
			}
			switch dep.State {
			case "deployed":
				f.Deployments.Deployed++
			case "pending":
				f.Deployments.Pending++
			case "failed":
				f.Deployments.Failed++
			case "rolled_back":
				f.Deployments.RolledBack++
			}
		}
	}
	return f, nil
}

type versionKind int

const (
	versionUnknown versionKind = iota
	versionCurrent
	versionOlder
)

func versionClass(agent, server string) versionKind {
	cmp, err := version.Compare(agent, server)
	switch {
	case err != nil:
		return versionUnknown
	case cmp < 0:
		return versionOlder
	}
	return versionCurrent
}

// Service builds the report of one tenant and keeps the result for CacheTTL.
// It is the way in for the API and the pages.
type Service struct {
	deps Deps

	mu    sync.Mutex // held during a build: one build at a time
	cache *Report
}

// NewService returns the report service of one tenant.
func NewService(d Deps) *Service { return &Service{deps: d} }

// Get returns the report to who. The tenant-wide authz.ReadPKI check comes
// first and no data is read for a caller who fails it (a role limited to one
// CA does: the report names every CA, agent and alert of the tenant). The
// cache belongs to the tenant, not to the caller, and has no key that comes
// from a request. The Report is shared: do not change it.
func (s *Service) Get(ctx context.Context, who keys.Who) (*Report, error) {
	now := s.deps.Clock.Now().UTC()
	if err := who.Principal.Check(authz.ReadPKI, authz.Resource{Tenant: s.deps.Tenant}, now); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if age := now.Sub(s.cacheTime()); s.cache != nil && age >= 0 && age < CacheTTL {
		return s.cache, nil
	}
	r, err := Build(ctx, s.deps, now)
	if err != nil {
		return nil, err
	}
	s.cache = r
	return r, nil
}

func (s *Service) cacheTime() time.Time {
	if s.cache == nil {
		return time.Time{}
	}
	return s.cache.GeneratedAt
}
