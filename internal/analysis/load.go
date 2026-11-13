package analysis

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/agents"
	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/tlsscan"
)

// CacheTTL is how long a finished analysis is reused: the monitor's period.
const CacheTTL = time.Minute

// Engine is what Load reads from the CA engine (*ca.Engine).
type Engine interface {
	Certificates(ctx context.Context, who keys.Who, f ca.CertificateFilter) (*ca.CertificatePage, error)
	CAs(ctx context.Context, who keys.Who) ([]ca.CAInfo, error)
	CertificateTraits(ctx context.Context, who keys.Who) (map[string]ca.Traits, error)
	CertificateOrigins(ctx context.Context, who keys.Who) (map[string]ca.Origin, error)
	CertificateNames(ctx context.Context, who keys.Who) ([]ca.CertName, error)
	ACMEAccountActivity(ctx context.Context, who keys.Who) (accounts []ca.AccountActivity, truncated bool, err error)
	ListDomains(ctx context.Context, who keys.Who) ([]ca.Domain, error)
}

// Agents is what Load reads about agents (*agents.Service).
type Agents interface {
	ListAgents(ctx context.Context, who keys.Who) ([]agents.Agent, error)
	GetAgent(ctx context.Context, who keys.Who, id string) (*agents.Agent, error)
}

// Endpoints is the list of TLS endpoints (*tlsscan.Service). Only the stored
// result of the last scan is read; the analysis never connects anywhere.
type Endpoints interface {
	List(ctx context.Context, who keys.Who) ([]tlsscan.Endpoint, error)
}

// Deps are the inputs of one tenant's analysis.
type Deps struct {
	Tenant string // for the permission check of Service.Get
	Engine Engine
	Agents Agents    // nil = the agent listener is off
	Scan   Endpoints // nil = no scanning
	// ScanOff: scanning is switched off (monitor.scan_interval: off); the
	// endpoints that are entered then keep their last result, which no rule
	// should lean on.
	ScanOff       bool
	ServerVersion string
	Clock         clock.Clock
	// Who reads the data: a system principal that may read the whole tenant.
	// The zero value means authz.System("analysis").
	Who keys.Who
}

func (d *Deps) who() keys.Who {
	if d.Who.Principal != nil {
		return d.Who
	}
	return keys.Who{Actor: audit.Actor{Type: audit.ActorSystem, Name: "analysis"}, Principal: authz.System("analysis")}
}

// Load builds the snapshot at now through the existing services. It does no
// permission check: Service.Get does, and is the way in.
func Load(ctx context.Context, d Deps, now time.Time) (Snapshot, error) {
	now = now.UTC()
	who := d.who()
	s := Snapshot{Now: now, ServerVersion: d.ServerVersion}

	traits, err := d.Engine.CertificateTraits(ctx, who)
	if err != nil {
		return s, fmt.Errorf("analysis: certificate traits: %w", err)
	}
	origins, err := d.Engine.CertificateOrigins(ctx, who)
	if err != nil {
		return s, fmt.Errorf("analysis: certificate origins: %w", err)
	}
	convert := func(info *ca.CertificateInfo) Certificate {
		c := Certificate{
			ID: info.ID, Serial: info.Serial, Fingerprint: info.Fingerprint, Source: info.Source,
			CAID: info.CAID, CAName: info.CAName, DNSNames: info.DNSNames, IPs: info.IPs, CommonName: info.CommonName,
			NotBefore: info.NotBefore, NotAfter: info.NotAfter, CreatedAt: info.CreatedAt,
		}
		if o, ok := origins[info.ID]; ok {
			c.Class, c.IssuerKey = o.Class, o.Key
		}
		if t, ok := traits[info.ID]; ok {
			c.Traits = &t
		}
		return c
	}

	// Every valid certificate. The walk is paged like the monitor's.
	err = eachCertificate(ctx, d.Engine, who, ca.CertificateFilter{Status: ca.CertValid, HideAgentCertificates: true},
		func(info *ca.CertificateInfo) bool {
			s.Certificates = append(s.Certificates, convert(info))
			return true
		})
	if err != nil {
		return s, fmt.Errorf("analysis: certificates: %w", err)
	}
	// What was created lately (strictly inside the window, like the rule reads
	// it), newest first: the IDs sort by creation time,
	// so the walk stops at the first certificate that is older than the window.
	cutoff := now.Add(-RecentWindow)
	err = eachCertificate(ctx, d.Engine, who, ca.CertificateFilter{HideAgentCertificates: true},
		func(info *ca.CertificateInfo) bool {
			if !info.CreatedAt.After(cutoff) {
				return false
			}
			s.Recent = append(s.Recent, convert(info))
			return true
		})
	if err != nil {
		return s, fmt.Errorf("analysis: recent certificates: %w", err)
	}
	if s.Names, err = d.Engine.CertificateNames(ctx, who); err != nil {
		return s, fmt.Errorf("analysis: certificate names: %w", err)
	}

	cas, err := d.Engine.CAs(ctx, who)
	if err != nil {
		return s, fmt.Errorf("analysis: CAs: %w", err)
	}
	for i := range cas {
		s.CAs = append(s.CAs, convertCA(&cas[i]))
	}
	if s.Domains, err = d.Engine.ListDomains(ctx, who); err != nil {
		return s, fmt.Errorf("analysis: domains: %w", err)
	}
	accounts, truncated, err := d.Engine.ACMEAccountActivity(ctx, who)
	if err != nil {
		return s, fmt.Errorf("analysis: ACME accounts: %w", err)
	}
	if truncated {
		s.AccountsLimit = ca.MaxActivityAccounts
	}
	for _, a := range accounts {
		s.Accounts = append(s.Accounts, Account{ID: a.ID, Status: a.Status, AgentLinked: a.AgentLinked, CreatedAt: a.CreatedAt, LastOrderAt: a.LastOrderAt})
	}

	if d.Agents == nil {
		s.Missing.Agents = "the agent listener is off, so there is no agent data."
	} else if s.Agents, err = loadAgents(ctx, d.Agents, who); err != nil {
		return s, fmt.Errorf("analysis: agents: %w", err)
	}

	if d.Scan == nil || d.ScanOff {
		s.Missing.Scan = "the TLS scan is off, so no endpoint was scanned."
	} else {
		eps, err := d.Scan.List(ctx, who)
		if err != nil {
			return s, fmt.Errorf("analysis: endpoints: %w", err)
		}
		for i := range eps {
			ep := eps[i]
			s.Endpoints = append(s.Endpoints, Endpoint{
				ID: ep.ID, Host: ep.Host, Port: ep.Port, Name: ep.Name(),
				LastOKAt: ep.LastOKAt, Fingerprint: ep.Fingerprint, FingerprintSince: ep.FingerprintSince,
			})
		}
	}
	return s, nil
}

// eachCertificate walks the certificates a filter selects, page by page,
// until fn returns false.
func eachCertificate(ctx context.Context, e Engine, who keys.Who, f ca.CertificateFilter, fn func(*ca.CertificateInfo) bool) error {
	f.Limit = ca.MaxPageSize
	for {
		page, err := e.Certificates(ctx, who, f)
		if err != nil {
			return err
		}
		for i := range page.Items {
			if !fn(&page.Items[i]) {
				return nil
			}
		}
		if page.NextCursor == "" {
			return nil
		}
		f.Cursor = page.NextCursor
	}
}

func convertCA(info *ca.CAInfo) CA {
	out := CA{ID: info.ID, Name: info.Name, Issuing: info.Status == ca.StatusActive && info.KeyMode != ca.KeyModeOffline}
	for _, g := range info.Generations {
		end, _ := time.Parse(time.RFC3339, g.NotAfter) // zero if the column is empty or corrupt
		out.Generations = append(out.Generations, Generation{
			Number: g.Generation, Current: g.Current, Signed: !g.Pending && !end.IsZero(), Revoked: g.Revoked != "",
			Intermediate: g.Issuer != "", NotAfter: end.UTC(), Signature: g.SignatureAlgorithm,
		})
	}
	return out
}

func loadAgents(ctx context.Context, src Agents, who keys.Who) ([]Agent, error) {
	list, err := src.ListAgents(ctx, who)
	if err != nil {
		return nil, err
	}
	out := make([]Agent, 0, len(list))
	for _, a := range list {
		full, err := src.GetAgent(ctx, who, a.ID) // ListAgents carries no deployments
		if err != nil {
			return nil, err
		}
		ag := Agent{ID: a.ID, Hostname: a.Hostname, Version: a.Version, Status: a.Status}
		for _, dep := range full.Deployments {
			ag.Deployments = append(ag.Deployments, Deployment{
				Name: dep.Name, State: dep.State, Serial: dep.Serial, CertificateID: dep.CertificateID,
				Fingerprint: dep.Fingerprint, Removed: dep.Removed,
			})
		}
		out = append(out, ag)
	}
	return out, nil
}

// Analysis is the outcome of one run.
type Analysis struct {
	GeneratedAt time.Time
	// Results has one entry per rule, in the order of Rules.
	Results []Result
	// Findings are all findings of all rules, most severe first. Like
	// Results it holds at most MaxFindingsPerRule per rule; Summary counts
	// every finding.
	Findings []Finding
	Summary  Summary
}

// Only returns the analysis restricted to one rule, or false if there is no
// such rule. The summary then covers that rule only.
func (a *Analysis) Only(id string) (*Analysis, bool) {
	for _, r := range a.Results {
		if r.ID != id {
			continue
		}
		return &Analysis{GeneratedAt: a.GeneratedAt, Results: []Result{r}, Findings: Findings([]Result{r}), Summary: Summarize([]Result{r})}, true
	}
	return nil, false
}

// Analyze loads the snapshot and runs the rules at now.
func Analyze(ctx context.Context, d Deps, now time.Time) (*Analysis, error) {
	snap, err := Load(ctx, d, now)
	if err != nil {
		return nil, err
	}
	results := Run(snap)
	return &Analysis{GeneratedAt: snap.Now, Results: results, Findings: Findings(results), Summary: Summarize(results)}, nil
}

// Service runs the analysis of one tenant and keeps the result for CacheTTL.
// It is the way in for the API and the pages.
type Service struct {
	deps Deps

	mu    sync.Mutex // held during a run: one run at a time
	cache *Analysis
}

// NewService returns the analysis service of one tenant.
func NewService(d Deps) *Service { return &Service{deps: d} }

// Get returns the analysis to who. The tenant-wide authz.ReadPKI check comes
// first and nothing is read for a caller who fails it: findings name the CAs,
// hosts, accounts and domains of the whole tenant. The cache belongs to the
// tenant, not to the caller. The Analysis is shared: do not change it.
func (s *Service) Get(ctx context.Context, who keys.Who) (*Analysis, error) {
	now := s.deps.Clock.Now().UTC()
	if err := who.Principal.Check(authz.ReadPKI, authz.Resource{Tenant: s.deps.Tenant}, now); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cache != nil {
		if age := now.Sub(s.cache.GeneratedAt); age >= 0 && age < CacheTTL {
			return s.cache, nil
		}
	}
	a, err := Analyze(ctx, s.deps, now)
	if err != nil {
		return nil, err
	}
	s.cache = a
	return a, nil
}
