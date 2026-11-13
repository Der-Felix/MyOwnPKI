package analysis

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Der-Felix/MyOwnPKI/internal/agents"
	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/tlsscan"
)

// The real services satisfy the interfaces Load reads through.
var (
	_ Engine    = (*ca.Engine)(nil)
	_ Agents    = (*agents.Service)(nil)
	_ Endpoints = (*tlsscan.Service)(nil)
)

func TestRunKeepsTheOrderOfTheRules(t *testing.T) {
	t.Parallel()
	results := Run(Snapshot{Now: now})
	wantIDs := []string{"orphaned_certificate", "duplicate_certificates", "renewal_loop", "expiry_wave", "weak_key", "weak_signature",
		"ca_cliff", "outdated_agent", "unused_acme_account", "unused_domain"}
	if len(results) != 10 || len(Rules()) != 10 {
		t.Fatalf("%d results", len(results))
	}
	for i, r := range results {
		if r.ID != wantIDs[i] || r.Title == "" || Rules()[i].ID != r.ID {
			t.Errorf("result %d: %q %q", i, r.ID, r.Title)
		}
		if i != 0 && ruleOrder(r.ID) != i {
			t.Errorf("%s: order %d", r.ID, ruleOrder(r.ID))
		}
	}
	// An empty snapshot: the rules that need input say unknown, the rest ok,
	// and nothing is invented.
	states := map[string]string{}
	for _, r := range results {
		states[r.ID] = r.State
		if r.Counts.Total() != 0 || len(r.Findings) != 0 {
			t.Errorf("%s found something in an empty snapshot", r.ID)
		}
	}
	for id, state := range map[string]string{"expiry_wave": StateUnknown, "outdated_agent": StateUnknown, "orphaned_certificate": StateOK, "weak_key": StateOK} {
		if states[id] != state {
			t.Errorf("%s on an empty snapshot: %s, want %s", id, states[id], state)
		}
	}
	if sum := Summarize(results); sum != (Summary{Unknown: 2}) {
		t.Errorf("summary %+v", sum)
	}
}

// TestFindingsAreSortedAndCapped: most severe first, then rule, then subject;
// at most 200 findings per rule are kept and the rest is counted.
func TestFindingsAreSortedAndCapped(t *testing.T) {
	t.Parallel()
	weak := &ca.Traits{KeyAlgorithm: ca.TraitRSA, KeyBits: 1024, Signature: x509.SHA1WithRSA}
	var certs []Certificate
	for i := range 250 {
		certs = append(certs, cert(fmt.Sprintf("w%03d", i), func(c *Certificate) { c.Traits = weak }))
	}
	s := Snapshot{
		Now: now, ServerVersion: "0.3.8", Certificates: certs,
		Agents:   []Agent{{ID: "agt-1", Hostname: "h", Status: "active", Version: "0.3.0"}},
		Accounts: []Account{{ID: "acc-1", Status: "valid", CreatedAt: now.Add(-100 * day)}},
	}
	results := Run(s)
	byID := map[string]Result{}
	for _, r := range results {
		byID[r.ID] = r
	}
	wk := byID[RuleWeakKey]
	if wk.State != StateFindings || wk.Counts.Critical != 250 || len(wk.Findings) != MaxFindingsPerRule {
		t.Errorf("weak_key: %s, %+v, %d kept", wk.State, wk.Counts, len(wk.Findings))
	}
	if ws := byID[RuleWeakSignature]; ws.Counts.Critical != 250 || len(ws.Findings) != MaxFindingsPerRule {
		t.Errorf("weak_signature: %+v, %d kept", ws.Counts, len(ws.Findings))
	}
	// The kept findings are the first by subject.
	if wk.Findings[0].Subject != "w000.homelab.lan" || wk.Findings[199].Subject != "w199.homelab.lan" {
		t.Errorf("kept %s ... %s", wk.Findings[0].Subject, wk.Findings[199].Subject)
	}
	sum := Summarize(results)
	if sum.Critical != 500 || sum.Warning != 1 || sum.Info != 2 { // the wave of 250 certificates, the agent and the account
		t.Errorf("summary %+v counts every finding, also those beyond the cap", sum)
	}
	all := Findings(results)
	if len(all) != 2*MaxFindingsPerRule+3 {
		t.Fatalf("%d findings", len(all))
	}
	rank := map[string]int{SeverityCritical: 0, SeverityWarning: 1, SeverityInfo: 2}
	for i := 1; i < len(all); i++ {
		a, b := all[i-1], all[i]
		if rank[a.Severity] > rank[b.Severity] {
			t.Fatalf("finding %d (%s) before %d (%s)", i-1, a.Severity, i, b.Severity)
		}
		if a.Severity == b.Severity && ruleOrder(a.Rule) > ruleOrder(b.Rule) {
			t.Fatalf("rules out of order at %d: %s before %s", i, a.Rule, b.Rule)
		}
	}
	if all[len(all)-2].Severity != SeverityWarning && all[len(all)-2].Severity != SeverityInfo {
		t.Errorf("the tail is %s", all[len(all)-2].Severity)
	}
	// Run twice: the same input gives the same bytes.
	if fmt.Sprint(Run(s)) != fmt.Sprint(results) {
		t.Error("two runs differ")
	}
}

func TestOnlyFiltersByRule(t *testing.T) {
	t.Parallel()
	a := &Analysis{GeneratedAt: now, Results: Run(Snapshot{Now: now, Certificates: []Certificate{cert("k", func(c *Certificate) {
		c.Traits = &ca.Traits{KeyAlgorithm: ca.TraitRSA, KeyBits: 1024, Signature: x509.SHA256WithRSA}
	})}})}
	a.Findings, a.Summary = Findings(a.Results), Summarize(a.Results)
	one, ok := a.Only(RuleWeakKey)
	if !ok || len(one.Results) != 1 || len(one.Findings) != 1 || one.Summary.Critical != 1 || one.Summary.Unknown != 0 || !one.GeneratedAt.Equal(now) {
		t.Errorf("only: %+v %v", one, ok)
	}
	if _, ok := a.Only("no_such_rule"); ok {
		t.Error("an unknown rule was found")
	}
	if len(a.Results) != 10 {
		t.Error("Only changed the analysis")
	}
}

// TestHostileNamesStayRawAndClipped: names from CSRs, ACME and agents reach
// the findings as text of bounded length with no markup added or removed;
// escaping is the template's job.
func TestHostileNamesStayRawAndClipped(t *testing.T) {
	t.Parallel()
	evil := `<script>alert("x")</script>&'` + strings.Repeat("é", 4000)
	weak := func(c *Certificate) {
		c.Traits = &ca.Traits{KeyAlgorithm: ca.TraitRSA, KeyBits: 1024, Signature: x509.SHA1WithRSA}
	}
	s := Snapshot{
		Now: now, ServerVersion: "0.3.8",
		Certificates: []Certificate{cert("a", names(evil), weak), cert("b", func(c *Certificate) { c.DNSNames, c.CommonName = nil, evil }, weak)},
		Agents:       []Agent{{ID: "agt-1", Hostname: evil, Version: evil[:50], Status: "active"}, {ID: "agt-2", Hostname: evil, Version: "0.3.0", Status: "active"}},
		Domains:      []ca.Domain{{ID: "dom-1", Name: evil, CAID: "x", CreatedAt: now.Add(-90 * day)}},
		Accounts:     []Account{{ID: "acc-1", Status: "valid", CreatedAt: now.Add(-90 * day)}},
		CAs:          []CA{{ID: "ca-1", Name: evil, Issuing: true, Generations: []Generation{{Number: 1, Current: true, Signed: true, NotAfter: now.Add(day)}}}},
	}
	checked := 0
	for _, f := range Findings(Run(s)) {
		for name, text := range map[string]string{"subject": f.Subject, "seen": f.Seen, "key": f.Key, "href": f.Href} {
			// Fixed templates plus at most a few clipped values.
			if utf8.RuneCountInString(text) > 4*maxClip {
				t.Errorf("%s %s of %s has %d runes", f.Rule, name, f.Key[:10], utf8.RuneCountInString(text))
			}
			if !utf8.ValidString(text) {
				t.Errorf("%s %s is not valid UTF-8 (a clip cut a rune)", f.Rule, name)
			}
		}
		if strings.ContainsAny(f.Key, `<>"'& `) || strings.ContainsAny(f.Href, `<>"'& `) {
			t.Errorf("key or href with markup characters: %q %q", f.Key, f.Href)
		}
		if strings.Contains(f.Seen+f.Subject, "<script>") {
			checked++ // raw, not escaped here
		}
		if strings.Contains(f.Seen+f.Subject, "&lt;") {
			t.Errorf("%s escaped its text: the template must do that", f.Rule)
		}
	}
	if checked == 0 {
		t.Error("no finding carried the hostile name")
	}
}

// TestNoNetworkImports: nothing here talks to anything (docs/PHASE3.md D11).
// net/netip only parses addresses. The tlsscan package is imported for its
// types and the name matching; Load reads the stored result of the last scan
// and never starts one.
func TestNoNetworkImports(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	banned := []string{"net", "net/http", "net/rpc", "net/smtp", "net/mail", "net/textproto", "net/url", "crypto/tls", "os/exec",
		"golang.org/x/net", "google.golang.org/grpc", "connectrpc.com"}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), f, src, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range parsed.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			for _, b := range banned {
				if path != "net/netip" && (path == b || strings.HasPrefix(path, b+"/")) {
					t.Errorf("%s imports %s", f, path)
				}
			}
		}
	}
}

// --- Load ---------------------------------------------------------------------

type fakeEngine struct {
	calls atomic.Int64
	pages atomic.Int64
	who   []keys.Who
	err   error

	valid, all []ca.CertificateInfo // newest first
	traits     map[string]ca.Traits
	origins    map[string]ca.Origin
	names      []ca.CertName
	accounts   []ca.AccountActivity
	domains    []ca.Domain
	cas        []ca.CAInfo
}

func (f *fakeEngine) note(who keys.Who) error {
	f.calls.Add(1)
	f.who = append(f.who, who)
	return f.err
}

func (f *fakeEngine) Certificates(_ context.Context, who keys.Who, flt ca.CertificateFilter) (*ca.CertificatePage, error) {
	if err := f.note(who); err != nil {
		return nil, err
	}
	f.pages.Add(1)
	if !flt.HideAgentCertificates {
		return nil, errors.New("agent identity certificates must be hidden")
	}
	src := f.all
	if flt.Status == ca.CertValid {
		src = f.valid
	}
	start := 0
	if flt.Cursor != "" {
		start = slices.IndexFunc(src, func(c ca.CertificateInfo) bool { return c.ID == flt.Cursor }) + 1
	}
	end := min(start+flt.Limit, len(src))
	page := &ca.CertificatePage{Items: src[start:end]}
	if end < len(src) {
		page.NextCursor = src[end-1].ID
	}
	return page, nil
}

func (f *fakeEngine) CAs(_ context.Context, who keys.Who) ([]ca.CAInfo, error) {
	return f.cas, f.note(who)
}

func (f *fakeEngine) CertificateTraits(_ context.Context, who keys.Who) (map[string]ca.Traits, error) {
	return f.traits, f.note(who)
}

func (f *fakeEngine) CertificateOrigins(_ context.Context, who keys.Who) (map[string]ca.Origin, error) {
	return f.origins, f.note(who)
}

func (f *fakeEngine) CertificateNames(_ context.Context, who keys.Who) ([]ca.CertName, error) {
	return f.names, f.note(who)
}

func (f *fakeEngine) ACMEAccountActivity(_ context.Context, who keys.Who) ([]ca.AccountActivity, error) {
	return f.accounts, f.note(who)
}

func (f *fakeEngine) ListDomains(_ context.Context, who keys.Who) ([]ca.Domain, error) {
	return f.domains, f.note(who)
}

type fakeAgents struct {
	list []agents.Agent
	deps map[string][]agents.Deployment
}

func (f *fakeAgents) ListAgents(context.Context, keys.Who) ([]agents.Agent, error) {
	return f.list, nil
}

func (f *fakeAgents) GetAgent(_ context.Context, _ keys.Who, id string) (*agents.Agent, error) {
	return &agents.Agent{ID: id, Deployments: f.deps[id]}, nil
}

type fakeEndpoints struct{ list []tlsscan.Endpoint }

func (f fakeEndpoints) List(context.Context, keys.Who) ([]tlsscan.Endpoint, error) {
	return f.list, nil
}

func info(id string, created time.Time) ca.CertificateInfo {
	return ca.CertificateInfo{
		ID: id, Source: "issued", Status: ca.CertValid, CAID: "ca-1", CAName: "issuing", Serial: "S" + id, Fingerprint: "F" + id,
		DNSNames: []string{id + ".homelab.lan"}, CommonName: id + ".homelab.lan", NotBefore: created, NotAfter: created.Add(90 * day), CreatedAt: created,
	}
}

func TestLoad(t *testing.T) {
	t.Parallel()
	// 230 valid certificates (three pages), newest first; every fifth is recent.
	e := &fakeEngine{traits: map[string]ca.Traits{}, origins: map[string]ca.Origin{}}
	for i := range 230 {
		c := info(fmt.Sprintf("c%03d", 229-i), now.Add(-time.Duration(i)*day)) // c229 is today, c000 is 229 days old
		e.valid = append(e.valid, c)
		e.all = append(e.all, c)
		e.traits[c.ID] = ca.Traits{KeyAlgorithm: ca.TraitECDSA, KeyBits: 256, Signature: x509.ECDSAWithSHA256}
		e.origins[c.ID] = ca.Origin{Class: ca.SourceACME, Key: "acme:acc-1"}
	}
	delete(e.traits, "c229")  // not parsed
	delete(e.origins, "c228") // imported
	e.names = []ca.CertName{{Type: "dns", Value: "a.homelab.lan"}}
	e.accounts = []ca.AccountActivity{{ID: "acc-1", Status: "valid", CreatedAt: now.Add(-day)}, {ID: "acc-2", Status: "valid", AgentLinked: true, CreatedAt: now.Add(-day), LastOrderAt: now.Add(-time.Hour)}}
	e.domains = []ca.Domain{{ID: "dom-1", Name: "homelab.lan"}}
	e.cas = []ca.CAInfo{
		{ID: "root", Name: "root", Status: ca.StatusActive, KeyMode: ca.KeyModeOffline, Generations: []ca.GenerationInfo{
			{Generation: 1, Current: true, NotAfter: "2036-01-01T00:00:00Z", SignatureAlgorithm: x509.ECDSAWithSHA384}}},
		{ID: "sub", Name: "sub", Status: ca.StatusActive, KeyMode: ca.KeyModeOnlineEncrypted, Generations: []ca.GenerationInfo{
			{Generation: 1, Issuer: "root/1", NotAfter: "2026-12-01T00:00:00Z", Revoked: "superseded on 2026-11-01", SignatureAlgorithm: x509.SHA1WithRSA},
			{Generation: 2, Current: true, Issuer: "root/1", NotAfter: "2027-01-01T00:00:00Z", SignatureAlgorithm: x509.ECDSAWithSHA384},
			{Generation: 3, Pending: true}}},
		{ID: "old", Name: "old", Status: "retired", KeyMode: ca.KeyModeOnlineEncrypted},
	}
	ag := &fakeAgents{
		list: []agents.Agent{{ID: "agt-1", Hostname: "proxy-01", Status: agents.StatusActive, Version: "0.3.8"}, {ID: "agt-2", Hostname: "old-host", Status: agents.StatusRevoked, Version: "0.1.0"}},
		deps: map[string][]agents.Deployment{"agt-1": {{Name: "web", State: "deployed", Serial: "SX", CertificateID: "cx", Fingerprint: "FX"}, {Name: "gone", State: "deployed", Removed: true}}},
	}
	eps := fakeEndpoints{list: []tlsscan.Endpoint{
		{ID: "ep-1", Host: "10.0.0.5", SNI: "nas.homelab.lan", Port: 8443, LastOKAt: now.Add(-time.Hour), Fingerprint: "FP", FingerprintSince: now.Add(-10 * day)},
		{ID: "ep-2", Host: "web.homelab.lan", Port: 443},
	}}
	d := Deps{Tenant: "default", Engine: e, Agents: ag, Scan: eps, ServerVersion: "0.3.8", Clock: clock.NewFake(now)}

	s, err := Load(t.Context(), d, now)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Now.Equal(now) || s.ServerVersion != "0.3.8" || s.Missing != (Missing{}) {
		t.Errorf("header %+v %+v", s.Now, s.Missing)
	}
	if len(s.Certificates) != 230 {
		t.Fatalf("%d valid certificates (paging)", len(s.Certificates))
	}
	// Every walk used the system principal.
	for _, w := range e.who {
		if w.Principal == nil || w.Principal.Kind != authz.KindSystem || w.Actor.Type != audit.ActorSystem {
			t.Fatalf("read as %+v", w)
		}
	}
	byID := map[string]Certificate{}
	for _, c := range s.Certificates {
		byID[c.ID] = c
	}
	if c := byID["c010"]; c.Class != ca.SourceACME || c.IssuerKey != "acme:acc-1" || c.Traits == nil || c.Traits.KeyBits != 256 || c.Source != "issued" ||
		c.DNSNames[0] != "c010.homelab.lan" || c.Serial != "Sc010" || c.Fingerprint != "Fc010" || c.CAID != "ca-1" || c.CAName != "issuing" || c.CommonName == "" {
		t.Errorf("c010 %+v", c)
	}
	if c := byID["c229"]; c.Traits != nil {
		t.Errorf("a certificate without parsed traits has %+v", c.Traits)
	}
	if c := byID["c228"]; c.Class != "" || c.IssuerKey != "" {
		t.Errorf("a certificate without origin has %q %q", c.Class, c.IssuerKey)
	}
	// Recent stops at the window: today to 7 days ago minus a bit (days 0..6).
	if len(s.Recent) != 7 || s.Recent[0].ID != "c229" || s.Recent[6].ID != "c223" { // day 7 is exactly the window: outside
		var ids []string
		for _, r := range s.Recent {
			ids = append(ids, r.ID)
		}
		t.Errorf("recent: %v", ids)
	}
	if e.pages.Load() != 3+1 { // 230 valid in 3 pages, and one page is enough for the recent walk
		t.Errorf("%d pages read; the recent walk must stop early", e.pages.Load())
	}
	if len(s.Names) != 1 || len(s.Domains) != 1 || len(s.Accounts) != 2 || s.Accounts[1].AgentLinked != true || s.Accounts[0].ID != "acc-1" {
		t.Errorf("names %v domains %v accounts %+v", s.Names, s.Domains, s.Accounts)
	}

	// CAs.
	if len(s.CAs) != 3 {
		t.Fatalf("%d CAs", len(s.CAs))
	}
	root, sub, old := s.CAs[0], s.CAs[1], s.CAs[2]
	if root.Issuing || !sub.Issuing || old.Issuing {
		t.Errorf("issuing: root %v sub %v old %v", root.Issuing, sub.Issuing, old.Issuing)
	}
	if g := root.Generations[0]; g.Intermediate || !g.Signed || !g.Current || g.NotAfter.Year() != 2036 || g.Signature != x509.ECDSAWithSHA384 {
		t.Errorf("root generation %+v", g)
	}
	if g := sub.Generations[0]; !g.Intermediate || !g.Revoked || g.Current || g.Signature != x509.SHA1WithRSA {
		t.Errorf("revoked generation %+v", g)
	}
	if g := sub.Generations[1]; !g.Current || g.Revoked || !g.Signed {
		t.Errorf("current generation %+v", g)
	}
	if g := sub.Generations[2]; g.Signed || !g.NotAfter.IsZero() {
		t.Errorf("pending generation %+v", g)
	}

	// Agents with their deployments; endpoints with the name they are expected for.
	if len(s.Agents) != 2 || s.Agents[0].Hostname != "proxy-01" || len(s.Agents[0].Deployments) != 2 || s.Agents[0].Deployments[0].Serial != "SX" ||
		!s.Agents[0].Deployments[1].Removed || s.Agents[1].Status != agents.StatusRevoked {
		t.Errorf("agents %+v", s.Agents)
	}
	if len(s.Endpoints) != 2 || s.Endpoints[0].Name != "nas.homelab.lan" || s.Endpoints[1].Name != "web.homelab.lan" || s.Endpoints[0].Fingerprint != "FP" ||
		!s.Endpoints[0].FingerprintSince.Equal(now.Add(-10*day)) {
		t.Errorf("endpoints %+v", s.Endpoints)
	}

	// Missing input: no agent listener, scanning off.
	d.Agents, d.Scan = nil, nil
	s, err = Load(t.Context(), d, now)
	if err != nil || s.Missing.Agents == "" || s.Missing.Scan == "" || s.Agents != nil || s.Endpoints != nil {
		t.Errorf("without agents and scan: %+v %v", s.Missing, err)
	}
	d.Agents, d.Scan, d.ScanOff = ag, eps, true
	s, err = Load(t.Context(), d, now)
	if err != nil || s.Missing.Scan == "" || s.Missing.Agents != "" || s.Endpoints != nil {
		t.Errorf("scan off: %+v %v", s.Missing, err)
	}

	// The rules that depend on missing input say "unknown".
	d.Scan, d.ScanOff, d.ServerVersion = eps, false, "dev"
	a, err := Analyze(t.Context(), d, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range a.Results {
		if r.ID == RuleOutdatedAgent && r.State != StateUnknown {
			t.Errorf("outdated_agent under a dev server: %s", r.State)
		}
	}
	if a.Summary.Unknown == 0 || !a.GeneratedAt.Equal(now) {
		t.Errorf("summary %+v at %v", a.Summary, a.GeneratedAt)
	}

	// An error of a service is wrapped and returned, never swallowed.
	e.err = errors.New("db down")
	if _, err = Load(t.Context(), d, now); err == nil || !strings.Contains(err.Error(), "db down") {
		t.Errorf("error: %v", err)
	}
}

// --- Service ------------------------------------------------------------------

func viewer(bindings ...authz.Binding) keys.Who {
	for i := range bindings {
		bindings[i].Tenant = "default"
	}
	return keys.Who{Actor: audit.Actor{Type: audit.ActorUser, ID: "usr-1", Name: "u"},
		Principal: &authz.Principal{Kind: authz.KindUser, UserID: "usr-1", Username: "u", Bindings: bindings}}
}

func TestServicePermissionAndCache(t *testing.T) {
	t.Parallel()
	clk := clock.NewFake(now)
	e := &fakeEngine{}
	s := NewService(Deps{Tenant: "default", Engine: e, ServerVersion: "0.3.8", Clock: clk})

	// Permission before data.
	denied := map[string]keys.Who{
		"CA-scoped viewer": viewer(authz.Binding{CA: "issuing", Role: authz.Viewer}),
		"no role":          viewer(),
		"nobody":           {},
		"other tenant":     {Principal: &authz.Principal{Kind: authz.KindUser, Username: "x", Bindings: []authz.Binding{{Tenant: "other", Role: authz.Admin}}}},
	}
	for name, who := range denied {
		if a, err := s.Get(t.Context(), who); a != nil || !errors.Is(err, authz.ErrDenied) {
			t.Errorf("%s: %v %v", name, a, err)
		}
	}
	if e.calls.Load() != 0 {
		t.Fatalf("a denied caller caused %d reads", e.calls.Load())
	}

	first, err := s.Get(t.Context(), viewer(authz.Binding{Role: authz.Viewer}))
	if err != nil {
		t.Fatal(err)
	}
	reads := e.calls.Load()
	if reads == 0 || len(first.Results) != 10 {
		t.Fatalf("first run: %d reads, %d results", reads, len(first.Results))
	}
	for _, role := range []authz.Role{authz.Operator, authz.Admin} {
		again, gerr := s.Get(t.Context(), viewer(authz.Binding{Role: role}))
		if gerr != nil || again != first {
			t.Errorf("%s: %v same=%v", role, gerr, again == first)
		}
	}
	clk.Advance(59 * time.Second)
	if again, _ := s.Get(t.Context(), viewer(authz.Binding{Role: authz.Viewer})); again != first || e.calls.Load() != reads {
		t.Errorf("a call within the minute read again")
	}
	// A denied caller gets nothing while a result is cached.
	if a, derr := s.Get(t.Context(), denied["CA-scoped viewer"]); a != nil || !errors.Is(derr, authz.ErrDenied) {
		t.Errorf("cache leaked: %v %v", a, derr)
	}
	clk.Advance(time.Second)
	next, err := s.Get(t.Context(), viewer(authz.Binding{Role: authz.Viewer}))
	if err != nil || next == first || e.calls.Load() == reads || !next.GeneratedAt.Equal(now.Add(time.Minute)) {
		t.Errorf("the next minute: %v same=%v", err, next == first)
	}
	// An error is not kept.
	clk.Advance(time.Hour)
	e.err = errors.New("db down")
	if _, err := s.Get(t.Context(), keys.Who{Principal: authz.System("x")}); err == nil {
		t.Error("error swallowed")
	}
	e.err = nil
	if _, err := s.Get(t.Context(), keys.Who{Principal: authz.System("x")}); err != nil {
		t.Errorf("after the error: %v", err)
	}
}
