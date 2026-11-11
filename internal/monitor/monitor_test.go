package monitor

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/agents"
	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

var system = keys.Who{Actor: audit.Actor{Type: audit.ActorSystem, Name: "monitor"}, Principal: authz.System("monitor")}

type env struct {
	inst  *testinstance.Instance
	eval  *Evaluator
	store *Store
}

func newEnv(t *testing.T) *env {
	t.Helper()
	inst := testinstance.New(t, testinstance.Options{})
	inst.Unseal(t)
	return &env{
		inst:  inst,
		eval:  &Evaluator{Engine: inst.Engine, Seal: inst.Ring.Status, Rules: DefaultRules(), Who: system},
		store: &Store{DB: inst.SystemDB.Write, Tenant: "default"},
	}
}

func (e *env) issue(t *testing.T, days int, names ...string) *ca.Issued {
	t.Helper()
	issued, err := e.inst.Engine.Issue(t.Context(), ca.Request{CA: "issuing", Preset: "server", DNSNames: names, ValidityDays: days, Who: testinstance.Console})
	if err != nil {
		t.Fatal(err)
	}
	return issued
}

// run evaluates and syncs at the fake clock's time.
func (e *env) run(t *testing.T) ([]Finding, Changes) {
	t.Helper()
	now := e.inst.Clock.Now()
	found, err := e.eval.Evaluate(t.Context(), now)
	if err != nil {
		t.Fatal(err)
	}
	ch, err := e.store.Sync(t.Context(), now, found)
	if err != nil {
		t.Fatal(err)
	}
	return found, ch
}

func only(alerts []Alert, kind string) []Alert {
	var out []Alert
	for _, a := range alerts {
		if a.Kind == kind {
			out = append(out, a)
		}
	}
	return out
}

func byKind(found []Finding, kind string) []Finding {
	var out []Finding
	for _, f := range found {
		if f.Kind == kind {
			out = append(out, f)
		}
	}
	return out
}

// TestCertificateExpiry: warning at 14 days, critical at 3, expired stays
// critical; a renewal for the same names resolves it, one for other names
// does not.
func TestCertificateExpiry(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	cert := e.issue(t, 30, "www.homelab.lan")
	e.issue(t, 30, "other.homelab.lan", "www.homelab.lan") // a different name set
	e.issue(t, 365, "mail.homelab.lan")

	found, ch := e.run(t)
	if got := byKind(found, KindCertExpiry); len(got) != 0 {
		t.Fatalf("30 days left: %v", got)
	}
	if len(only(ch.Opened, KindCertExpiry)) != 0 {
		t.Fatalf("changes without findings: %+v", ch)
	}

	e.inst.Clock.Advance(17 * day) // 13 days left
	found, ch = e.run(t)
	got := byKind(found, KindCertExpiry)
	if len(got) != 2 || got[0].Severity != Warning || len(only(ch.Opened, KindCertExpiry)) != 2 {
		t.Fatalf("13 days left: %+v / %+v", got, ch)
	}
	if !strings.Contains(byKey(got, KindCertExpiry+":"+cert.ID).Detail, "renew it") {
		t.Errorf("detail: %q", got[0].Detail)
	}

	e.inst.Clock.Advance(11 * day) // 2 days left
	_, ch = e.run(t)
	if len(only(ch.Raised, KindCertExpiry)) != 2 || len(only(ch.Opened, KindCertExpiry)) != 0 {
		t.Fatalf("2 days left: %+v", ch)
	}

	e.inst.Clock.Advance(3 * day) // expired a day ago
	found, ch = e.run(t)
	if f := byKey(found, KindCertExpiry+":"+cert.ID); f.Severity != Critical || !strings.Contains(f.Detail, "EXPIRED") || len(only(ch.Opened, KindCertExpiry))+len(only(ch.Resolved, KindCertExpiry)) != 0 {
		t.Fatalf("expired: %+v / %+v", f, ch)
	}

	e.issue(t, 90, "www.homelab.lan") // renewed for exactly its names
	found, ch = e.run(t)
	if byKey(found, KindCertExpiry+":"+cert.ID).Key != "" || len(only(ch.Resolved, KindCertExpiry)) != 1 || only(ch.Resolved, KindCertExpiry)[0].Key != KindCertExpiry+":"+cert.ID {
		t.Fatalf("after the renewal: %+v / %+v", byKind(found, KindCertExpiry), ch)
	}
	if len(byKind(found, KindCertExpiry)) != 1 {
		t.Fatalf("the other name set must still alert: %+v", byKind(found, KindCertExpiry))
	}

	e.inst.Clock.Advance(31 * day) // the other one expired more than 30 days ago
	found, _ = e.run(t)
	if got := byKind(found, KindCertExpiry); len(got) != 0 {
		t.Fatalf("long expired certificates stay alerts: %+v", got)
	}
}

func byKey(found []Finding, key string) Finding {
	for _, f := range found {
		if f.Key == key {
			return f
		}
	}
	return Finding{}
}

// TestSealed: no alert for 10 minutes, then warning; critical once a CRL
// needs a signature within 24 hours; resolved by the unseal.
func TestSealed(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	if err := e.inst.Ring.Seal(t.Context(), testinstance.Console); err != nil {
		t.Fatal(err)
	}
	e.inst.Clock.Advance(9 * time.Minute)
	if found, _ := e.run(t); len(byKind(found, KindSealed)) != 0 {
		t.Fatal("sealed alert before 10 minutes")
	}
	e.inst.Clock.Advance(2 * time.Minute)
	found, ch := e.run(t)
	if s := byKind(found, KindSealed); len(s) != 1 || s[0].Severity != Warning || len(only(ch.Opened, KindSealed)) != 1 {
		t.Fatalf("sealed 11 minutes: %+v", s)
	}
	cas, err := e.inst.Engine.CAs(t.Context(), system)
	if err != nil {
		t.Fatal(err)
	}
	next := soonestCRL(cas)
	if next.IsZero() {
		t.Fatal("the test CA has no CRL")
	}
	e.inst.Clock.Set(next.Add(-23 * time.Hour))
	found, ch = e.run(t)
	if s := byKind(found, KindSealed); len(s) != 1 || s[0].Severity != Critical || len(only(ch.Raised, KindSealed)) != 1 {
		t.Fatalf("CRL within 24 hours: %+v / %+v", s, ch)
	}
	e.inst.Unseal(t)
	found, ch = e.run(t)
	if len(byKind(found, KindSealed)) != 0 || len(only(ch.Resolved, KindSealed)) != 1 {
		t.Fatalf("unsealed: %+v / %+v", byKind(found, KindSealed), ch)
	}
}

func soonestCRL(cas []ca.CAInfo) time.Time {
	var t time.Time
	for _, c := range cas {
		if c.KeyMode != ca.KeyModeOnlineEncrypted {
			continue
		}
		for _, g := range c.Generations {
			if g.CRL != nil && !g.CRL.NextUpdate.IsZero() && (t.IsZero() || g.CRL.NextUpdate.Before(t)) {
				t = g.CRL.NextUpdate
			}
		}
	}
	return t
}

// TestSyncIsIdempotent: the same findings twice change nothing; a finding
// that comes back after it was resolved opens a new alert.
func TestSyncIsIdempotent(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	now := e.inst.Clock.Now()
	f := []Finding{{Key: "x:1", Kind: "x", Subject: "one", Severity: Warning, Detail: "d"}}
	sync := func(at time.Time, fs []Finding) Changes {
		ch, err := e.store.Sync(context.Background(), at, fs)
		if err != nil {
			t.Fatal(err)
		}
		return ch
	}
	if ch := sync(now, f); len(ch.Opened) != 1 {
		t.Fatalf("first: %+v", ch)
	}
	if ch := sync(now.Add(time.Minute), f); !ch.Empty() {
		t.Fatalf("again: %+v", ch)
	}
	if ch := sync(now.Add(2*time.Minute), append(f, f...)); !ch.Empty() {
		t.Fatalf("duplicate finding: %+v", ch)
	}
	if ch := sync(now.Add(3*time.Minute), nil); len(ch.Resolved) != 1 {
		t.Fatalf("gone: %+v", ch)
	}
	if ch := sync(now.Add(4*time.Minute), f); len(ch.Opened) != 1 || ch.Opened[0].ID == "" {
		t.Fatalf("back: %+v", ch)
	}
	all, err := e.store.Since(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 || !all[0].Open() || all[1].Open() {
		t.Fatalf("history: %+v", all)
	}
}

type fakeAgents struct{ list []agents.Agent }

func (f *fakeAgents) ListAgents(context.Context, keys.Who) ([]agents.Agent, error) {
	return f.list, nil
}

func (f *fakeAgents) GetAgent(_ context.Context, _ keys.Who, id string) (*agents.Agent, error) {
	for i := range f.list {
		if f.list[i].ID == id {
			return &f.list[i], nil
		}
	}
	return nil, agents.ErrNotFound
}

// TestAgentRules: silent after 1 hour (critical after 24), an agent
// certificate below 48 hours, failed and rolled-back deployments; disabled
// agents and removed deployments never alert.
func TestAgentRules(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	now := e.inst.Clock.Now()
	short := e.issue(t, 1, "proxy1.homelab.lan") // stands in for an agent certificate with < 48 h
	fake := &fakeAgents{list: []agents.Agent{
		{ID: "agt_quiet", Hostname: "proxy1.homelab.lan", Status: agents.StatusActive, LastSeenAt: now.Add(-90 * time.Minute), CertificateID: short.ID,
			Deployments: []agents.Deployment{
				{Name: "web", State: "failed", LastError: "nginx -t failed"},
				{Name: "api", State: "rolled_back"},
				{Name: "old", State: "failed", Removed: true},
				{Name: "ok", State: "deployed"},
			}},
		{ID: "agt_gone", Hostname: "proxy2.homelab.lan", Status: agents.StatusActive, LastSeenAt: now.Add(-25 * time.Hour)},
		{ID: "agt_fresh", Hostname: "proxy3.homelab.lan", Status: agents.StatusActive, LastSeenAt: now.Add(-5 * time.Minute)},
		{ID: "agt_off", Hostname: "proxy4.homelab.lan", Status: "disabled", LastSeenAt: now.Add(-48 * time.Hour)},
	}}
	e.eval.Agents = fake
	found, err := e.eval.Evaluate(t.Context(), now)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		KindAgentSilent + ":agt_quiet":      Warning,
		KindAgentSilent + ":agt_gone":       Critical,
		KindAgentCertificate + ":agt_quiet": Critical,
		KindDeployFailed + ":agt_quiet/web": Warning,
		KindDeployFailed + ":agt_quiet/api": Warning,
	}
	got := map[string]string{}
	for _, f := range found {
		switch f.Kind {
		case KindAgentSilent, KindAgentCertificate, KindDeployFailed:
			got[f.Key] = f.Severity
		}
	}
	if len(got) != len(want) {
		t.Fatalf("agent findings: %v, want %v", got, want)
	}
	for k, sev := range want {
		if got[k] != sev {
			t.Errorf("%s = %q, want %q", k, got[k], sev)
		}
	}
	if d := byKey(found, KindDeployFailed+":agt_quiet/web").Detail; !strings.Contains(d, "nginx -t failed") || !strings.Contains(d, "journalctl -u myownpki-agent") {
		t.Errorf("deploy detail: %q", d)
	}
}
