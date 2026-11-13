package report

import (
	"context"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/agents"
	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/monitor"
)

// wed is a Wednesday in ISO week 2026-W46.
var wed = time.Date(2026, 11, 11, 10, 30, 0, 0, time.UTC)

// mon is the Monday of the week of wed.
var mon = time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)

type fakeEngine struct {
	calls     atomic.Int64
	expiry    []time.Time
	issuances []ca.Issuance
	cas       []ca.CAInfo
	counts    map[string]ca.Counts
	err       error
	// Records the window the report asked for.
	after, until, since, issuedUntil time.Time
}

func (f *fakeEngine) CAs(context.Context, keys.Who) ([]ca.CAInfo, error) {
	f.calls.Add(1)
	return f.cas, f.err
}

func (f *fakeEngine) CertificateCounts(_ context.Context, _ keys.Who, filters ...ca.CertificateFilter) (ca.Counts, map[string]ca.Counts, error) {
	f.calls.Add(1)
	if len(filters) != 1 || !filters[0].HideAgentCertificates {
		return ca.Counts{}, nil, errors.New("the report must hide agent identity certificates")
	}
	return ca.Counts{}, f.counts, f.err
}

func (f *fakeEngine) ExpiryTimes(_ context.Context, _ keys.Who, after, until time.Time) ([]time.Time, error) {
	f.calls.Add(1)
	f.after, f.until = after, until
	return f.expiry, f.err
}

func (f *fakeEngine) IssuanceSources(_ context.Context, _ keys.Who, since, until time.Time) ([]ca.Issuance, error) {
	f.calls.Add(1)
	f.since, f.issuedUntil = since, until
	return f.issuances, f.err
}

type fakeAlerts struct {
	calls atomic.Int64
	list  []monitor.Alert
	since time.Time
}

func (f *fakeAlerts) Since(_ context.Context, since time.Time) ([]monitor.Alert, error) {
	f.calls.Add(1)
	f.since = since
	return f.list, nil
}

type fakeAgents struct {
	list []agents.Agent
	deps map[string][]agents.Deployment
	// gone are agents that ListAgents still lists but GetAgent no longer finds.
	gone map[string]bool
}

func (f *fakeAgents) ListAgents(context.Context, keys.Who) ([]agents.Agent, error) {
	return f.list, nil
}

func (f *fakeAgents) GetAgent(_ context.Context, _ keys.Who, id string) (*agents.Agent, error) {
	if f.gone[id] {
		return nil, fmt.Errorf("agent %s: %w", id, agents.ErrNotFound)
	}
	return &agents.Agent{ID: id, Deployments: f.deps[id]}, nil
}

func deps(e *fakeEngine, clk clock.Clock) Deps {
	return Deps{Tenant: "default", Engine: e, Alerts: &fakeAlerts{}, Rules: monitor.DefaultRules(), ServerVersion: "0.3.8", Clock: clk}
}

func user(bindings ...authz.Binding) keys.Who {
	for i := range bindings {
		bindings[i].Tenant = "default"
	}
	return keys.Who{
		Actor:     audit.Actor{Type: audit.ActorUser, ID: "usr-1", Name: "u"},
		Principal: &authz.Principal{Kind: authz.KindUser, UserID: "usr-1", Username: "u", Bindings: bindings},
	}
}

func TestWeekStartAndLabel(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in    time.Time
		start time.Time
		label string
	}{
		{wed, mon, "2026-W46"},
		{mon, mon, "2026-W46"},
		{mon.Add(-time.Nanosecond), mon.Add(-7 * 24 * time.Hour), "2026-W45"},
		{time.Date(2026, 11, 15, 23, 59, 59, 0, time.UTC), mon, "2026-W46"}, // Sunday
		{time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC), mon.Add(7 * 24 * time.Hour), "2026-W47"},
		// 2026 has 53 ISO weeks: week 53 runs 2026-12-28 to 2027-01-03.
		{time.Date(2026, 12, 31, 12, 0, 0, 0, time.UTC), time.Date(2026, 12, 28, 0, 0, 0, 0, time.UTC), "2026-W53"},
		{time.Date(2027, 1, 3, 23, 59, 59, 0, time.UTC), time.Date(2026, 12, 28, 0, 0, 0, 0, time.UTC), "2026-W53"},
		{time.Date(2027, 1, 4, 0, 0, 0, 0, time.UTC), time.Date(2027, 1, 4, 0, 0, 0, 0, time.UTC), "2027-W01"},
		// A time zone is converted to UTC first: Sunday 23:30 in UTC-5 is Monday in UTC.
		{time.Date(2026, 11, 15, 23, 30, 0, 0, time.FixedZone("x", -5*3600)), mon.Add(7 * 24 * time.Hour), "2026-W47"},
	} {
		if got := WeekStart(tc.in); !got.Equal(tc.start) || got.Location() != time.UTC {
			t.Errorf("WeekStart(%v) = %v, want %v", tc.in, got, tc.start)
		}
		if got := WeekLabel(tc.in); got != tc.label {
			t.Errorf("WeekLabel(%v) = %s, want %s", tc.in, got, tc.label)
		}
	}
}

// TestExpiryWeekBorders: the last second of Sunday belongs to the old week,
// Monday 00:00:00 to the next; the current week counts only what ends after
// now; certificates beyond the 13th week are not counted.
func TestExpiryWeekBorders(t *testing.T) {
	t.Parallel()
	next := mon.Add(7 * 24 * time.Hour)
	e := &fakeEngine{expiry: []time.Time{
		wed.Add(-time.Second),                    // already ended: not counted
		wed.Add(time.Second),                     // current week
		next.Add(-time.Second),                   // Sunday 23:59:59: still the current week
		next,                                     // Monday 00:00:00: week 2
		next.Add(7*24*time.Hour - time.Second),   // week 2
		mon.Add(13 * 7 * 24 * time.Hour),         // first instant after week 13: dropped
		mon.Add(13*7*24*time.Hour - time.Second), // last second of week 13
		mon.Add(12 * 7 * 24 * time.Hour),         // week 13
	}}
	r, err := Build(t.Context(), deps(e, clock.NewFake(wed)), wed)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Expiry.Weeks) != ExpiryWeeks {
		t.Fatalf("%d weeks", len(r.Expiry.Weeks))
	}
	got := make([]int, ExpiryWeeks)
	for i, w := range r.Expiry.Weeks {
		got[i] = w.Count
		if want := mon.Add(time.Duration(i) * 7 * 24 * time.Hour); !w.Start.Equal(want) {
			t.Errorf("week %d starts %v, want %v", i, w.Start, want)
		}
	}
	want := []int{2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	if !slices.Equal(got, want) {
		t.Errorf("counts %v, want %v", got, want)
	}
	if !e.after.Equal(wed) || !e.until.Equal(mon.Add(13*7*24*time.Hour)) {
		t.Errorf("asked for (%v, %v]", e.after, e.until)
	}
}

// TestExpiryWindows: warning and critical come from monitor.Rules; the
// current week starts "now" for this purpose.
func TestExpiryWindows(t *testing.T) {
	t.Parallel()
	// Wednesday 10:30: critical window 3 days -> to Saturday 10:30 (current
	// week); warning 14 days -> to Wednesday 2026-11-25 10:30 (weeks 2 and 3
	// start Mon 16 and Mon 23, both inside).
	r, err := Build(t.Context(), deps(&fakeEngine{}, clock.NewFake(wed)), wed)
	if err != nil {
		t.Fatal(err)
	}
	want := []Window{WindowCritical, WindowWarning, WindowWarning, WindowNone}
	for i, w := range want {
		if r.Expiry.Weeks[i].Window != w {
			t.Errorf("week %d: %s, want %s", i, r.Expiry.Weeks[i].Window, w)
		}
	}
	// A week that starts exactly at the end of a window is outside it.
	rules := monitor.DefaultRules()
	if got := windowOf(wed.Add(rules.ExpiryWarn), wed, rules); got != WindowNone {
		t.Errorf("start at the end of the warning window: %s", got)
	}
	if got := windowOf(wed.Add(rules.ExpiryWarn-time.Second), wed, rules); got != WindowWarning {
		t.Errorf("start just inside the warning window: %s", got)
	}
	if got := windowOf(wed.Add(rules.ExpiryCrit-time.Second), wed, rules); got != WindowCritical {
		t.Errorf("start just inside the critical window: %s", got)
	}
}

// TestFiftyThreeWeekYear: the timeline over the turn of a 53-week year has 13
// distinct, consecutive weeks and the right labels.
func TestFiftyThreeWeekYear(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 12, 16, 9, 0, 0, 0, time.UTC) // Wednesday, 2026-W51
	e := &fakeEngine{expiry: []time.Time{time.Date(2027, 1, 1, 12, 0, 0, 0, time.UTC)}}
	r, err := Build(t.Context(), deps(e, clock.NewFake(now)), now)
	if err != nil {
		t.Fatal(err)
	}
	var labels []string
	for _, w := range r.Expiry.Weeks {
		labels = append(labels, WeekLabel(w.Start))
	}
	want := []string{"2026-W51", "2026-W52", "2026-W53", "2027-W01", "2027-W02", "2027-W03", "2027-W04", "2027-W05",
		"2027-W06", "2027-W07", "2027-W08", "2027-W09", "2027-W10"}
	if !slices.Equal(labels, want) {
		t.Errorf("labels %v", labels)
	}
	if r.Expiry.Weeks[2].Count != 1 { // 2027-01-01 is a Friday of 2026-W53
		t.Errorf("counts: %+v", r.Expiry.Weeks[:4])
	}
}

func TestIssuanceBuckets(t *testing.T) {
	t.Parallel()
	first := mon.Add(-11 * 7 * 24 * time.Hour)
	e := &fakeEngine{issuances: []ca.Issuance{
		{At: first, Source: ca.SourceACME},                       // first instant of week 1
		{At: first.Add(-time.Nanosecond), Source: ca.SourceACME}, // before: dropped
		{At: mon.Add(-time.Second), Source: ca.SourceUI},         // Sunday 23:59:59 of week 11
		{At: mon, Source: ca.SourceAgent},                        // Monday 00:00:00: current week
		{At: wed, Source: ca.SourceAgent},                        // current week
		{At: wed, Source: ca.SourceACME},                         // current week
		{At: mon.Add(7 * 24 * time.Hour), Source: ca.SourceUI},   // next week: dropped
	}}
	r, err := Build(t.Context(), deps(e, clock.NewFake(wed)), wed)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Issuances.Weeks) != IssuanceWeeks {
		t.Fatalf("%d weeks", len(r.Issuances.Weeks))
	}
	if !r.Issuances.Weeks[0].Start.Equal(first) || !r.Issuances.Weeks[11].Start.Equal(mon) {
		t.Errorf("weeks run %v to %v", r.Issuances.Weeks[0].Start, r.Issuances.Weeks[11].Start)
	}
	w0, w10, w11 := r.Issuances.Weeks[0], r.Issuances.Weeks[10], r.Issuances.Weeks[11]
	if w0.ACME != 1 || w0.Total() != 1 {
		t.Errorf("first week %+v", w0)
	}
	if w10.UI != 1 || w10.Total() != 1 {
		t.Errorf("Sunday 23:59:59 %+v", w10)
	}
	if w11.Agent != 2 || w11.ACME != 1 || w11.UI != 0 {
		t.Errorf("current week %+v", w11)
	}
	if !e.since.Equal(first) || !e.issuedUntil.Equal(mon.Add(7*24*time.Hour)) {
		t.Errorf("asked for [%v, %v)", e.since, e.issuedUntil)
	}
}

// TestEmptyTenant: no data gives full, empty weeks and no agent block.
func TestEmptyTenant(t *testing.T) {
	t.Parallel()
	r, err := Build(t.Context(), deps(&fakeEngine{}, clock.NewFake(wed)), wed)
	if err != nil {
		t.Fatal(err)
	}
	if !r.GeneratedAt.Equal(wed) || len(r.Expiry.Weeks) != 13 || len(r.Issuances.Weeks) != 12 || len(r.Alerts.Weeks) != 5 {
		t.Errorf("shape: %+v", r)
	}
	for _, w := range r.Expiry.Weeks {
		if w.Count != 0 {
			t.Errorf("expiry %+v", w)
		}
	}
	for _, w := range r.Issuances.Weeks {
		if w.Total() != 0 {
			t.Errorf("issuance %+v", w)
		}
	}
	if len(r.Authorities) != 0 || r.Agents != nil || r.Alerts.Open != 0 || r.Alerts.RetentionDays != 30 {
		t.Errorf("rest: %+v", r)
	}
}

func TestAuthorities(t *testing.T) {
	t.Parallel()
	e := &fakeEngine{
		cas: []ca.CAInfo{
			{ID: "ca-b", Name: "zeta", Status: ca.StatusActive},
			{ID: "ca-a", Name: "alpha", Status: ca.StatusActive},
			{ID: "ca-r", Name: "retired-empty", Status: "retired"},
			{ID: "ca-s", Name: "retired-used", Status: "retired"},
		},
		counts: map[string]ca.Counts{
			"ca-a": {Valid: 5, Expiring: 2, Expired: 1, Revoked: 3},
			"ca-s": {Revoked: 1},
			"":     {Valid: 1},
		},
	}
	r, err := Build(t.Context(), deps(e, clock.NewFake(wed)), wed)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, a := range r.Authorities {
		names = append(names, a.Name)
	}
	if !slices.Equal(names, []string{"alpha", "retired-used", "zeta", ""}) {
		t.Fatalf("authorities %v", names)
	}
	if a := r.Authorities[0]; a.Valid != 5 || a.Expiring != 2 || a.Expired != 1 || a.Revoked != 3 || a.External {
		t.Errorf("alpha %+v", a)
	}
	if a := r.Authorities[3]; !a.External || a.ID != "" || a.Valid != 1 {
		t.Errorf("external %+v", a)
	}
}

func TestAlertHistory(t *testing.T) {
	t.Parallel()
	al := &fakeAlerts{list: []monitor.Alert{
		{ID: "1", Severity: monitor.Critical, FirstSeen: wed.Add(-time.Hour)},                                                          // current week, open
		{ID: "2", Severity: monitor.Warning, FirstSeen: wed.Add(-2 * time.Hour), Resolved: wed.Add(-time.Hour)},                        // current week, resolved
		{ID: "3", Severity: monitor.Warning, FirstSeen: mon.Add(-4 * 7 * 24 * time.Hour)},                                              // first column, open
		{ID: "4", Severity: monitor.Critical, FirstSeen: mon.Add(-4*7*24*time.Hour - time.Second), Resolved: wed.Add(-24 * time.Hour)}, // before the first column
		{ID: "5", Severity: monitor.Warning, FirstSeen: mon.Add(-time.Second), Resolved: wed.Add(-24 * time.Hour)},                     // Sunday 23:59:59 before: week 4
	}}
	d := deps(&fakeEngine{}, clock.NewFake(wed))
	d.Alerts = al
	r, err := Build(t.Context(), d, wed)
	if err != nil {
		t.Fatal(err)
	}
	if !al.since.Equal(wed.Add(-30 * 24 * time.Hour)) {
		t.Errorf("asked since %v", al.since)
	}
	if r.Alerts.Open != 2 { // alerts 1 and 3 have no resolved time
		t.Errorf("open %d", r.Alerts.Open)
	}
	got := r.Alerts.Weeks
	if got[4].Critical != 1 || got[4].Warning != 1 {
		t.Errorf("current week %+v", got[4])
	}
	if got[0].Warning != 1 || got[0].Critical != 0 {
		t.Errorf("first week %+v", got[0])
	}
	if got[3].Warning != 1 {
		t.Errorf("week before the current one %+v", got[3])
	}
}

func TestFleet(t *testing.T) {
	t.Parallel()
	rules := monitor.DefaultRules()
	ag := &fakeAgents{
		list: []agents.Agent{
			{ID: "a1", Status: agents.StatusActive, LastSeenAt: wed.Add(-time.Minute), Version: "0.3.8"},
			{ID: "a2", Status: agents.StatusActive, LastSeenAt: wed.Add(-rules.AgentSilentWarn), Version: "0.3.2"}, // exactly the warn threshold
			{ID: "a3", Status: agents.StatusActive, LastSeenAt: wed.Add(-rules.AgentSilentCrit), Version: "0.4.0"}, // exactly critical; newer
			{ID: "a4", Status: agents.StatusActive, Version: "dev"},                                                // never reported
			{ID: "a5", Status: agents.StatusDisabled, Version: "0.1.0"},
			{ID: "a6", Status: agents.StatusRevoked, Version: "0.1.0"},
		},
		deps: map[string][]agents.Deployment{
			"a1": {{State: "deployed"}, {State: "deployed"}, {State: "pending"}, {State: "failed", Removed: true}},
			"a2": {{State: "failed"}, {State: "rolled_back"}},
			"a5": {{State: "failed"}}, // not read: disabled
		},
	}
	d := deps(&fakeEngine{}, clock.NewFake(wed))
	d.Agents = ag
	r, err := Build(t.Context(), d, wed)
	if err != nil {
		t.Fatal(err)
	}
	f := r.Agents
	if f == nil {
		t.Fatal("no fleet")
	}
	if f.Active != 2 || f.SilentWarning != 1 || f.SilentCritical != 1 || f.Disabled != 1 || f.Revoked != 1 {
		t.Errorf("states %+v", f)
	}
	if f.Version != (VersionCounts{Current: 2, Older: 1, Unknown: 1}) {
		t.Errorf("versions %+v", f.Version)
	}
	if f.Deployments != (DeploymentCounts{Deployed: 2, Pending: 1, Failed: 1, RolledBack: 1}) {
		t.Errorf("deployments %+v", f.Deployments)
	}

	// A development server cannot tell old from new.
	d.ServerVersion = "dev"
	r, err = Build(t.Context(), d, wed)
	if err != nil {
		t.Fatal(err)
	}
	if r.Agents.Version != (VersionCounts{Unknown: 4}) {
		t.Errorf("versions under a dev server %+v", r.Agents.Version)
	}
}

// TestCache: a second call within a minute reads nothing, the next minute
// reads again; errors are not cached.
func TestCache(t *testing.T) {
	t.Parallel()
	clk := clock.NewFake(wed)
	e := &fakeEngine{}
	d := deps(e, clk)
	al := &fakeAlerts{}
	d.Alerts = al
	s := NewService(d)
	viewer := user(authz.Binding{Role: authz.Viewer})

	first, err := s.Get(t.Context(), viewer)
	if err != nil {
		t.Fatal(err)
	}
	engineCalls, alertCalls := e.calls.Load(), al.calls.Load()
	if engineCalls == 0 || alertCalls != 1 {
		t.Fatalf("first build: %d engine calls, %d alert reads", engineCalls, alertCalls)
	}
	clk.Advance(59 * time.Second)
	again, err := s.Get(t.Context(), viewer)
	if err != nil || again != first {
		t.Fatalf("second call: %v same=%v", err, again == first)
	}
	if e.calls.Load() != engineCalls || al.calls.Load() != alertCalls {
		t.Errorf("the second call queried: %d, %d", e.calls.Load(), al.calls.Load())
	}
	clk.Advance(time.Second) // 60 s after the build
	next, err := s.Get(t.Context(), viewer)
	if err != nil {
		t.Fatal(err)
	}
	if next == first || e.calls.Load() == engineCalls || !next.GeneratedAt.Equal(wed.Add(time.Minute)) {
		t.Errorf("the next minute did not rebuild: same=%v calls=%d at %v", next == first, e.calls.Load(), next.GeneratedAt)
	}

	// An error is returned and kept only for FailTTL (TestFailureIsRemembered).
	clk.Advance(time.Hour)
	e.err = errors.New("db down")
	if _, err2 := s.Get(t.Context(), viewer); err2 == nil {
		t.Fatal("the build error was swallowed")
	}
	e.err = nil
	clk.Advance(FailTTL)
	if _, err3 := s.Get(t.Context(), viewer); err3 != nil {
		t.Errorf("after the error: %v", err3)
	}

	// The clock moving backwards never serves a report from the future.
	clk.Set(wed.Add(-24 * time.Hour))
	back, err := s.Get(t.Context(), viewer)
	if err != nil || !back.GeneratedAt.Equal(wed.Add(-24*time.Hour)) {
		t.Errorf("clock set back: %v %v", err, back)
	}
}

// TestCacheServesAllRolesButChecksFirst: a viewer, an operator and an admin
// share one build; a role limited to one CA, a user of another tenant and
// nobody get authz.ErrDenied before any query.
func TestPermissionBeforeData(t *testing.T) {
	t.Parallel()
	e := &fakeEngine{}
	d := deps(e, clock.NewFake(wed))
	al := &fakeAlerts{}
	d.Alerts = al
	s := NewService(d)

	denied := map[string]keys.Who{
		"CA-scoped viewer": user(authz.Binding{CA: "issuing", Role: authz.Viewer}),
		"no role":          user(),
		"nobody":           {},
		"other tenant": {Principal: &authz.Principal{Kind: authz.KindUser, Username: "x",
			Bindings: []authz.Binding{{Tenant: "other", Role: authz.Admin}}}},
	}
	for name, who := range denied {
		if _, err := s.Get(t.Context(), who); !errors.Is(err, authz.ErrDenied) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if e.calls.Load() != 0 || al.calls.Load() != 0 {
		t.Fatalf("a denied caller caused %d engine calls and %d alert reads", e.calls.Load(), al.calls.Load())
	}

	var first *Report
	for _, role := range []authz.Role{authz.Viewer, authz.Operator, authz.Admin} {
		r, err := s.Get(t.Context(), user(authz.Binding{Role: role}))
		if err != nil {
			t.Fatalf("%s: %v", role, err)
		}
		if first == nil {
			first = r
		} else if r != first {
			t.Errorf("%s built its own report", role)
		}
	}
	// A denied caller gets nothing even while a report is cached.
	if r, err := s.Get(t.Context(), denied["CA-scoped viewer"]); r != nil || !errors.Is(err, authz.ErrDenied) {
		t.Errorf("cached report leaked to a CA-scoped viewer: %v %v", r, err)
	}
	for _, p := range []*authz.Principal{authz.System("monitor"), authz.Console()} {
		if _, err := s.Get(t.Context(), keys.Who{Principal: p}); err != nil {
			t.Errorf("%s: %v", p.Kind, err)
		}
	}
}

// TestOneBuildAtATime: concurrent first calls build once.
func TestOneBuildAtATime(t *testing.T) {
	t.Parallel()
	e := &fakeEngine{}
	d := deps(e, clock.NewFake(wed))
	al := &fakeAlerts{}
	d.Alerts = al
	s := NewService(d)
	done := make(chan struct{})
	for range 8 {
		go func() {
			defer func() { done <- struct{}{} }()
			if _, err := s.Get(context.Background(), user(authz.Binding{Role: authz.Viewer})); err != nil {
				t.Error(err)
			}
		}()
	}
	for range 8 {
		<-done
	}
	if al.calls.Load() != 1 {
		t.Errorf("%d builds", al.calls.Load())
	}
}

// TestSeparateTenantsSeparateCaches: the cache is a field of the tenant's
// service, there is no shared or request-derived key.
func TestSeparateTenantsSeparateCaches(t *testing.T) {
	t.Parallel()
	e1, e2 := &fakeEngine{counts: map[string]ca.Counts{"ca-1": {Valid: 1}}, cas: []ca.CAInfo{{ID: "ca-1", Name: "one", Status: ca.StatusActive}}}, &fakeEngine{}
	s1 := NewService(deps(e1, clock.NewFake(wed)))
	d2 := deps(e2, clock.NewFake(wed))
	d2.Tenant = "other"
	s2 := NewService(d2)
	r1, err := s1.Get(t.Context(), keys.Who{Principal: authz.Console()})
	if err != nil {
		t.Fatal(err)
	}
	r2, err := s2.Get(t.Context(), keys.Who{Principal: authz.Console()})
	if err != nil {
		t.Fatal(err)
	}
	if len(r1.Authorities) != 1 || len(r2.Authorities) != 0 {
		t.Errorf("tenant 1 has %d, tenant 2 has %d authorities", len(r1.Authorities), len(r2.Authorities))
	}
	// A viewer of tenant "default" may not read tenant "other".
	if _, err := s2.Get(t.Context(), user(authz.Binding{Role: authz.Viewer})); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("viewer of another tenant: %v", err)
	}
}

// TestNoNetworkImports: the package never talks to anything (docs/PHASE3.md
// D11). The check reads the import lists of the non-test files.
func TestNoNetworkImports(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	banned := []string{"net", "net/http", "net/rpc", "net/smtp", "crypto/tls", "golang.org/x/net", "google.golang.org/grpc", "connectrpc.com"}
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
				if path == b || strings.HasPrefix(path, b+"/") {
					t.Errorf("%s imports %s", f, path)
				}
			}
		}
	}
}

// TestFailureIsRemembered: a failed build is remembered for FailTTL, so a
// persistent error does not repeat the full build for every request; after
// FailTTL the next call tries again.
func TestFailureIsRemembered(t *testing.T) {
	t.Parallel()
	clk := clock.NewFake(wed)
	e := &fakeEngine{err: errors.New("db down")}
	s := NewService(deps(e, clk))
	viewer := user(authz.Binding{Role: authz.Viewer})

	_, first := s.Get(t.Context(), viewer)
	if first == nil || !strings.Contains(first.Error(), "db down") {
		t.Fatalf("first: %v", first)
	}
	calls := e.calls.Load()
	for range 3 {
		clk.Advance(time.Second)
		if _, err := s.Get(t.Context(), viewer); !errors.Is(err, first) {
			t.Errorf("within FailTTL: got %v, want the remembered error", err)
		}
	}
	if e.calls.Load() != calls {
		t.Errorf("a remembered failure built again: %d calls, was %d", e.calls.Load(), calls)
	}
	e.err = nil
	clk.Advance(FailTTL - 3*time.Second)
	if r, err := s.Get(t.Context(), viewer); err != nil || r == nil {
		t.Errorf("after FailTTL: %v %v", r, err)
	}
	if e.calls.Load() == calls {
		t.Error("no new build after FailTTL")
	}
	// A denied caller never sees the remembered error.
	if _, err := s.Get(t.Context(), user(authz.Binding{CA: "issuing", Role: authz.Viewer})); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("denied caller: %v", err)
	}
}

// gate is an Engine whose first read blocks until released.
type gate struct {
	*fakeEngine
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (g *gate) ExpiryTimes(ctx context.Context, who keys.Who, after, until time.Time) ([]time.Time, error) {
	g.once.Do(func() { close(g.entered) })
	select {
	case <-g.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return g.fakeEngine.ExpiryTimes(ctx, who, after, until)
}

func newGate() *gate {
	return &gate{fakeEngine: &fakeEngine{}, entered: make(chan struct{}), release: make(chan struct{})}
}

// TestWaiterHonorsItsContext: while a build is in progress a second caller
// waits, but leaves as soon as its own context ends; the build goes on and
// serves the next caller, and there is only one build at a time.
func TestWaiterHonorsItsContext(t *testing.T) {
	t.Parallel()
	g := newGate()
	d := deps(nil, clock.NewFake(wed))
	d.Engine = g
	al := &fakeAlerts{}
	d.Alerts = al
	s := NewService(d)
	viewer := user(authz.Binding{Role: authz.Viewer})

	type result struct {
		r   *Report
		err error
	}
	builder := make(chan result, 1)
	go func() {
		r, err := s.Get(context.Background(), viewer)
		builder <- result{r, err}
	}()
	<-g.entered

	ctx, cancel := context.WithCancel(context.Background())
	waiter := make(chan result, 1)
	go func() {
		r, err := s.Get(ctx, viewer)
		waiter <- result{r, err}
	}()
	select {
	case r := <-waiter:
		t.Fatalf("the waiter returned while the build is in progress: %+v", r)
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	select {
	case r := <-waiter:
		if !errors.Is(r.err, context.Canceled) || r.r != nil {
			t.Errorf("waiter: %v %v", r.r, r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the waiter did not leave when its context ended")
	}

	second := make(chan result, 1)
	go func() {
		r, err := s.Get(context.Background(), viewer)
		second <- result{r, err}
	}()
	close(g.release)
	b, w := <-builder, <-second
	if b.err != nil || w.err != nil || b.r == nil || b.r != w.r {
		t.Errorf("builder %v %v, waiter %v %v: not the same build", b.r, b.err, w.r, w.err)
	}
	if n := al.calls.Load(); n != 1 {
		t.Errorf("%d builds read the alerts, want 1", n)
	}
}

// TestCancelledBuilderIsNotRemembered: the caller of a build that gives up (its
// context ended) must not make the others fail for FailTTL.
func TestCancelledBuilderIsNotRemembered(t *testing.T) {
	t.Parallel()
	g := newGate()
	d := deps(nil, clock.NewFake(wed))
	d.Engine = g
	s := NewService(d)
	viewer := user(authz.Binding{Role: authz.Viewer})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := s.Get(ctx, viewer); done <- err }()
	<-g.entered
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("builder: %v", err)
	}
	close(g.release)
	if r, err := s.Get(context.Background(), viewer); err != nil || r == nil {
		t.Errorf("the next caller: %v %v", r, err)
	}
}

// TestFleetSkipsADeletedAgent: an agent that was deleted between ListAgents
// and GetAgent is left out; any other error still fails the build.
func TestFleetSkipsADeletedAgent(t *testing.T) {
	t.Parallel()
	ag := &fakeAgents{
		list: []agents.Agent{
			{ID: "a1", Status: agents.StatusActive, LastSeenAt: wed.Add(-time.Minute), Version: "0.3.8"},
			{ID: "a2", Status: agents.StatusActive, LastSeenAt: wed.Add(-time.Minute), Version: "0.3.8"},
		},
		deps: map[string][]agents.Deployment{"a1": {{State: "deployed"}}, "a2": {{State: "deployed"}}},
		gone: map[string]bool{"a2": true},
	}
	d := deps(&fakeEngine{}, clock.NewFake(wed))
	d.Agents = ag
	r, err := Build(t.Context(), d, wed)
	if err != nil {
		t.Fatalf("a deleted agent failed the report: %v", err)
	}
	f := r.Agents
	if f.Active != 1 || f.Version.Current != 1 || f.Deployments.Deployed != 1 {
		t.Errorf("the deleted agent was counted: %+v", f)
	}
}
