package monitor

import (
	"errors"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
)

func viewerWho(bindings ...authz.Binding) keys.Who {
	return keys.Who{
		Actor:     audit.Actor{Type: audit.ActorUser, ID: "usr_v", Name: "vera"},
		Principal: &authz.Principal{Kind: authz.KindUser, UserID: "usr_v", Username: "vera", Bindings: bindings},
	}
}

// TestListWindow: List shows the open alerts and those resolved within 7
// days (newest first), and drops an alert resolved 7 days and a second ago.
func TestListWindow(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	clk := e.inst.Clock
	finding := func(key, severity string) Finding {
		return Finding{Key: key, Kind: KindCertExpiry, Subject: key + ".homelab.lan", Severity: severity, Detail: "ends soon", Href: "/certificates/" + key}
	}
	sync := func(findings ...Finding) {
		t.Helper()
		if _, err := e.store.Sync(t.Context(), clk.Now(), findings); err != nil {
			t.Fatal(err)
		}
	}
	// Four alerts open together. "old", "edge" and "recent" are resolved one
	// after the other (1 hour, 2 hours and 3 days later); "open" stays and
	// rises to critical.
	sync(finding("old", Warning), finding("edge", Warning), finding("recent", Warning), finding("open", Warning))
	clk.Advance(time.Hour)
	sync(finding("edge", Warning), finding("recent", Warning), finding("open", Critical)) // old resolves now
	oldResolved := clk.Now().Truncate(time.Second)
	clk.Advance(time.Hour)
	sync(finding("recent", Warning), finding("open", Critical)) // edge resolves now
	edgeResolved := clk.Now().Truncate(time.Second)
	clk.Advance(3 * 24 * time.Hour)
	sync(finding("open", Critical)) // recent resolves now
	recentResolved := clk.Now().Truncate(time.Second)

	read := func(at time.Time) (open, resolved []Alert) {
		t.Helper()
		open, resolved, err := e.store.List(t.Context(), viewerWho(authz.Binding{Tenant: "default", Role: authz.Viewer}), at)
		if err != nil {
			t.Fatal(err)
		}
		return open, resolved
	}
	names := func(list []Alert) []string {
		out := make([]string, 0, len(list))
		for _, a := range list {
			out = append(out, a.Key)
		}
		return out
	}

	// Right after "recent" was resolved: the open one, and the three resolved
	// ones, the newest first.
	open, resolved := read(clk.Now())
	if got := names(open); len(got) != 1 || got[0] != "open" || open[0].Severity != Critical || !open[0].Open() {
		t.Fatalf("open: %v", got)
	}
	if got := names(resolved); len(got) != 3 || got[0] != "recent" || got[1] != "edge" || got[2] != "old" || !resolved[0].Resolved.Equal(recentResolved) {
		t.Fatalf("resolved: %v", got)
	}

	// 7 days after "old" was resolved it is still listed; a second later not.
	_, resolved = read(oldResolved.Add(ResolvedWindow))
	if len(resolved) != 3 {
		t.Errorf("at the edge: %v", names(resolved))
	}
	_, resolved = read(oldResolved.Add(ResolvedWindow + time.Second))
	if got := names(resolved); len(got) != 2 {
		t.Errorf("a second later: %v", got)
	}
	_, resolved = read(edgeResolved.Add(ResolvedWindow + time.Second))
	if got := names(resolved); len(got) != 1 {
		t.Errorf("after edge is out too: %v", got)
	}
	open, resolved = read(recentResolved.Add(ResolvedWindow + time.Second))
	if len(open) != 1 || len(resolved) != 0 {
		t.Errorf("a week later: open %v, resolved %v", names(open), names(resolved))
	}
}

// TestListNeedsTheTenantWideReadRole: the alerts name objects of every CA,
// so a role limited to one CA, no role and no principal are refused.
func TestListNeedsTheTenantWideReadRole(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	now := e.inst.Clock.Now()
	for name, who := range map[string]keys.Who{
		"viewer":   viewerWho(authz.Binding{Tenant: "default", Role: authz.Viewer}),
		"admin":    viewerWho(authz.Binding{Tenant: "default", Role: authz.Admin}),
		"console":  {Principal: authz.Console()},
		"one CA":   viewerWho(authz.Binding{Tenant: "default", CA: "issuing", Role: authz.Viewer}),
		"no roles": viewerWho(),
		"no one":   {},
	} {
		_, _, err := e.store.List(t.Context(), who, now)
		want := name == "viewer" || name == "admin" || name == "console"
		if (err == nil) != want || (err != nil && !errors.Is(err, authz.ErrDenied)) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
