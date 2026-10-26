package agents

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
	"github.com/Der-Felix/MyOwnPKI/internal/tenant"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

func eventually(t *testing.T, ready func() bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	for !ready() {
		select {
		case <-ctx.Done():
			t.Fatal("test barrier was not reached")
		default:
			runtime.Gosched()
		}
	}
}

func agentCaller(t *testing.T, e *env, host string) *Caller {
	t.Helper()
	_, cert, _ := e.admitted(t, host)
	c, err := e.s.Identify(t.Context(), cert, "192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestReportsAreScopedBoundedAndAudited(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollAuto)
	first, second := agentCaller(t, e, "proxy1.homelab.lan"), agentCaller(t, e, "proxy2.homelab.lan")
	in := ReportInput{Version: "<script>report()</script>", OS: "linux", Arch: "amd64", Deployments: []DeploymentReport{
		{Name: "proxy", Profile: "nginx", Names: []string{"proxy1.homelab.lan"}, State: "deployed", Serial: first.Agent.CertSerial.String},
		{Name: "broken", Profile: "file", State: "failed", LastError: `<img src=x onerror=alert(1)>`},
	}}
	for range 2 {
		if err := e.s.Report(t.Context(), first, in); err != nil {
			t.Fatal(err)
		}
	}
	other := ReportInput{Deployments: []DeploymentReport{{Name: "proxy", State: "failed", Serial: first.Agent.CertSerial.String}}}
	if err := e.s.Report(t.Context(), second, other); err != nil {
		t.Fatal(err)
	}
	a, err := e.s.GetAgent(t.Context(), testinstance.Console, first.Agent.ID)
	if err != nil || len(a.Deployments) != 2 || a.Version != in.Version || a.LastSeenAt.IsZero() {
		t.Fatalf("report not stored: %v", err)
	}
	for _, d := range a.Deployments {
		if d.CertificateID != "" {
			t.Fatal("an identity serial was linked without an owned ACME account")
		}
		if d.Name == "proxy" && d.State != "deployed" {
			t.Fatal("the second agent changed the first agent's deployment")
		}
	}
	if a.Silent(e.inst.Clock.Now()) {
		t.Fatal("fresh report is silent")
	}
	e.inst.Clock.Advance(15 * time.Minute)
	if !a.Silent(e.inst.Clock.Now()) {
		t.Fatal("three missed reports are not silent")
	}
	e.inst.Deliver(t)
	entries := testinstance.Audit(t, e.inst.TenantAudit)
	count := 0
	for _, entry := range entries {
		if entry == "agent.deployment.state/success" {
			count++
		}
	}
	if count != 3 {
		t.Fatalf("heartbeats produced repeated state audit entries: %d", count)
	}
	// Different names on successive snapshots cannot grow storage without bound.
	if rerr := e.s.Report(t.Context(), second, ReportInput{Deployments: []DeploymentReport{{Name: "replacement", State: "pending"}}}); rerr != nil {
		t.Fatal(rerr)
	}
	rows, err := pkidb.New(e.s.PKI).ListAgentDeployments(t.Context(), second.Agent.ID)
	if err != nil || len(rows) != 1 || rows[0].Name != "replacement" {
		t.Fatal("old unrequested inventory was retained")
	}
}

func TestReportInputLimits(t *testing.T) {
	t.Parallel()
	for _, change := range []string{"count", "duplicate", "name", "profile", "names", "dns", "state", "serial", "fingerprint", "error", "version", "os", "arch", "challenge", "time", "ack", "utf8"} {
		t.Run(change, func(t *testing.T) {
			t.Parallel()
			in := ReportInput{Deployments: []DeploymentReport{{Name: "proxy", State: "deployed"}}}
			d := &in.Deployments[0]
			switch change {
			case "count":
				in.Deployments = make([]DeploymentReport, MaxReportDeployments+1)
			case "duplicate":
				in.Deployments = append(in.Deployments, *d)
			case "name":
				d.Name = "../foreign-agent"
			case "profile":
				d.Profile = strings.Repeat("x", 33)
			case "names":
				d.Names = make([]string, 101)
			case "dns":
				d.Names = []string{strings.Repeat("x", 254)}
			case "state":
				d.State = "<script>"
			case "serial":
				d.Serial = strings.Repeat("0", 66)
			case "fingerprint":
				d.Fingerprint = "bad fingerprint"
			case "error":
				d.LastError = strings.Repeat("x", 1025)
			case "version":
				in.Version = strings.Repeat("x", 65)
			case "os":
				in.OS = strings.Repeat("x", 33)
			case "arch":
				in.Arch = strings.Repeat("x", 33)
			case "challenge":
				d.Challenge = strings.Repeat("x", 33)
			case "time":
				d.NotAfter = "tomorrow"
			case "ack":
				d.HandledRenewalVersion = -1
			case "utf8":
				d.LastError = string([]byte{0xff})
			}
			if err := validReport(in); !errors.Is(err, ErrInvalid) {
				t.Fatalf("%s accepted: %v", change, err)
			}
		})
	}
}

func TestRenewalRequestRolesVersionAndAudit(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollAuto)
	c := agentCaller(t, e, "proxy1.homelab.lan")
	in := ReportInput{Deployments: []DeploymentReport{{Name: "proxy", State: "deployed"}}}
	if err := e.s.Report(t.Context(), c, in); err != nil {
		t.Fatal(err)
	}
	for _, role := range []authz.Role{authz.Viewer, authz.Operator, authz.Admin} {
		who := keys.Who{Actor: audit.Actor{Type: audit.ActorUser, ID: "test-user", Name: "operator"}, Principal: &authz.Principal{
			Kind: authz.KindUser, UserID: "test-user", Bindings: []authz.Binding{{Tenant: "default", Role: role}}, StepUpAt: e.inst.Clock.Now(),
		}}
		err := e.s.RequestRenewal(t.Context(), who, c.Agent.ID, "proxy")
		if role == authz.Viewer {
			if !errors.Is(err, authz.ErrDenied) {
				t.Fatalf("viewer: %v", err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if derr := e.s.RequestRenewal(t.Context(), who, c.Agent.ID, "proxy"); !errors.Is(derr, ErrConflict) {
			t.Fatal("duplicate request accepted")
		}
		state, err := e.s.WatchDesiredState(t.Context(), c, 0)
		if err != nil || len(state.Deployments) != 1 || !state.Changed {
			t.Fatalf("desired request: %v", err)
		}
		version := state.Deployments[0].RenewalVersion
		// A heartbeat sent before the request cannot clear it, including
		// in the same clock second. A wrong future acknowledgement cannot either.
		for _, ack := range []int64{0, version + 1} {
			in.Deployments[0].HandledRenewalVersion = ack
			if err := e.s.Report(t.Context(), c, in); err != nil {
				t.Fatal(err)
			}
			row, _ := pkidb.New(e.s.PKI).GetAgentDeployment(t.Context(), pkidb.GetAgentDeploymentParams{AgentID: c.Agent.ID, Name: "proxy"})
			if !row.RenewRequestedAt.Valid {
				t.Fatal("an unrelated report cleared the request")
			}
		}
		in.Deployments[0].State = "failed"
		in.Deployments[0].HandledRenewalVersion = version
		if err := e.s.Report(t.Context(), c, in); err != nil {
			t.Fatal(err)
		}
		row, _ := pkidb.New(e.s.PKI).GetAgentDeployment(t.Context(), pkidb.GetAgentDeploymentParams{AgentID: c.Agent.ID, Name: "proxy"})
		if row.RenewRequestedAt.Valid {
			t.Fatal("a matching failed result did not clear the request")
		}
	}
	e.inst.Deliver(t)
	var logged int
	if err := e.inst.TenantAudit.Read.QueryRowContext(t.Context(), `SELECT count(*) FROM audit_entries WHERE action = 'agent.renew.request' AND result = 'success' AND actor_id = 'test-user' AND instr(details_json, 'proxy') > 0`).Scan(&logged); err != nil || logged != 2 {
		t.Fatalf("renew audit=%d: %v", logged, err)
	}
}

func TestWithdrawRenewalRolesVersionRaceAndAudit(t *testing.T) {
	t.Parallel()
	for _, role := range []authz.Role{authz.Viewer, authz.Operator, authz.Admin} {
		t.Run(string(role), func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, tenant.EnrollAuto)
			c := agentCaller(t, e, "proxy1.homelab.lan")
			in := ReportInput{Deployments: []DeploymentReport{{Name: "proxy", State: "deployed"}}}
			if err := e.s.Report(t.Context(), c, in); err != nil {
				t.Fatal(err)
			}
			if err := e.s.RequestRenewal(t.Context(), testinstance.Console, c.Agent.ID, "proxy"); err != nil {
				t.Fatal(err)
			}
			state, err := e.s.WatchDesiredState(t.Context(), c, 0)
			if err != nil {
				t.Fatal(err)
			}
			who := keys.Who{Actor: audit.Actor{Type: audit.ActorUser, ID: "test-user", Name: "operator"}, Principal: &authz.Principal{
				Kind: authz.KindUser, UserID: "test-user", Bindings: []authz.Binding{{Tenant: "default", Role: role}}, StepUpAt: e.inst.Clock.Now(),
			}}
			err = e.s.WithdrawRenewal(t.Context(), who, c.Agent.ID, "proxy")
			if role == authz.Viewer {
				if !errors.Is(err, authz.ErrDenied) {
					t.Fatalf("viewer: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if secondErr := e.s.WithdrawRenewal(t.Context(), who, c.Agent.ID, "proxy"); !errors.Is(secondErr, ErrConflict) {
				t.Fatalf("second withdrawal: %v", secondErr)
			}
			q := pkidb.New(e.s.PKI)
			a, err := q.GetAgent(t.Context(), c.Agent.ID)
			if err != nil || a.DesiredVersion != state.Version+1 {
				t.Fatalf("desired version after withdrawal: %d, %v", a.DesiredVersion, err)
			}

			// The agent had already started. Its acknowledgement of the withdrawn
			// version succeeds without changing or clearing anything else.
			in.Deployments[0].State = "failed"
			in.Deployments[0].HandledRenewalVersion = state.Deployments[0].RenewalVersion
			if reportErr := e.s.Report(t.Context(), c, in); reportErr != nil {
				t.Fatal(reportErr)
			}
			d, err := q.GetAgentDeployment(t.Context(), pkidb.GetAgentDeploymentParams{AgentID: c.Agent.ID, Name: "proxy"})
			if err != nil || d.RenewRequestedAt.Valid {
				t.Fatalf("withdrawn request returned: %+v, %v", d, err)
			}
			a, err = q.GetAgent(t.Context(), c.Agent.ID)
			if err != nil || a.DesiredVersion != state.Version+1 {
				t.Fatalf("late acknowledgement changed the version: %d, %v", a.DesiredVersion, err)
			}
			e.inst.Deliver(t)
			var logged int
			if err := e.inst.TenantAudit.Read.QueryRowContext(t.Context(), `SELECT count(*) FROM audit_entries WHERE action = 'agent.renew.withdraw' AND result = 'success' AND actor_id = 'test-user' AND instr(details_json, 'proxy') > 0`).Scan(&logged); err != nil || logged != 1 {
				t.Fatalf("withdraw audit=%d: %v", logged, err)
			}
		})
	}
}

func TestReportFullInventoryRetainsOnlyRequestedRemovedDeployment(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollAuto)
	c := agentCaller(t, e, "proxy1.homelab.lan")
	removed := DeploymentReport{Name: "removed", State: "failed", LastError: "old deployment"}
	if err := e.s.Report(t.Context(), c, ReportInput{Deployments: []DeploymentReport{removed}}); err != nil {
		t.Fatal(err)
	}
	if err := e.s.RequestRenewal(t.Context(), testinstance.Console, c.Agent.ID, removed.Name); err != nil {
		t.Fatal(err)
	}
	in := ReportInput{Deployments: []DeploymentReport{removed}}
	for i := range MaxDeployments {
		in.Deployments = append(in.Deployments, DeploymentReport{Name: fmt.Sprintf("active-%03d", i), State: "deployed"})
	}
	if err := e.s.Report(t.Context(), c, in); err != nil {
		t.Fatal(err)
	}
	q := pkidb.New(e.s.PKI)
	rows, err := q.ListAgentDeployments(t.Context(), c.Agent.ID)
	if err != nil || len(rows) != MaxReportDeployments {
		t.Fatalf("full report retained %d rows: %v", len(rows), err)
	}

	// Omitting the removed result keeps its open request, but marks it as no
	// longer configured. One hundred active deployments still fit the report.
	in.Deployments = in.Deployments[1:]
	if reportErr := e.s.Report(t.Context(), c, in); reportErr != nil {
		t.Fatal(reportErr)
	}
	a, err := e.s.GetAgent(t.Context(), testinstance.Console, c.Agent.ID)
	if err != nil || len(a.Deployments) != MaxReportDeployments {
		t.Fatalf("requested removed deployment was dropped: %v", err)
	}
	for _, d := range a.Deployments {
		if d.Name == removed.Name && !d.Removed {
			t.Fatal("removed deployment is not marked as absent from the agent configuration")
		}
	}
	if withdrawErr := e.s.WithdrawRenewal(t.Context(), testinstance.Console, c.Agent.ID, removed.Name); withdrawErr != nil {
		t.Fatal(withdrawErr)
	}
	if reportErr := e.s.Report(t.Context(), c, in); reportErr != nil {
		t.Fatal(reportErr)
	}
	rows, err = q.ListAgentDeployments(t.Context(), c.Agent.ID)
	if err != nil || len(rows) != MaxDeployments {
		t.Fatalf("withdrawn removed deployment was not deleted: %d, %v", len(rows), err)
	}
}

func TestReportAndWatchLimitsArePerAgent(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollAuto)
	flooded, other := agentCaller(t, e, "proxy1.homelab.lan"), agentCaller(t, e, "proxy2.homelab.lan")

	// The fastest ordinary heartbeat interval is 270 s: ceil(600/270) = 3
	// reports per window. A 45 s long-poll gives ceil(600/45) = 14 watches.
	normalReports := int((10*time.Minute + 270*time.Second - 1) / (270 * time.Second))
	normalWatches := int((10*time.Minute + 45*time.Second - 1) / (45 * time.Second))
	if normalReports != 3 || normalWatches != 14 || normalReports > reportPerWindow/2 || normalWatches > watchPerWindow/2 {
		t.Fatalf("ordinary rates approach the limits: reports=%d/%d watches=%d/%d", normalReports, reportPerWindow, normalWatches, watchPerWindow)
	}

	for i := range reportPerWindow {
		state := "deployed"
		if i%2 == 0 {
			state = "pending"
		}
		if err := e.s.Report(t.Context(), flooded, ReportInput{Deployments: []DeploymentReport{{Name: "proxy", State: state}}}); err != nil {
			t.Fatalf("report %d: %v", i, err)
		}
	}
	for range 20 {
		if err := e.s.Report(t.Context(), flooded, ReportInput{Deployments: []DeploymentReport{{Name: "proxy", State: "failed"}}}); !errors.Is(err, ErrRateLimited) {
			t.Fatalf("flooded report: %v", err)
		}
	}
	if err := e.s.Report(t.Context(), other, ReportInput{Deployments: []DeploymentReport{{Name: "proxy", State: "deployed"}}}); err != nil {
		t.Fatalf("another agent was blocked by the flood: %v", err)
	}
	e.inst.Deliver(t)
	var stateAudits int
	if err := e.inst.TenantAudit.Read.QueryRowContext(t.Context(), `SELECT count(*) FROM audit_entries WHERE action = 'agent.deployment.state'`).Scan(&stateAudits); err != nil || stateAudits != reportPerWindow+1 {
		t.Fatalf("state audit entries=%d, want %d: %v", stateAudits, reportPerWindow+1, err)
	}

	for i := range watchPerWindow {
		if _, err := e.s.WatchDesiredState(t.Context(), flooded, 0); err != nil {
			t.Fatalf("watch %d: %v", i, err)
		}
	}
	if _, err := e.s.WatchDesiredState(t.Context(), flooded, 0); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("flooded watch: %v", err)
	}
	if _, err := e.s.WatchDesiredState(t.Context(), other, 0); err != nil {
		t.Fatalf("another agent cannot watch: %v", err)
	}
}

func TestWatchTimeoutReplacementCapacityAndShutdown(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollAuto)
	c := agentCaller(t, e, "proxy1.homelab.lan")
	waitEnded := make(chan struct{}, 2)
	e.s.Sleep = func(ctx context.Context, d time.Duration) error {
		err := e.inst.Clock.Sleep(ctx, d)
		waitEnded <- struct{}{}
		return err
	}
	initial, err := e.s.WatchDesiredState(t.Context(), c, 0)
	if err != nil || !initial.Changed {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	watch := func() {
		state, err := e.s.WatchDesiredState(t.Context(), c, initial.Version)
		if err == nil && state.Changed {
			err = errors.New("timeout returned a change")
		}
		results <- err
	}
	go watch()
	eventually(t, func() bool { return e.inst.Clock.Waiting() == 1 })
	go watch()
	if err := <-results; !errors.Is(err, ErrWatchReplaced) {
		t.Fatalf("replacement: %v", err)
	}
	<-waitEnded // the first canceled timer has unregistered from the fake clock
	eventually(t, func() bool { return e.inst.Clock.Waiting() == 1 })
	e.inst.Clock.Advance(50 * time.Second)
	if err := <-results; err != nil {
		t.Fatal(err)
	}
	for i := range MaxWatches {
		if _, err := e.s.subscribe(fmt.Sprintf("slot-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.s.subscribe("overflow"); !errors.Is(err, ErrRateLimited) {
		t.Fatal("global watch limit was not enforced")
	}
	if _, err := e.s.subscribe("slot-0"); err != nil {
		t.Fatal("replacement should not consume another slot")
	}
	e.s.CloseWatches()
	if _, err := e.s.subscribe("new"); !errors.Is(err, ErrWatchClosed) {
		t.Fatal("shutdown accepted another watch")
	}
}

func TestRestartReleasesManyWatchesAndKeepsRequests(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollAuto)
	e.s.Sleep = e.inst.Clock.Sleep
	q := pkidb.New(e.s.PKI)
	const count = 64
	callers := make([]*Caller, count)
	for i := range count {
		id := fmt.Sprintf("simulated-%d", i)
		now := dbTime(e.inst.Clock.Now())
		if err := q.InsertAgent(t.Context(), pkidb.InsertAgentParams{ID: id, Hostname: "proxy.homelab.lan", EnrollmentMode: "verified", Proof: "{}", CreatedAt: now, ApprovedAt: now, ApprovedBy: "test", UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
		callers[i] = &Caller{Agent: pkidb.Agent{ID: id}}
	}
	callers[0].Who = testinstance.Console
	if err := e.s.Report(t.Context(), callers[0], ReportInput{Deployments: []DeploymentReport{{Name: "proxy", State: "pending"}}}); err != nil {
		t.Fatal(err)
	}
	if err := e.s.RequestRenewal(t.Context(), testinstance.Console, callers[0].Agent.ID, "proxy"); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, count)
	for i, c := range callers {
		version := int64(1)
		if i == 0 {
			version = 2
		}
		go func() { _, err := e.s.WatchDesiredState(t.Context(), c, version); done <- err }()
	}
	eventually(t, func() bool { return e.inst.Clock.Waiting() == count })
	e.s.CloseWatches()
	for range count {
		if err := <-done; !errors.Is(err, ErrWatchClosed) {
			t.Fatalf("restart did not release watch: %v", err)
		}
	}
	// The replacement service reads persisted desired versions, not the old hub.
	restarted := &Service{PKI: e.s.PKI, Clock: e.inst.Clock, Sleep: e.inst.Clock.Sleep}
	for i, c := range callers {
		state, err := restarted.WatchDesiredState(t.Context(), c, 0)
		version := int64(1)
		if i == 0 {
			version = 2
		}
		if err != nil || state.Version != version {
			t.Fatalf("after restart: %v", err)
		}
		if i == 0 && (len(state.Deployments) != 1 || state.Deployments[0].RenewalVersion != 2) {
			t.Fatal("outstanding request lost at restart")
		}
	}
}
