package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	serveragents "github.com/Der-Felix/MyOwnPKI/internal/agents"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	agentv1 "github.com/Der-Felix/MyOwnPKI/internal/gen/myownpki/agent/v1"
	"github.com/Der-Felix/MyOwnPKI/internal/gen/myownpki/agent/v1/agentv1connect"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

func awaitRuntime(t *testing.T, ready func() bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	for !ready() {
		select {
		case <-ctx.Done():
			t.Fatal("runtime test barrier was not reached")
		default:
			runtime.Gosched()
		}
	}
}

func TestRenewalSchedulingAndEarlierARI(t *testing.T) {
	t.Parallel()
	for _, ari := range []bool{false, true} {
		t.Run(map[bool]string{false: "two_thirds", true: "earlier_ari"}[ari], func(t *testing.T) {
			t.Parallel()
			r := newDeployRig(t, ProfileFile)
			r.installOld(t)
			f := clock.NewFake(r.a.Now())
			r.a.Now = f.Now
			r.a.Random = func() float64 { return 0.25 }
			d := r.a.cfg.Deployments[0]
			old := r.old[d.Name].Leaf
			if err := r.a.saveDeploymentResults([]DeploymentResult{{Name: d.Name, State: "deployed", Serial: certificateSerial(old)}}); err != nil {
				t.Fatal(err)
			}
			want := RenewAt(old, serialFraction(old))
			r.a.ariForTest = func(context.Context, *x509.Certificate) (renewalWindow, error) {
				if !ari {
					return renewalWindow{}, errors.New("ARI unavailable; use normal schedule")
				}
				return renewalWindow{Start: old.NotBefore.Add(24 * time.Hour), End: old.NotBefore.Add(48 * time.Hour), RetryAfter: 6 * time.Hour}, nil
			}
			if ari {
				want = old.NotBefore.Add(30 * time.Hour)
			}
			obtains := 0
			r.a.obtainForTest = func(context.Context, Deployment) (*Material, error) {
				obtains++
				return cloneMaterial(r.next[d.Name]), nil
			}
			plans := map[string]*renewalPlan{}
			if _, err := r.a.schedule(t.Context(), nil, plans); err != nil {
				t.Fatal(err)
			}
			f.Set(want.Add(-time.Nanosecond))
			if _, err := r.a.schedule(t.Context(), nil, plans); err != nil || obtains != 0 {
				t.Fatalf("renewed too early: %v", err)
			}
			f.Advance(time.Nanosecond)
			if _, err := r.a.schedule(t.Context(), nil, plans); err != nil || obtains != 1 {
				t.Fatalf("did not renew at selected time: obtains=%d, %v", obtains, err)
			}
			if plans[d.Name].renew != want {
				t.Fatalf("renewal point=%v, want %v", plans[d.Name].renew, want)
			}
		})
	}
}

func TestDeploymentFailureBackoffPersistsAndRenewNowBypassesOnce(t *testing.T) {
	t.Parallel()
	for _, failure := range []string{"failed", "rolled_back"} {
		t.Run(failure, func(t *testing.T) {
			t.Parallel()
			r := newDeployRig(t, ProfileFile)
			r.installOld(t)
			f := clock.NewFake(r.a.Now())
			r.a.Now = f.Now
			d := r.a.cfg.Deployments[0]
			attempts := 0
			r.a.obtainForTest = func(context.Context, Deployment) (*Material, error) {
				attempts++
				if failure == "failed" {
					return nil, errors.New("issuance failed")
				}
				return cloneMaterial(r.next[d.Name]), nil
			}
			r.a.runHookForTest = func(context.Context, string) error {
				r.testCalls++
				if r.testCalls%2 == 1 {
					return errors.New("new configuration failed its test")
				}
				return nil
			}
			plans := map[string]*renewalPlan{}
			for failures := 1; failures <= 9; failures++ {
				before := f.Now()
				if _, err := r.a.schedule(t.Context(), nil, plans); err != nil {
					t.Fatal(err)
				}
				rows, err := r.a.deploymentResults()
				if err != nil || len(rows) != 1 {
					t.Fatal(err)
				}
				if rows[0].State != failure || !rows[0].NextAttempt.Equal(before.Add(deploymentBackoff(failures))) {
					t.Fatalf("backoff after %d: %+v", failures, rows[0])
				}
				if attempts != failures {
					t.Fatalf("attempts=%d, want %d", attempts, failures)
				}
				f.Set(rows[0].NextAttempt.Add(-time.Nanosecond))
				// A fresh process reads the same durable backoff.
				restarted := &Agent{cfg: r.a.cfg, st: r.a.st, Now: f.Now, log: r.a.log, obtainForTest: r.a.obtainForTest}
				if _, err := restarted.schedule(t.Context(), nil, map[string]*renewalPlan{}); err != nil || attempts != failures {
					t.Fatalf("restart bypassed backoff: %v", err)
				}
				if failures < 9 {
					f.Advance(time.Nanosecond)
				}
			}
			state := &agentv1.WatchDesiredStateResponse{Version: 42, AllowedNames: d.Names, Deployments: []*agentv1.DesiredDeployment{{Name: d.Name, RenewalVersion: 42}}}
			if _, err := r.a.schedule(t.Context(), state, plans); err != nil || attempts != 10 {
				t.Fatal("renew now did not bypass backoff")
			}
			if _, err := r.a.schedule(t.Context(), state, plans); err != nil || attempts != 10 {
				t.Fatal("one request bypassed backoff more than once")
			}
			rows, _ := r.a.deploymentResults()
			if rows[0].HandledRenewalVersion != 42 {
				t.Fatal("request acknowledgement was not persisted")
			}
		})
	}
}

type runtimeClient struct {
	agentv1connect.AgentServiceClient
	report func(context.Context, *connect.Request[agentv1.ReportRequest]) (*connect.Response[agentv1.ReportResponse], error)
	watch  func(context.Context, *connect.Request[agentv1.WatchDesiredStateRequest]) (*connect.Response[agentv1.WatchDesiredStateResponse], error)
}

func (c runtimeClient) Report(ctx context.Context, r *connect.Request[agentv1.ReportRequest]) (*connect.Response[agentv1.ReportResponse], error) {
	return c.report(ctx, r)
}
func (c runtimeClient) WatchDesiredState(ctx context.Context, r *connect.Request[agentv1.WatchDesiredStateRequest]) (*connect.Response[agentv1.WatchDesiredStateResponse], error) {
	return c.watch(ctx, r)
}

func runtimeAgent(f *clock.Fake, client runtimeClient) *Agent {
	a := &Agent{Now: f.Now, Sleep: f.Sleep, Random: func() float64 { return 0.5 }, log: slog.New(slog.DiscardHandler), ch: &channel{client: client}, reportWake: make(chan struct{}, 1)}
	a.ch.cert.Store(&tls.Certificate{})
	return a
}

func TestReportsEveryFiveMinutesAndImmediatelyAfterResult(t *testing.T) {
	t.Parallel()
	r := newDeployRig(t, ProfileFile)
	f := clock.NewFake(r.a.Now())
	var calls atomic.Int64
	client := runtimeClient{report: func(context.Context, *connect.Request[agentv1.ReportRequest]) (*connect.Response[agentv1.ReportResponse], error) {
		calls.Add(1)
		return connect.NewResponse(&agentv1.ReportResponse{}), nil
	}}
	a := runtimeAgent(f, client)
	a.cfg, a.st = r.a.cfg, r.a.st
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); a.reportLoop(ctx) }()
	defer func() { cancel(); <-done }()
	awaitRuntime(t, func() bool { return calls.Load() == 1 && f.Waiting() == 1 })
	f.Advance(5*time.Minute - time.Nanosecond)
	if calls.Load() != 1 {
		t.Fatal("heartbeat was early")
	}
	f.Advance(time.Nanosecond)
	awaitRuntime(t, func() bool { return calls.Load() == 2 && f.Waiting() == 1 })
	a.wakeReport()
	awaitRuntime(t, func() bool { return calls.Load() == 3 && f.Waiting() == 1 })
}

func TestRunPassSendsOneReportWithAllResults(t *testing.T) {
	t.Parallel()
	r := newDeployRig(t, ProfileNginx, ProfileFile)
	r.installOld(t)
	f := clock.NewFake(r.a.Now())
	var calls atomic.Int64
	var mu sync.Mutex
	var reports [][]DeploymentResult
	client := runtimeClient{report: func(_ context.Context, req *connect.Request[agentv1.ReportRequest]) (*connect.Response[agentv1.ReportResponse], error) {
		calls.Add(1)
		mu.Lock()
		var states []DeploymentResult
		for _, deployment := range req.Msg.Deployments {
			states = append(states, DeploymentResult{Name: deployment.Name, State: deployment.State})
		}
		reports = append(reports, states)
		mu.Unlock()
		return connect.NewResponse(&agentv1.ReportResponse{}), nil
	}}
	r.a.Now, r.a.Sleep, r.a.Random = f.Now, f.Sleep, func() float64 { return 0.5 }
	r.a.ch = &channel{client: client}
	r.a.ch.cert.Store(&tls.Certificate{})
	r.a.reportWake = make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); r.a.reportLoop(ctx) }()
	defer func() { cancel(); <-done }()
	awaitRuntime(t, func() bool { return calls.Load() == 1 && f.Waiting() == 1 })
	if _, err := r.a.RunPass(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	awaitRuntime(t, func() bool { return calls.Load() == 2 && f.Waiting() == 1 })
	mu.Lock()
	defer mu.Unlock()
	if len(reports) != 2 || len(reports[1]) != 2 {
		t.Fatalf("reports after one pass: %+v", reports)
	}
	for _, deployment := range reports[1] {
		if deployment.State != "deployed" {
			t.Fatalf("result missing from combined report: %+v", reports[1])
		}
	}
}

func TestReportRateLimitWaitsForNextScheduledReport(t *testing.T) {
	t.Parallel()
	f := clock.NewFake(time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC))
	var calls atomic.Int64
	client := runtimeClient{report: func(context.Context, *connect.Request[agentv1.ReportRequest]) (*connect.Response[agentv1.ReportResponse], error) {
		calls.Add(1)
		return nil, connect.NewError(connect.CodeResourceExhausted, errors.New("limited"))
	}}
	a := runtimeAgent(f, client)
	r := newDeployRig(t, ProfileFile)
	a.cfg, a.st = r.a.cfg, r.a.st
	waits := make(chan time.Duration, 2)
	a.Sleep = func(ctx context.Context, d time.Duration) error { waits <- d; return f.Sleep(ctx, d) }
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); a.reportLoop(ctx) }()
	defer func() { cancel(); <-done }()
	for i := range 2 {
		if got := <-waits; got != 5*time.Minute {
			t.Fatalf("rate-limited report delay=%v, want 5m", got)
		}
		awaitRuntime(t, func() bool { return calls.Load() == int64(i+1) && f.Waiting() == 1 })
		f.Advance(5 * time.Minute)
	}
}

func TestReportPrunesRemovedDeploymentOnlyAfterAcceptance(t *testing.T) {
	t.Parallel()
	r := newDeployRig(t, ProfileFile)
	f := clock.NewFake(r.a.Now())
	var calls atomic.Int64
	var lengths []int
	client := runtimeClient{report: func(_ context.Context, req *connect.Request[agentv1.ReportRequest]) (*connect.Response[agentv1.ReportResponse], error) {
		call := calls.Add(1)
		lengths = append(lengths, len(req.Msg.Deployments))
		if call == 1 {
			return nil, connect.NewError(connect.CodeUnavailable, errors.New("report not accepted"))
		}
		return connect.NewResponse(&agentv1.ReportResponse{}), nil
	}}
	a := runtimeAgent(f, client)
	a.st = r.a.st
	a.cfg = &Config{}
	var results []DeploymentResult
	for i := range 100 {
		name := fmt.Sprintf("active-%03d", i)
		a.cfg.Deployments = append(a.cfg.Deployments, Deployment{Name: name, Profile: ProfileFile})
		results = append(results, DeploymentResult{Name: name, State: "deployed"})
	}
	results = append(results, DeploymentResult{Name: "removed", State: "failed"})
	if err := a.saveDeploymentResults(results); err != nil {
		t.Fatal(err)
	}
	if err := a.report(t.Context()); err == nil {
		t.Fatal("the refused report unexpectedly succeeded")
	}
	stored, err := a.deploymentResults()
	if err != nil || len(stored) != 101 {
		t.Fatalf("refused report removed local state: %d, %v", len(stored), err)
	}
	if reportErr := a.report(t.Context()); reportErr != nil {
		t.Fatal(reportErr)
	}
	stored, err = a.deploymentResults()
	if err != nil || len(stored) != 100 {
		t.Fatalf("accepted removed result was not pruned: %d, %v", len(stored), err)
	}
	if reportErr := a.report(t.Context()); reportErr != nil {
		t.Fatal(reportErr)
	}
	if got, want := lengths, []int{101, 101, 100}; !slices.Equal(got, want) {
		t.Fatalf("report lengths=%v, want %v", got, want)
	}
	select {
	case <-a.reportWake:
	default:
		t.Fatal("accepted removal did not schedule a follow-up report")
	}
}

func TestWatchBackoffDoublesCapsAndResets(t *testing.T) {
	t.Parallel()
	f := clock.NewFake(time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC))
	var calls atomic.Int64
	client := runtimeClient{watch: func(context.Context, *connect.Request[agentv1.WatchDesiredStateRequest]) (*connect.Response[agentv1.WatchDesiredStateResponse], error) {
		if calls.Add(1) == 9 {
			return connect.NewResponse(&agentv1.WatchDesiredStateResponse{Version: 3}), nil
		}
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("server restarted"))
	}}
	a := runtimeAgent(f, client)
	waits := make(chan time.Duration, 2)
	a.Sleep = func(ctx context.Context, d time.Duration) error { waits <- d; return f.Sleep(ctx, d) }
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); a.watchLoop(ctx, make(chan *agentv1.WatchDesiredStateResponse, 1)) }()
	defer func() { cancel(); <-done }()
	for _, want := range []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second, 30 * time.Second, 500 * time.Millisecond} {
		if got := <-waits; got != want {
			t.Fatalf("watch delay=%v, want %v", got, want)
		}
		awaitRuntime(t, func() bool { return f.Waiting() == 1 })
		f.Advance(want)
	}
}

func TestServerRestartReconnectsManyAgentsWithoutBurst(t *testing.T) {
	const count = 64
	inst := testinstance.New(t, testinstance.Options{})
	f := inst.Clock
	old := &serveragents.Service{PKI: inst.PKIDB.Write, Clock: f, Sleep: f.Sleep}
	q := pkidb.New(inst.PKIDB.Write)
	callers := make([]*serveragents.Caller, count)
	for i := range count {
		id := fmt.Sprintf("simulated-%d", i)
		now := f.Now().UTC().Format(time.RFC3339)
		if err := q.InsertAgent(t.Context(), pkidb.InsertAgentParams{ID: id, Hostname: "proxy.homelab.lan", EnrollmentMode: "verified", Proof: "{}", CreatedAt: now, ApprovedAt: now, ApprovedBy: "test", UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
		callers[i] = &serveragents.Caller{Agent: pkidb.Agent{ID: id}}
	}
	callers[0].Who = testinstance.Console
	if err := old.Report(t.Context(), callers[0], serveragents.ReportInput{Deployments: []serveragents.DeploymentReport{{Name: "proxy", State: "pending"}}}); err != nil {
		t.Fatal(err)
	}
	if err := old.RequestRenewal(t.Context(), testinstance.Console, callers[0].Agent.ID, "proxy"); err != nil {
		t.Fatal(err)
	}

	var current atomic.Pointer[serveragents.Service]
	current.Store(old)
	var restarting atomic.Bool
	var entered, connected atomic.Int64
	var mu sync.Mutex
	buckets := map[int64]int{}
	ctx, cancel := context.WithCancel(t.Context())
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	for i, caller := range callers {
		desiredVersion := int64(1)
		if i == 0 {
			desiredVersion = 2
		}
		var waitingOnce sync.Once
		client := runtimeClient{watch: func(ctx context.Context, req *connect.Request[agentv1.WatchDesiredStateRequest]) (*connect.Response[agentv1.WatchDesiredStateResponse], error) {
			svc := current.Load()
			if svc == old && req.Msg.KnownVersion == desiredVersion {
				waitingOnce.Do(func() { entered.Add(1) })
			}
			if restarting.Load() && svc != old && req.Msg.KnownVersion == desiredVersion {
				mu.Lock()
				buckets[f.Now().UnixNano()/int64(100*time.Millisecond)]++
				mu.Unlock()
				connected.Add(1)
			}
			state, err := svc.WatchDesiredState(ctx, caller, req.Msg.KnownVersion)
			if err != nil {
				return nil, err
			}
			out := &agentv1.WatchDesiredStateResponse{Version: state.Version, Changed: state.Changed, AllowedNames: state.AllowedNames}
			for _, d := range state.Deployments {
				out.Deployments = append(out.Deployments, &agentv1.DesiredDeployment{Name: d.Name, RenewRequestedAt: d.RequestedAt, RenewalVersion: d.RenewalVersion})
			}
			return connect.NewResponse(out), nil
		}}
		a := runtimeAgent(f, client)
		a.Random = func() float64 { return (float64(i) + 0.5) / count }
		workers.Go(func() { a.watchLoop(ctx, make(chan *agentv1.WatchDesiredStateResponse, 1)) })
	}
	awaitRuntime(t, func() bool { return entered.Load() == count && f.Waiting() == count })
	old.CloseWatches()
	restarted := &serveragents.Service{PKI: inst.PKIDB.Write, Clock: f, Sleep: f.Sleep}
	current.Store(restarted)
	state, err := restarted.WatchDesiredState(t.Context(), callers[0], 0)
	if err != nil || state.Version != 2 || len(state.Deployments) != 1 || state.Deployments[0].RenewalVersion != 2 {
		t.Fatalf("outstanding request lost at restart: %+v, %v", state, err)
	}
	restarting.Store(true)
	awaitRuntime(t, func() bool { return f.Waiting() == count })
	for step := 1; step <= 10; step++ {
		f.Advance(100 * time.Millisecond)
		want := int64(float64(step)*float64(count)/10 + 0.5)
		awaitRuntime(t, func() bool { return connected.Load() >= want })
	}
	if connected.Load() != count {
		t.Fatal("agents did not reconnect within their backoff")
	}
	mu.Lock()
	defer mu.Unlock()
	for _, size := range buckets {
		if size > 7 {
			t.Fatalf("reconnect burst=%d agents in one fake 100ms bucket", size)
		}
	}
}
