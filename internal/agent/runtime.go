package agent

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	agentv1 "github.com/Der-Felix/MyOwnPKI/internal/gen/myownpki/agent/v1"
)

func (a *Agent) fraction() float64 {
	if a.Random != nil {
		return a.Random()
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0.5
	}
	return float64(binary.BigEndian.Uint64(b[:])>>11) / (1 << 53)
}

func deploymentBackoff(failures int) time.Duration {
	return min(10*time.Minute*time.Duration(1<<min(max(failures-1, 0), 6)), 6*time.Hour)
}

func (a *Agent) wakeReport() {
	if a.reportWake != nil {
		select {
		case a.reportWake <- struct{}{}:
		default:
		}
	}
}

// waitUntilEvent uses the injected wait for timers and releases it when
// an event wins. No real timer is hidden from fake-clock tests.
func (a *Agent) waitUntilEvent(ctx context.Context, d time.Duration, event <-chan struct{}) error {
	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- a.Sleep(wctx, d) }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-event:
		return nil
	case err := <-done:
		return err
	}
}

func (a *Agent) report(ctx context.Context) error {
	stored, err := a.deploymentResults()
	if err != nil {
		return err
	}
	if len(a.cfg.Deployments) > 100 {
		return errors.New("report: more than 100 configured deployments")
	}
	in := &agentv1.ReportRequest{AgentVersion: a.Version, Os: a.OS, Arch: a.Arch}
	for _, d := range a.cfg.Deployments {
		result := DeploymentResult{Name: d.Name, State: "pending"}
		for _, r := range stored {
			if r.Name == d.Name {
				result = r
				break
			}
		}
		in.Deployments = append(in.Deployments, reportDeployment(d, result))
	}
	var removed []DeploymentResult
	for _, r := range stored {
		if !slices.ContainsFunc(a.cfg.Deployments, func(d Deployment) bool { return d.Name == r.Name }) {
			removed = append(removed, r)
			in.Deployments = append(in.Deployments, reportDeployment(Deployment{Name: r.Name}, r))
			break // one removed result per report keeps 100 active deployments within the limit
		}
	}
	if _, err = a.ch.client.Report(ctx, connect.NewRequest(in)); err != nil {
		return explainTLS(err)
	}
	if len(removed) > 0 {
		a.passMu.Lock()
		_, err = a.pruneDeploymentResults(removed)
		a.passMu.Unlock()
		if err != nil {
			return fmt.Errorf("report: prune accepted removed deployment: %w", err)
		}
		// Report the omission (and the next removed result, if any) at once.
		a.wakeReport()
	}
	return nil
}

func reportDeployment(d Deployment, r DeploymentResult) *agentv1.DeploymentReport {
	out := &agentv1.DeploymentReport{Name: d.Name, Profile: d.Profile, Names: d.Names, Challenge: d.Challenge,
		State: r.State, CertificateSerial: r.Serial, ServedFingerprint: r.Fingerprint, LastError: r.LastError,
		HandledRenewalVersion: r.HandledRenewalVersion}
	if !r.NotAfter.IsZero() {
		out.NotAfter = r.NotAfter.UTC().Format(time.RFC3339)
	}
	if !r.DeployedAt.IsZero() {
		out.DeployedAt = r.DeployedAt.UTC().Format(time.RFC3339)
	}
	return out
}

func (a *Agent) reportLoop(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		if a.Identity() == nil {
			if a.Sleep(ctx, time.Second) != nil {
				return
			}
			continue
		}
		callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := a.report(callCtx)
		cancel()
		var wait time.Duration
		switch {
		case connect.CodeOf(err) == connect.CodeResourceExhausted:
			wait = 270*time.Second + time.Duration(a.fraction()*float64(time.Minute))
		case err != nil:
			if ctx.Err() == nil {
				a.log.Warn("agent report failed", slog.Any("error", err))
			}
			wait = time.Duration(a.fraction() * float64(backoff))
			backoff = min(2*backoff, time.Minute)
		default:
			backoff = time.Second
			wait = 270*time.Second + time.Duration(a.fraction()*float64(time.Minute))
		}
		if a.waitUntilEvent(ctx, wait, a.reportWake) != nil {
			return
		}
	}
}

func (a *Agent) watchBackoffDelay(backoff time.Duration) time.Duration {
	return time.Duration(a.fraction() * float64(backoff))
}

func (a *Agent) watchLoop(ctx context.Context, updates chan<- *agentv1.WatchDesiredStateResponse) {
	var version int64
	backoff := time.Second
	for ctx.Err() == nil {
		if a.Identity() == nil {
			if a.Sleep(ctx, time.Second) != nil {
				return
			}
			continue
		}
		callCtx, cancel := context.WithTimeout(ctx, time.Minute)
		reply, err := a.ch.client.WatchDesiredState(callCtx, connect.NewRequest(&agentv1.WatchDesiredStateRequest{KnownVersion: version}))
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if a.Sleep(ctx, a.watchBackoffDelay(backoff)) != nil {
				return
			}
			backoff = min(2*backoff, time.Minute)
			continue
		}
		backoff = time.Second
		version = reply.Msg.Version
		if reply.Msg.Changed {
			select {
			case updates <- reply.Msg:
			case <-ctx.Done():
				return
			}
		}
	}
}

type renewalPlan struct {
	serial                                     string
	renew, nextARI, ariStart, ariEnd, ariPoint time.Time
}

func (a *Agent) currentLeaf(d Deployment) (*x509.Certificate, error) {
	f := deploymentPaths(d)
	path := f.Fullchain
	if path == "" {
		path = f.Certificate
	}
	data, _, err := a.readTarget(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("deployed certificate is not PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

func (a *Agent) plan(ctx context.Context, d Deployment, plans map[string]*renewalPlan, allowARI bool) (*renewalPlan, bool) {
	leaf, err := a.currentLeaf(d)
	if err != nil {
		return &renewalPlan{renew: a.Now()}, false
	}
	serial := certificateSerial(leaf)
	p := plans[d.Name]
	if p == nil || p.serial != serial {
		p = &renewalPlan{serial: serial, renew: RenewAt(leaf, serialFraction(leaf))}
		plans[d.Name] = p
	}
	polled := false
	if allowARI && !a.Now().Before(p.nextARI) {
		polled = true
		p.nextARI = a.Now().Add(6 * time.Hour)
		get := a.renewalInfo
		if a.ariForTest != nil {
			get = a.ariForTest
		}
		// One short ARI lookup per tick keeps operator requests responsive
		// even when the directory or renewal-info endpoint is unreachable.
		ariCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		a.passMu.Lock()
		window, err := get(ariCtx, leaf)
		a.passMu.Unlock()
		cancel()
		if err == nil {
			if !window.Start.Equal(p.ariStart) || !window.End.Equal(p.ariEnd) {
				p.ariStart, p.ariEnd = window.Start, window.End
				p.ariPoint = window.Start.Add(time.Duration(a.fraction() * float64(window.End.Sub(window.Start))))
			}
			if !p.ariPoint.IsZero() && p.ariPoint.Before(p.renew) {
				p.renew = p.ariPoint
			}
			if window.RetryAfter > 0 {
				p.nextARI = a.Now().Add(max(time.Minute, min(window.RetryAfter, 24*time.Hour)))
			}
		}
	}
	return p, polled
}

func renewalVersion(state *agentv1.WatchDesiredStateResponse, name string) int64 {
	if state != nil {
		for _, d := range state.Deployments {
			if d.Name == name {
				return d.RenewalVersion
			}
		}
	}
	return 0
}

func namesAllowed(d Deployment, state *agentv1.WatchDesiredStateResponse) bool {
	if state == nil {
		return true
	} // the server remains authoritative before the first watch
	for _, name := range d.Names {
		if !slices.ContainsFunc(state.AllowedNames, func(pattern string) bool {
			if pattern == name {
				return true
			}
			suffix, ok := strings.CutPrefix(pattern, "*.")
			return ok && strings.HasSuffix(name, "."+suffix)
		}) {
			return false
		}
	}
	return true
}

// schedule chooses only local deployment names. Persisted failures bound
// retries across restarts; a new desired-state request bypasses it once.
func (a *Agent) schedule(ctx context.Context, state *agentv1.WatchDesiredStateResponse, plans map[string]*renewalPlan) (time.Duration, error) {
	stored, err := a.deploymentResults()
	if err != nil {
		return 0, err
	}
	now, wait := a.Now(), time.Minute
	var due []string
	var refused []DeploymentResult
	polledARI := false
	for _, d := range a.cfg.Deployments {
		r := DeploymentResult{}
		for _, old := range stored {
			if old.Name == d.Name {
				r = old
				break
			}
		}
		requested := renewalVersion(state, d.Name) > r.HandledRenewalVersion
		at := now
		if !requested && (r.State == "failed" || r.State == "rolled_back") {
			if r.NextAttempt.IsZero() {
				r.NextAttempt = now.Add(10 * time.Minute)
				r.Failures = max(1, r.Failures)
				a.passMu.Lock()
				err := a.saveDeploymentResults([]DeploymentResult{r})
				a.passMu.Unlock()
				if err != nil {
					return 0, err
				}
			}
			at = r.NextAttempt
		} else if !requested && r.State == "deployed" {
			p, polled := a.plan(ctx, d, plans, !polledARI)
			polledARI = polledARI || polled
			at = p.renew
			wait = min(wait, max(time.Second, p.nextARI.Sub(now)))
		}
		if at.After(now) {
			wait = min(wait, at.Sub(now))
			continue
		}
		if !namesAllowed(d, state) {
			refused = append(refused, DeploymentResult{Name: d.Name, State: "failed", LastError: "configured names are not in the agent's allowed names", AttemptedAt: now,
				Failures: min(r.Failures+1, 7), NextAttempt: now.Add(deploymentBackoff(r.Failures + 1)), HandledRenewalVersion: max(r.HandledRenewalVersion, renewalVersion(state, d.Name))})
			continue
		}
		due = append(due, d.Name)
	}
	if state != nil {
		for _, d := range state.Deployments {
			if slices.ContainsFunc(a.cfg.Deployments, func(local Deployment) bool { return local.Name == d.Name }) {
				continue
			}
			if slices.ContainsFunc(stored, func(r DeploymentResult) bool { return r.Name == d.Name && r.HandledRenewalVersion >= d.RenewalVersion }) {
				continue
			}
			refused = append(refused, DeploymentResult{Name: d.Name, State: "failed", LastError: "deployment is no longer configured on this host", HandledRenewalVersion: d.RenewalVersion})
		}
	}
	if len(refused) > 0 {
		a.passMu.Lock()
		err := a.saveDeploymentResults(refused)
		a.passMu.Unlock()
		if err != nil {
			return 0, err
		}
	}
	if len(due) > 0 {
		requested := map[string]int64{}
		for _, name := range due {
			requested[name] = renewalVersion(state, name)
		}
		_, runErr := a.runPass(ctx, due, requested)
		if errors.Is(runErr, ErrACMEAccountRegistration) {
			return 0, runErr
		}
		if runErr != nil && ctx.Err() == nil {
			a.log.Warn("deployment pass failed", slog.Any("error", runErr))
		}
	}
	if len(refused) > 0 && len(due) == 0 {
		a.wakeReport()
	}
	return max(wait, time.Second), nil
}

func (a *Agent) run(ctx context.Context) error {
	if !a.runMu.TryLock() {
		return errors.New("the agent is already running")
	}
	defer a.runMu.Unlock()
	if err := a.preflightStart(); err != nil {
		return fmt.Errorf("startup write check: %w", err)
	}
	if _, err := a.Recover(ctx); err != nil {
		return fmt.Errorf("recover deployment: %w", err)
	}
	if ctx.Err() != nil {
		return nil
	}
	a.passMu.Lock()
	if a.reportWake == nil {
		a.reportWake = make(chan struct{}, 1)
	}
	a.passMu.Unlock()
	ctx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	updates := make(chan *agentv1.WatchDesiredStateResponse, 1)
	if a.ch != nil {
		workers.Go(func() { _ = a.maintainIdentity(ctx) })
		workers.Go(func() { a.reportLoop(ctx) })
		workers.Go(func() { a.watchLoop(ctx, updates) })
	}
	plans := map[string]*renewalPlan{}
	var desired *agentv1.WatchDesiredStateResponse
	for ctx.Err() == nil {
		wait := time.Second
		if id, err := a.st.identity(); err == nil && a.Now().Before(id.Leaf.NotAfter) {
			wait, err = a.schedule(ctx, desired, plans)
			if err != nil {
				return err
			}
		}
		waitCtx, stopWait := context.WithCancel(ctx)
		timeout := make(chan error, 1)
		go func() { timeout <- a.Sleep(waitCtx, wait) }()
		select {
		case <-ctx.Done():
		case next := <-updates:
			desired = next
		case err := <-timeout:
			if err != nil && ctx.Err() == nil {
				stopWait()
				return err
			}
		}
		stopWait()
	}
	return nil
}
