package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// sentinelSecret must never appear in an error, a warning or a log line.
const sentinelSecret = "SENTINEL-TSIG-SECRET-4f9a" //nolint:gosec // a test sentinel, not a credential

// logBuffer is a bytes.Buffer that tolerates the guard's cleanup goroutine.
type logBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// captureLog returns a debug-level logger and what it wrote.
func captureLog() (*slog.Logger, *logBuffer) {
	buf := &logBuffer{}
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})), buf
}

// recordingProvider is a dnsProvider that records every call and can be told
// to fail, hang or panic. It holds credentials, so the guard redacts for it.
type recordingProvider struct {
	mu    sync.Mutex
	calls []string
	ctxs  []context.Context
	creds *dnsCredentials

	presentErr, cleanErr error
	presentPanic         any
	cleanPanic           any
	cleanBlock           chan struct{} // CleanUp waits for it to close
	cancelOnPresent      context.CancelFunc
	cleanCtxErr          error     // the error of the bound context when CleanUp ran
	cleanDeadline        time.Time // and its deadline
	idleClosed           bool
}

func newRecordingProvider() *recordingProvider {
	return &recordingProvider{creds: &dnsCredentials{Type: DNSTypeRFC2136, TSIGKeyName: "acme-agent", TSIGSecret: newSecret([]byte(sentinelSecret))}}
}

func (p *recordingProvider) dnsCreds() *dnsCredentials { return p.creds }
func (p *recordingProvider) closeIdle()                { p.mu.Lock(); p.idleClosed = true; p.mu.Unlock() }
func (p *recordingProvider) useContext(ctx context.Context) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ctxs = append(p.ctxs, ctx)
}
func (*recordingProvider) Timeout() (time.Duration, time.Duration) { return time.Minute, time.Second }

func (p *recordingProvider) log(s string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, s)
}

func (p *recordingProvider) Present(domain, token, _ string) error {
	p.log("present " + domain + " " + token)
	if p.cancelOnPresent != nil {
		p.cancelOnPresent()
	}
	if p.presentPanic != nil {
		panic(p.presentPanic)
	}
	return p.presentErr
}

func (p *recordingProvider) CleanUp(domain, token, _ string) error {
	p.log("cleanup " + domain + " " + token)
	p.mu.Lock()
	if n := len(p.ctxs); n > 0 {
		p.cleanCtxErr = p.ctxs[n-1].Err()
		p.cleanDeadline, _ = p.ctxs[n-1].Deadline()
	}
	p.mu.Unlock()
	if p.cleanPanic != nil {
		panic(p.cleanPanic)
	}
	if p.cleanBlock != nil {
		<-p.cleanBlock
	}
	return p.cleanErr
}

func (p *recordingProvider) callList() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.calls...)
}

func wildcardDeployment() Deployment {
	return Deployment{Name: "wild", Names: []string{"*.homelab.lan", "homelab.lan"}}
}

func testGuard(ctx context.Context, p dnsProvider, log *slog.Logger) *dnsGuard {
	cfg := DNSProvider{PropagationTimeout: 120, PropagationWait: 3}
	return newDNSGuard(ctx, p, "homelab-dns", cfg, wildcardDeployment(), 2*time.Second, log)
}

func TestGuardRunsPresentAndCleanUpForWildcardAndBaseName(t *testing.T) {
	t.Parallel()
	p := newRecordingProvider()
	g := testGuard(t.Context(), p, nil)
	// lego passes the identifier of the authorization: "homelab.lan" for both
	// "*.homelab.lan" and "homelab.lan".
	for _, tok := range []string{"tok1", "tok2"} {
		if err := g.Present("homelab.lan", tok, "ka-"+tok); err != nil {
			t.Fatal(err)
		}
	}
	for _, tok := range []string{"tok1", "tok2"} {
		if err := g.CleanUp("homelab.lan", tok, "ka-"+tok); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"present homelab.lan tok1", "present homelab.lan tok2", "cleanup homelab.lan tok1", "cleanup homelab.lan tok2"}
	if got := p.callList(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("calls %q, want %q", got, want)
	}
	g.finish()
	if len(p.callList()) != 4 {
		t.Fatalf("finish cleaned again: %q", p.callList())
	}
	// The pause before the first check counts against the timeout.
	if timeout, interval := g.Timeout(); timeout != 123*time.Second || interval != 2*time.Second {
		t.Fatalf("timeout %v, interval %v", timeout, interval)
	}
}

func TestGuardRefusesAForeignDomain(t *testing.T) {
	t.Parallel()
	p := newRecordingProvider()
	log, logs := captureLog()
	g := testGuard(t.Context(), p, log)
	for _, domain := range []string{"evil.example", "sub.homelab.lan", "lan", "", "homelab.lan.evil.example"} {
		if err := g.Present(domain, "tok", "ka"); err == nil {
			t.Errorf("Present(%q) accepted", domain)
		}
		// Nothing was written, so the cleanup of that name is refused quietly.
		if err := g.CleanUp(domain, "tok", "ka"); err == nil {
			t.Errorf("CleanUp(%q) accepted", domain)
		}
	}
	if calls := p.callList(); len(calls) != 0 {
		t.Fatalf("the provider was called: %q", calls)
	}
	if w := g.Warnings(); len(w) != 0 || strings.Contains(logs.String(), "cleanup failed") {
		t.Fatalf("a refused name is not a cleanup problem: %q %s", w, logs.String())
	}
	// Case and a trailing dot do not matter.
	if err := g.Present("HomeLab.LAN.", "tok", "ka"); err != nil {
		t.Fatal(err)
	}
}

func TestGuardCleansUpAfterAFailedPresent(t *testing.T) {
	t.Parallel()
	p := newRecordingProvider()
	p.presentErr = errors.New("server said no")
	g := testGuard(t.Context(), p, nil)
	err := g.Present("homelab.lan", "tok", "ka")
	if err == nil || !strings.Contains(err.Error(), `dns provider "homelab-dns"`) {
		t.Fatalf("Present: %v", err)
	}
	// The provider may have written the record before it failed: finish
	// removes it even when lego forgets to.
	g.finish()
	if got := p.callList(); len(got) != 2 || got[1] != "cleanup homelab.lan tok" {
		t.Fatalf("calls %q", got)
	}
}

func TestGuardCleansUpAfterCancelWithAContextThatIsNotCanceled(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	p := newRecordingProvider()
	g := testGuard(ctx, p, nil)
	if err := g.Present("homelab.lan", "tok", "ka"); err != nil {
		t.Fatal(err)
	}
	cancel()
	// Canceled: no new record, but the old one goes.
	if err := g.Present("homelab.lan", "tok2", "ka2"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Present after cancel: %v", err)
	}
	if err := g.CleanUp("homelab.lan", "tok", "ka"); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cleanCtxErr != nil {
		t.Fatalf("the cleanup context was canceled: %v", p.cleanCtxErr)
	}
	if d := p.cleanDeadline; d.IsZero() || time.Until(d) > cleanupTimeout || time.Until(d) < cleanupTimeout-5*time.Second {
		t.Fatalf("cleanup deadline %v", d)
	}
	if got := strings.Join(p.calls, "|"); got != "present homelab.lan tok|cleanup homelab.lan tok" {
		t.Fatalf("calls %q (the Present after cancel must not reach the provider)", got)
	}
}

func TestGuardPresentStopsWhenTheContextIsCanceledBeforeIt(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	p := newRecordingProvider()
	g := testGuard(ctx, p, nil)
	if err := g.Present("homelab.lan", "tok", "ka"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Present: %v", err)
	}
	g.finish()
	if calls := p.callList(); len(calls) != 0 {
		t.Fatalf("calls %q", calls)
	}
}

func TestGuardCleanUpTimeoutIsRecorded(t *testing.T) {
	t.Parallel()
	p := newRecordingProvider()
	p.cleanBlock = make(chan struct{})
	t.Cleanup(func() { close(p.cleanBlock) })
	log, logs := captureLog()
	g := testGuard(t.Context(), p, log)
	g.cleanupTimeout = 50 * time.Millisecond
	if err := g.Present("homelab.lan", "tok", "ka"); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err := g.CleanUp("homelab.lan", "tok", "ka")
	if err == nil || !strings.Contains(err.Error(), "did not finish") {
		t.Fatalf("CleanUp: %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("the cleanup was not bounded: %v", time.Since(start))
	}
	if w := g.Warnings(); len(w) != 1 || !strings.Contains(w[0], "did not finish") {
		t.Fatalf("warnings %q", w)
	}
	if !strings.Contains(logs.String(), "cleanup failed") || !strings.Contains(logs.String(), "level=WARN") {
		t.Fatalf("no warning logged: %s", logs)
	}
}

func TestGuardCleanUpErrorIsRecordedAndRedacted(t *testing.T) {
	t.Parallel()
	p := newRecordingProvider()
	p.cleanErr = fmt.Errorf("server answered: bad key %s", sentinelSecret)
	log, logs := captureLog()
	g := testGuard(t.Context(), p, log)
	if err := g.Present("homelab.lan", "tok", "ka"); err != nil {
		t.Fatal(err)
	}
	err := g.CleanUp("homelab.lan", "tok", "ka")
	if err == nil || strings.Contains(err.Error(), sentinelSecret) || !strings.Contains(err.Error(), redacted) {
		t.Fatalf("CleanUp: %v", err)
	}
	for _, w := range g.Warnings() {
		if strings.Contains(w, sentinelSecret) {
			t.Fatalf("warning with the secret: %q", w)
		}
	}
	if len(g.Warnings()) != 1 || strings.Contains(logs.String(), sentinelSecret) {
		t.Fatalf("warnings %q, log %s", g.Warnings(), logs)
	}
}

func TestGuardPresentErrorsAreRedacted(t *testing.T) {
	t.Parallel()
	p := newRecordingProvider()
	p.presentErr = fmt.Errorf("auth failed for secret %s", sentinelSecret)
	g := testGuard(t.Context(), p, nil)
	err := g.Present("homelab.lan", "tok", "ka")
	if err == nil || strings.Contains(err.Error(), sentinelSecret) || strings.Contains(fmt.Sprintf("%+v %#v %q", err, err, err), sentinelSecret) {
		t.Fatalf("Present: %v", err)
	}
}

func TestGuardTurnsAPanicIntoAnErrorAndStillCleansUp(t *testing.T) {
	t.Parallel()
	p := newRecordingProvider()
	p.presentPanic = "boom with " + sentinelSecret
	log, logs := captureLog()
	g := testGuard(t.Context(), p, log)
	err := g.Present("homelab.lan", "tok", "ka")
	if err == nil || !strings.Contains(err.Error(), "panicked") || strings.Contains(err.Error(), sentinelSecret) {
		t.Fatalf("Present: %v", err)
	}
	p.presentPanic = nil
	p.cleanPanic = "bad cleanup " + sentinelSecret
	if err := g.CleanUp("homelab.lan", "tok", "ka"); err == nil || !strings.Contains(err.Error(), "panicked") || strings.Contains(err.Error(), sentinelSecret) {
		t.Fatalf("CleanUp: %v", err)
	}
	if strings.Contains(logs.String(), sentinelSecret) {
		t.Fatalf("log has the secret: %s", logs)
	}
	if got := p.callList(); len(got) != 2 {
		t.Fatalf("calls %q", got)
	}
}

func TestGuardFinishCleansWhatLegoSkipped(t *testing.T) {
	t.Parallel()
	p := newRecordingProvider()
	g := testGuard(t.Context(), p, nil)
	for _, tok := range []string{"a", "b"} {
		if err := g.Present("homelab.lan", tok, "ka"+tok); err != nil {
			t.Fatal(err)
		}
	}
	if err := g.CleanUp("homelab.lan", "a", "kaa"); err != nil {
		t.Fatal(err)
	}
	g.finish()
	g.finish() // idempotent
	got := p.callList()
	if len(got) != 4 || got[3] != "cleanup homelab.lan b" {
		t.Fatalf("calls %q", got)
	}
}

func TestGuardCloseWipesTheCredentialsAndReleasesConnections(t *testing.T) {
	t.Parallel()
	p := newRecordingProvider()
	g := testGuard(t.Context(), p, nil)
	if !p.creds.TSIGSecret.isSet() {
		t.Fatal("no secret to begin with")
	}
	g.close()
	g.close()
	if p.creds.TSIGSecret.isSet() || !p.idleClosed {
		t.Fatalf("secret set %v, connections closed %v", p.creds.TSIGSecret.isSet(), p.idleClosed)
	}
}
