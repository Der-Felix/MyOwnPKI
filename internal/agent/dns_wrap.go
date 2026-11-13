package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	// cleanupTimeout bounds one CleanUp while the issuance runs normally.
	cleanupTimeout = 30 * time.Second
	// shutdownCleanupBudget is all the time the CleanUps of one issuance share
	// once its context is canceled (the agent is stopping): the unit's
	// TimeoutStopSec is 30 s, and a hanging DNS server must not make systemd
	// kill the agent in the middle of the second record.
	shutdownCleanupBudget = 12 * time.Second
)

// Optional interfaces of the providers behind the guard.
type (
	// dnsCredentialsHolder lets the guard remove secrets from every error and
	// log line and wipe them when the issuance is over.
	dnsCredentialsHolder interface{ dnsCreds() *dnsCredentials }
	// dnsContextBinder hands the context of the current phase to a provider
	// whose lego interface has none (Present and CleanUp take no context).
	dnsContextBinder interface{ useContext(ctx context.Context) }
	// dnsIdleCloser releases connections when the issuance is over.
	dnsIdleCloser interface{ closeIdle() }
)

// recordKey identifies one presented challenge record.
type recordKey struct{ domain, token, keyAuth string }

// dnsGuard is the wrapper every DNS provider runs in (docs/PHASE3.md §13.2,
// §13.4). lego calls it like a provider; it
//
//   - refuses a domain that is not one of the deployment's names, so a
//     compromised ACME server cannot make the agent write another name's record;
//   - checks the context before Present, and hands it to the provider;
//   - runs CleanUp with a context that is not canceled, for at most
//     cleanupTimeout (when the issuance was canceled: within one shared
//     budget of shutdownCleanupBudget), and records a failure, which lego only
//     logs; Notice puts the failures into the deployment's status;
//   - turns a panic of the provider into an error;
//   - removes the provider's secrets from every error and log line, and wipes
//     them when the issuance is over.
type dnsGuard struct {
	inner dnsProvider
	ctx   context.Context //nolint:containedctx // one guard per issuance; lego's provider interface has no context
	log   *slog.Logger
	name  string // the dns_providers key, for messages

	names             map[string]bool // base names of the deployment, no "*."
	timeout, interval time.Duration
	cleanupTimeout    time.Duration
	cleanupBudget     time.Duration // shared by all CleanUps once ctx is canceled

	mu         sync.Mutex
	pending    map[recordKey]bool
	warnings   []string
	leftover   []string        // domains whose record may remain, in order, without repeats
	budget     context.Context //nolint:containedctx // the shared deadline of the CleanUps after a cancel; nil until the first one
	budgetStop context.CancelFunc
	closed     bool
}

// newDNSGuard wraps inner for one issuance of deployment d. interval is the
// polling interval of the propagation check.
func newDNSGuard(ctx context.Context, inner dnsProvider, name string, cfg DNSProvider, d Deployment, interval time.Duration, log *slog.Logger) *dnsGuard {
	g := &dnsGuard{
		inner: inner, ctx: ctx, log: log, name: name,
		names:    map[string]bool{},
		timeout:  time.Duration(cfg.PropagationTimeout+cfg.PropagationWait) * time.Second,
		interval: interval, cleanupTimeout: cleanupTimeout, cleanupBudget: shutdownCleanupBudget,
		pending: map[recordKey]bool{},
	}
	for _, n := range d.Names {
		g.names[baseName(n)] = true
	}
	return g
}

// baseName is the name lego passes to Present: the identifier of the
// authorization, which for "*.x" is "x".
func baseName(n string) string {
	return strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(n), "*."), ".")
}

// Timeout is lego's propagation timeout and polling interval. The pause
// before the first check (propagation_wait) counts against the timeout.
func (g *dnsGuard) Timeout() (time.Duration, time.Duration) { return g.timeout, g.interval }

func (g *dnsGuard) redact(err error) error {
	if h, ok := g.inner.(dnsCredentialsHolder); ok && h.dnsCreds() != nil {
		return h.dnsCreds().redact(err)
	}
	return err
}

func (g *dnsGuard) redactText(s string) string {
	if h, ok := g.inner.(dnsCredentialsHolder); ok && h.dnsCreds() != nil {
		return redactText(s, h.dnsCreds().secrets()...)
	}
	return s
}

func (g *dnsGuard) bind(ctx context.Context) {
	if b, ok := g.inner.(dnsContextBinder); ok {
		b.useContext(ctx)
	}
}

// call runs f, turning a panic into an error. The panic text goes through the
// redaction like any error.
func (g *dnsGuard) call(what string, f func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = g.redact(fmt.Errorf("the DNS provider panicked during %s: %v", what, r))
		}
	}()
	return g.redact(f())
}

// Present creates the TXT record of a challenge.
func (g *dnsGuard) Present(domain, token, keyAuth string) error {
	if err := g.ctx.Err(); err != nil {
		return fmt.Errorf("dns-01: not started: %w", err)
	}
	if err := g.allowed(domain); err != nil {
		return err
	}
	k := recordKey{domain, token, keyAuth}
	// Count the record as present before the provider runs: a provider that
	// fails half way may have written it.
	g.mu.Lock()
	g.pending[k] = true
	g.mu.Unlock()
	g.bind(g.ctx)
	if err := g.call("Present", func() error { return g.inner.Present(domain, token, keyAuth) }); err != nil {
		return fmt.Errorf("dns provider %q: %w", g.name, err)
	}
	return nil
}

// CleanUp removes the TXT record of a challenge. It runs even when the
// issuance was canceled, and its failure is recorded as a warning: the
// certificate, if issued, is still good.
func (g *dnsGuard) CleanUp(domain, token, keyAuth string) error {
	// Present refused this name, so nothing was written: no warning.
	if err := g.allowed(domain); err != nil {
		return err
	}
	k := recordKey{domain, token, keyAuth}
	g.mu.Lock()
	delete(g.pending, k)
	g.mu.Unlock()
	err := g.cleanUp(k)
	if err != nil {
		g.warn(domain, err)
		return err
	}
	return nil
}

// cleanupParent is the context the next CleanUp's limit hangs on, and the
// longest the CleanUp may take. While the issuance runs, that is a context
// that is not canceled and cleanupTimeout. Once the issuance is canceled (the
// agent is stopping), all CleanUps share one deadline of cleanupBudget, which
// starts with the first of them; ok is false when it has passed.
func (g *dnsGuard) cleanupParent() (parent context.Context, limit time.Duration, ok bool) {
	if g.ctx.Err() == nil {
		return context.WithoutCancel(g.ctx), g.cleanupTimeout, true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.budget == nil {
		g.budget, g.budgetStop = context.WithTimeout(context.WithoutCancel(g.ctx), g.cleanupBudget)
	}
	return g.budget, g.cleanupBudget, g.budget.Err() == nil
}

func (g *dnsGuard) cleanUp(k recordKey) error {
	parent, limit, ok := g.cleanupParent()
	if !ok {
		return fmt.Errorf("dns provider %q: removing the TXT record for %s was not tried: the %s that the agent takes for all cleanups while it stops are used up", g.name, k.domain, g.cleanupBudget)
	}
	ctx, cancel := context.WithTimeout(parent, g.cleanupTimeout)
	defer cancel()
	g.bind(ctx)
	done := make(chan error, 1)
	go func() {
		done <- g.call("CleanUp", func() error { return g.inner.CleanUp(k.domain, k.token, k.keyAuth) })
	}()
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("dns provider %q: removing the TXT record for %s: %w", g.name, k.domain, err)
		}
		return nil
	case <-ctx.Done():
		return fmt.Errorf("dns provider %q: removing the TXT record for %s did not finish within %s", g.name, k.domain, min(limit, g.cleanupTimeout))
	}
}

// finish removes every record that lego did not clean up (it skips duplicate
// tokens and does nothing after a panic elsewhere). Call it when the
// issuance is over; it is cheap when nothing is left.
func (g *dnsGuard) finish() {
	g.mu.Lock()
	var left []recordKey
	for k := range g.pending {
		left = append(left, k)
	}
	clear(g.pending)
	g.mu.Unlock()
	for _, k := range left {
		if err := g.cleanUp(k); err != nil {
			g.warn(k.domain, err)
		}
	}
}

// close wipes the credentials and releases connections. It runs after finish.
func (g *dnsGuard) close() {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return
	}
	g.closed = true
	stop := g.budgetStop
	g.mu.Unlock()
	if stop != nil {
		stop()
	}
	if c, ok := g.inner.(dnsIdleCloser); ok {
		c.closeIdle()
	}
	if h, ok := g.inner.(dnsCredentialsHolder); ok && h.dnsCreds() != nil {
		h.dnsCreds().wipe()
	}
}

// Warnings are the cleanup problems of this issuance, with secrets removed.
func (g *dnsGuard) Warnings() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.warnings...)
}

// Notice is the text for the status of the deployment when a cleanup failed,
// or "" when none did. It names the records that may remain and nothing the
// provider said, so it carries no secret and no provider text; the details
// are in Warnings and in the log. A certificate that was issued is still good,
// so the issuance does not fail because of it.
func (g *dnsGuard) Notice() string {
	g.mu.Lock()
	left := slices.Clone(g.leftover)
	g.mu.Unlock()
	if len(left) == 0 {
		return ""
	}
	const shown = 3
	var names []string
	for _, d := range left[:min(len(left), shown)] {
		names = append(names, "_acme-challenge."+d)
	}
	text := "dns-01 cleanup failed: a TXT record may remain at " + strings.Join(names, ", ")
	if len(left) > shown {
		text += fmt.Sprintf(" and %d more", len(left)-shown)
	}
	return text + "; remove it by hand if it stays (the agent log has the details)"
}

func (g *dnsGuard) warn(domain string, err error) {
	text := g.redactText(err.Error())
	g.mu.Lock()
	g.warnings = append(g.warnings, text)
	if d := baseName(domain); !slices.Contains(g.leftover, d) {
		g.leftover = append(g.leftover, d)
	}
	g.mu.Unlock()
	if g.log != nil {
		g.log.Warn("dns-01 cleanup failed: a TXT record may be left behind; remove it by hand if it stays",
			slog.String("provider", g.name), slog.String("domain", domain), slog.String("error", text))
	}
}

// allowed refuses a domain that is not a name of this deployment.
func (g *dnsGuard) allowed(domain string) error {
	if !g.names[baseName(domain)] {
		return errors.New("dns-01: the ACME server asked for a record for a name that is not one of this deployment's names; refused")
	}
	return nil
}
