package notify

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
)

// ActionTest is the audit action of a test message.
const ActionTest = "notification.test"

// ErrNoChannel: nothing to test, because neither notify.email nor
// notify.webhook is configured.
var ErrNoChannel = errors.New("no notification channel is configured – set notify.email or notify.webhook in the server's configuration")

// WaitError refuses a test that comes too soon after the previous one.
type WaitError struct{ RetryAfter time.Duration }

func (e *WaitError) Error() string {
	return fmt.Sprintf("a test message was sent a moment ago – try again in %d seconds", int(e.RetryAfter.Seconds())+1)
}

// Result is the outcome of one channel. Error is the channel's own error
// text, shortened: never a secret (password, HMAC key, webhook path or
// query), but it may name hosts, file paths and recipient addresses.
type Result struct {
	Channel string `json:"channel"`
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
}

// SendAll sends d through every channel at once (a slow mail server must not
// delay the webhook) and returns one result per channel, in order.
func SendAll(ctx context.Context, channels []Channel, d Digest) []Result {
	out := make([]Result, len(channels))
	var wg sync.WaitGroup
	for i, c := range channels {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i] = Result{Channel: c.Name(), OK: true}
			if err := c.Send(ctx, d); err != nil {
				out[i] = Result{Channel: c.Name(), Error: shorten(clean(err.Error()), 300)}
			}
		}()
	}
	wg.Wait()
	return out
}

func shorten(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

// minTestGap keeps a loop or a double click from mailing the recipients
// over and over.
const minTestGap = 10 * time.Second

// Tester sends the test message of the web UI and the REST API
// (`myownpki notify test` uses SendAll directly). It checks the role,
// sends synchronously and audits the attempt.
type Tester struct {
	Channels []Channel
	Server   string // the host name in the message
	Clock    clock.Clock
	Audit    *sql.DB // writer of the tenant's audit log
	Scope    string
	Tenant   string

	mu   sync.Mutex
	last time.Time
}

// Names lists the configured channels.
func (t *Tester) Names() []string {
	out := make([]string, 0, len(t.Channels))
	for _, c := range t.Channels {
		out = append(out, c.Name())
	}
	return out
}

// Send checks that who may send a test (tenant admin), sends it through
// every channel and appends one audit entry with the result per channel – never a
// secret (password, HMAC key, webhook path or query); the error texts may name
// hosts, file paths and recipient addresses. A refusal is audited as denied; with no
// channel there is nothing to send and nothing to audit. The audit entry is
// written after the send (it holds the result), so an audit failure is
// reported although the message went out.
func (t *Tester) Send(ctx context.Context, who keys.Who) ([]Result, error) {
	now := t.Clock.Now().UTC()
	if err := who.Principal.Check(authz.TestNotify, authz.Resource{Tenant: t.Tenant}, now); err != nil {
		if aerr := t.audit(ctx, who, now, audit.ResultDenied, map[string]any{"reason": err.Error()}); aerr != nil {
			return nil, errors.Join(err, aerr)
		}
		return nil, err
	}
	if len(t.Channels) == 0 {
		return nil, ErrNoChannel
	}
	t.mu.Lock()
	if wait := minTestGap - now.Sub(t.last); wait > 0 && !t.last.IsZero() {
		t.mu.Unlock()
		return nil, &WaitError{RetryAfter: wait}
	}
	t.last = now
	t.mu.Unlock()

	results := SendAll(ctx, t.Channels, TestDigest(t.Server, now))
	result := audit.ResultSuccess
	channels := map[string]any{}
	for _, r := range results {
		entry := map[string]any{"ok": r.OK}
		if !r.OK {
			result = audit.ResultFailure
			entry["error"] = r.Error
		}
		channels[r.Channel] = entry
	}
	if err := t.audit(ctx, who, now, result, map[string]any{"channels": channels}); err != nil {
		return results, err
	}
	return results, nil
}

func (t *Tester) audit(ctx context.Context, who keys.Who, now time.Time, result audit.Result, details map[string]any) error {
	// The request may be gone by now; the entry must not be lost with it.
	_, _, err := audit.Append(context.WithoutCancel(ctx), t.Audit, t.Scope, audit.Entry{
		Time: now, Actor: who.Actor, Action: ActionTest, Target: audit.Target{Type: "notification", ID: "test"},
		Result: result, SourceIP: who.SourceIP, Details: details,
	}, "")
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	return nil
}
