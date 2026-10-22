package acme

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
)

// TestRateLimits (PHASE2 step 11): the tenant's limits apply, a client
// over a limit gets 429 rateLimited with the real wait as Retry-After, and
// the window opens again after an hour (fake clock).
func TestRateLimits(t *testing.T) {
	t.Parallel()
	v := newEnv(t, ca.ApprovalOpen)
	var mu sync.Mutex
	lim := Limits{OrdersPerAccount: 2, FailedPerName: 2, AccountsPerIP: 2}
	v.s.opt.Limits = func(context.Context) (Limits, error) {
		mu.Lock()
		defer mu.Unlock()
		return lim, nil
	}
	limited := func(what string, a *answer, wantWait int) {
		t.Helper()
		if a.code != http.StatusTooManyRequests || a.problem() != "rateLimited" {
			t.Fatalf("%s: %d %s", what, a.code, a.body)
		}
		if got, _ := strconv.Atoi(a.header.Get("Retry-After")); got != wantWait {
			t.Errorf("%s: Retry-After %q, want %d", what, a.header.Get("Retry-After"), wantWait)
		}
	}

	// New accounts per client address.
	c := v.client(t)
	c.register()
	v.client(t).register()
	limited("third account", v.client(t).register(), 3600)
	v.Clock.Advance(20 * time.Minute)
	limited("third account later", v.client(t).register(), 2400)
	v.Clock.Advance(41 * time.Minute)
	if a := v.client(t).register(); a.code != http.StatusCreated {
		t.Errorf("after the hour: %d %s", a.code, a.body)
	}

	// New orders per account.
	c.nonce = "" // the cached one expired with the hour
	for i := range 2 {
		if o := c.order(fmt.Sprintf("o%d.homelab.lan", i)); o.code != http.StatusCreated {
			t.Fatalf("order %d: %d %s", i, o.code, o.body)
		}
	}
	limited("third order", c.order("o3.homelab.lan"), 3600)

	// A changed setting counts at the next request – no restart.
	mu.Lock()
	lim.OrdersPerAccount = 10
	mu.Unlock()
	if o := c.order("o3.homelab.lan"); o.code != http.StatusCreated {
		t.Errorf("order after raising the limit: %d %s", o.code, o.body)
	}

	// Failed validations per name: after two, the next start is refused.
	other := v.client(t)
	other.register()
	for range 2 {
		other.challengeWith("broken.homelab.lan", func(string, string) http.HandlerFunc {
			return func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) }
		})
	}
	order := other.order("broken.homelab.lan")
	a := other.post(strs(order.json["authorizations"])[0], nil)
	for _, x := range list(a.json["challenges"]) {
		if ch, _ := x.(map[string]any); ch["type"] == "http-01" {
			url, _ := ch["url"].(string)
			limited("third validation", other.post(url, map[string]any{}), 3600)
		}
	}
}

// TestLimiterCap: many client addresses cost memory only up to the cap;
// the oldest windows go first, the newest keep their count.
func TestLimiterCap(t *testing.T) {
	t.Parallel()
	clk := clock.NewFake(time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC))
	l := newLimiter(clk)
	l.maxKeys = 1000
	for i := range 50_000 {
		clk.Advance(time.Millisecond)
		l.allow(ipKey(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255)), 1, time.Hour)
		if len(l.hits) > l.maxKeys {
			t.Fatalf("after %d addresses: %d windows", i+1, len(l.hits))
		}
	}
	newest := ipKey("10.0.195.79") // address 49999
	if ok, _ := l.allow(newest, 1, time.Hour); ok {
		t.Error("the newest address lost its count")
	}
	if ok, _ := l.allow(ipKey("10.0.0.0"), 1, time.Hour); !ok {
		t.Error("the oldest address should have been dropped")
	}
	// Expired windows go before live ones.
	clk.Advance(2 * time.Hour)
	l.allow("fresh", 1, time.Hour)
	if len(l.hits) != 1 && len(l.hits) > l.maxKeys {
		t.Errorf("%d windows after expiry", len(l.hits))
	}
}

func TestIPKeyAndRetry(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"192.0.2.7":             "192.0.2.7",
		"::ffff:192.0.2.7":      "192.0.2.7",
		"2001:db8:1:2:aaaa::1":  "2001:db8:1:2::/64",
		"2001:db8:1:2:bbbb::99": "2001:db8:1:2::/64",
		"not-an-ip":             "not-an-ip",
	} {
		if got := ipKey(in); got != want {
			t.Errorf("ipKey(%q) = %q, want %q", in, got, want)
		}
	}
	for d, want := range map[time.Duration]int{0: 1, time.Millisecond: 1, time.Second: 1, 1500 * time.Millisecond: 2, time.Hour: 3600} {
		if got := retrySeconds(d); got != want {
			t.Errorf("retrySeconds(%s) = %d, want %d", d, got, want)
		}
	}
}
