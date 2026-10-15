package auth

import (
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
)

// rule: the first free failures cost nothing, then the wait doubles from
// base up to limit. Failures are forgotten after forget without a new one.
type rule struct {
	free        int
	base, limit time.Duration
	forget      time.Duration
}

// Throttle rules (PHASE1 step 10, owner decision d): strict per (IP, user),
// looser per user, so one attacker is slowed down fast and a distributed
// attack on one account still is, without locking the user out for good.
// Unknown user names share one counter per IP (owner 2026-10-15): invented
// names must not create entries of their own.
var (
	strictRule = rule{free: 5, base: time.Second, limit: 15 * time.Minute, forget: time.Hour}
	looseRule  = rule{free: 20, base: time.Second, limit: 15 * time.Minute, forget: time.Hour}
)

// maxThrottleEntries bounds the memory: rotating names and addresses must not
// grow the map without end.
const maxThrottleEntries = 100_000

type throttleEntry struct {
	failures int
	last     time.Time
	rule     rule
}

// wait is how long this entry still slows down; 0 = not now.
func (e *throttleEntry) wait(now time.Time) time.Duration {
	r := e.rule
	if now.Sub(e.last) >= r.forget || e.failures < r.free {
		return 0
	}
	d := min(r.base<<min(e.failures-r.free, 20), r.limit)
	return max(d-now.Sub(e.last), 0)
}

// Throttle slows down guessing of passwords, TOTP and recovery codes. It
// lives in memory and is checked before any hash is computed. The lockout in
// the database (users.locked_until) is the second, persistent stage.
type Throttle struct {
	mu      sync.Mutex
	entries map[string]*throttleEntry
}

// NewThrottle returns an empty throttle.
func NewThrottle() *Throttle { return &Throttle{entries: map[string]*throttleEntry{}} }

// ipKey groups addresses the way one attacker gets them: IPv4 one by one, an
// IPv6 client by its /64 – a single host usually owns a whole /64.
// IPv4-mapped IPv6 counts as IPv4.
func ipKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	a = a.Unmap()
	if a.Is6() {
		p, err := a.WithZone("").Prefix(64)
		if err == nil {
			return p.String()
		}
	}
	return a.String()
}

// keys returns the counters of one attempt with their rules: a known user
// has a strict (IP, user) and a loose per-user counter; an unknown name only
// the per-IP counter for unknown names.
func throttleKeys(ip, user string, known bool) map[string]rule {
	if !known {
		return map[string]rule{"n|" + ipKey(ip): strictRule}
	}
	u := strings.ToLower(user)
	return map[string]rule{"s|" + ipKey(ip) + "|" + u: strictRule, "u|" + u: looseRule}
}

// Wait returns how long the attempt must wait; 0 = go ahead. known: the
// user name exists.
func (t *Throttle) Wait(ip, user string, known bool, now time.Time) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	var w time.Duration
	for key := range throttleKeys(ip, user, known) {
		if e := t.entries[key]; e != nil {
			w = max(w, e.wait(now))
		}
	}
	return w
}

// Failure counts a failed attempt.
func (t *Throttle) Failure(ip, user string, known bool, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.entries)+2 > maxThrottleEntries {
		t.prune(now)
	}
	for key, r := range throttleKeys(ip, user, known) {
		e := t.entries[key]
		if e == nil || now.Sub(e.last) >= r.forget {
			e = &throttleEntry{rule: r}
			t.entries[key] = e
		}
		e.failures++
		e.last = now
	}
}

// Success clears the strict counter of (ip, user). The per-user counter
// stays: a successful login of the real user must not reset what an attacker
// elsewhere has built up.
func (t *Throttle) Success(ip, user string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, "s|"+ipKey(ip)+"|"+strings.ToLower(user))
}

// Forget clears every counter of user (myownpki user unlock).
func (t *Throttle) Forget(user string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	u := strings.ToLower(user)
	for key := range t.entries {
		if key == "u|"+u || (strings.HasPrefix(key, "s|") && strings.HasSuffix(key, "|"+u)) {
			delete(t.entries, key)
		}
	}
}

// prune makes room: first entries that are forgotten anyway, then the ones
// with the fewest failures – but never one that is slowing somebody down
// right now (owner 2026-10-15). Only braking entries can push the map past
// its size, and each of them took several failures from its own address.
func (t *Throttle) prune(now time.Time) {
	for key, e := range t.entries {
		if now.Sub(e.last) >= e.rule.forget {
			delete(t.entries, key)
		}
	}
	target := maxThrottleEntries * 3 / 4
	if len(t.entries) <= target {
		return
	}
	type cand struct {
		key string
		e   *throttleEntry
	}
	var cands []cand
	for key, e := range t.entries {
		if e.wait(now) == 0 {
			cands = append(cands, cand{key, e})
		}
	}
	slices.SortFunc(cands, func(a, b cand) int {
		if a.e.failures != b.e.failures {
			return a.e.failures - b.e.failures
		}
		return a.e.last.Compare(b.e.last)
	})
	for _, c := range cands {
		if len(t.entries) <= target {
			return
		}
		delete(t.entries, c.key)
	}
}
