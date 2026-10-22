package acme

import (
	"encoding/base64"
	"io"
	"sync"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/ids"
)

func newID(prefix string, now time.Time, rnd io.Reader) (string, error) {
	return ids.New(prefix, now, rnd)
}

// randomToken is 128 random bits, base64url (challenge tokens, nonces).
func randomToken(rnd io.Reader) (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rnd, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Nonces live in memory (RFC 8555 §6.5): at most maxNonces, each for one
// hour, used once. A restart forgets them; clients answer badNonce with a
// retry.
const (
	maxNonces    = 100_000
	nonceTimeout = time.Hour
)

type nonceStore struct {
	mu    sync.Mutex
	clk   clock.Clock
	rnd   io.Reader
	byVal map[string]time.Time
	order []string // oldest first, for evicting when full
}

func newNonceStore(clk clock.Clock, rnd io.Reader) *nonceStore {
	return &nonceStore{clk: clk, rnd: rnd, byVal: map[string]time.Time{}}
}

// New issues a nonce.
func (n *nonceStore) New() (string, error) {
	v, err := randomToken(n.rnd)
	if err != nil {
		return "", err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	for len(n.byVal) >= maxNonces && len(n.order) > 0 {
		delete(n.byVal, n.order[0])
		n.order = n.order[1:]
	}
	n.byVal[v] = n.clk.Now().Add(nonceTimeout)
	n.order = append(n.order, v)
	if len(n.order) > 2*maxNonces { // compact the slice of used ones now and then
		live := n.order[:0]
		for _, o := range n.order {
			if _, ok := n.byVal[o]; ok {
				live = append(live, o)
			}
		}
		n.order = live
	}
	return v, nil
}

// Use spends a nonce: true once per nonce, while it is fresh.
func (n *nonceStore) Use(v string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	exp, ok := n.byVal[v]
	if !ok {
		return false
	}
	delete(n.byVal, v)
	return n.clk.Now().Before(exp)
}

// limiter counts events per key in fixed windows (PHASE2 step 11).
type limiter struct {
	mu   sync.Mutex
	clk  clock.Clock
	hits map[string]*window
}

type window struct {
	start time.Time
	n     int
}

func newLimiter(clk clock.Clock) *limiter { return &limiter{clk: clk, hits: map[string]*window{}} }

// allow counts one event for key and reports whether it stays within max
// per period; when not, it returns how long until the window resets.
func (l *limiter) allow(key string, max int, period time.Duration) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clk.Now()
	w := l.hits[key]
	if w == nil || now.Sub(w.start) >= period {
		if len(l.hits) > 100_000 { // forget old windows rather than grow without bound
			for k, o := range l.hits {
				if now.Sub(o.start) >= period {
					delete(l.hits, k)
				}
			}
		}
		w = &window{start: now}
		l.hits[key] = w
	}
	if w.n >= max {
		return false, w.start.Add(period).Sub(now)
	}
	w.n++
	return true, 0
}

// peek reports whether key is still within max per period, without
// counting (for limits that count only failures).
func (l *limiter) peek(key string, max int, period time.Duration) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clk.Now()
	w := l.hits[key]
	if w == nil || now.Sub(w.start) >= period || w.n < max {
		return true, 0
	}
	return false, w.start.Add(period).Sub(now)
}
