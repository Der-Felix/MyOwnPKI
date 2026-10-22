package acme

import (
	"bytes"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
)

// lockedBuffer collects the server log of a test (the validator writes
// from its own goroutines).
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// challengeWith orders name, lets answer serve its http-01 token and
// returns the final authorization.
func (c *client) challengeWith(name string, answer func(token, keyAuth string) http.HandlerFunc) *answer {
	c.t.Helper()
	order := c.order(name)
	if order.code != http.StatusCreated {
		c.t.Fatalf("order %s: %d %s", name, order.code, order.body)
	}
	az := strs(order.json["authorizations"])[0]
	a := c.post(az, nil)
	for _, x := range list(a.json["challenges"]) {
		ch, _ := x.(map[string]any)
		if ch["type"] != "http-01" {
			continue
		}
		url, _ := ch["url"].(string)
		tok, _ := ch["token"].(string)
		c.v.chall.mu.Lock()
		c.v.chall.handlers[tok] = answer(tok, tok+"."+c.thumbprint())
		c.v.chall.mu.Unlock()
		c.post(url, map[string]any{})
	}
	res := c.waitAuthz(az, "invalid")
	return res
}

func redirectTo(target string) func(string, string) http.HandlerFunc {
	return func(string, string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target, http.StatusFound) }
	}
}

// TestHTTP01RedirectsStayInTheOrder (security fix after part A): a
// redirect may only lead to an identifier of the same order – an IP
// identifier only to exactly its address – and the dialer checks the
// address policy on every hop.
func TestHTTP01RedirectsStayInTheOrder(t *testing.T) {
	t.Parallel()
	v := newEnv(t, ca.ApprovalOpen)
	c := v.client(t)
	c.register()
	const outside = "redirect to a host outside this order"
	for name, tc := range map[string]struct{ order, target string }{
		"foreign host in the domain": {"r1.homelab.lan", "http://router.homelab.lan/admin"},
		"foreign host elsewhere":     {"r2.homelab.lan", "http://intranet.example.com/"},
		"IP outside the order":       {"r3.homelab.lan", "http://192.168.1.1/"},
		"IP in the range, not in it": {"r4.homelab.lan", "http://192.0.2.11/.well-known/acme-challenge/x"},
		"other IP for an IP order":   {"192.0.2.11", "http://192.0.2.10/"},
		"metadata service":           {"r5.homelab.lan", "http://169.254.169.254/latest/meta-data/"},
	} {
		res := c.challengeWith(tc.order, redirectTo(tc.target))
		body := string(res.body)
		if !strings.Contains(body, outside) || strings.Contains(body, strings.TrimPrefix(tc.target, "http://")) {
			t.Errorf("%s: %s", name, body)
		}
	}

	// The same host on port 443 is fine (RFC 8555 §8.3), and so is another
	// identifier of the same order.
	o := c.order("nas.homelab.lan", "www.homelab.lan")
	for _, az := range strs(o.json["authorizations"]) {
		a := c.post(az, nil)
		id, _ := a.json["identifier"].(map[string]any)
		name, _ := id["value"].(string)
		for _, x := range list(a.json["challenges"]) {
			ch, _ := x.(map[string]any)
			if ch["type"] != "http-01" {
				continue
			}
			url, _ := ch["url"].(string)
			tok, _ := ch["token"].(string)
			keyAuth, path := tok+"."+c.thumbprint(), "/.well-known/acme-challenge/"+tok
			c.v.chall.mu.Lock()
			c.v.chall.handlers[tok] = func(w http.ResponseWriter, r *http.Request) {
				switch {
				case name == "nas.homelab.lan" && r.TLS == nil:
					http.Redirect(w, r, "https://nas.homelab.lan"+path, http.StatusFound) // same host, port 443
				case name == "www.homelab.lan" && r.Host == "www.homelab.lan":
					http.Redirect(w, r, "http://nas.homelab.lan"+path, http.StatusFound) // another identifier of the order
				default:
					_, _ = w.Write([]byte(keyAuth))
				}
			}
			c.v.chall.mu.Unlock()
			c.post(url, map[string]any{})
		}
		c.waitAuthz(az, "valid")
	}
}

// TestHTTP01ReadsNothingBack: what a target answers never reaches the
// client, the audit log or the server log – only status and length.
func TestHTTP01ReadsNothingBack(t *testing.T) {
	t.Parallel()
	v := newEnv(t, ca.ApprovalOpen)
	var logs lockedBuffer
	v.s.log = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	c := v.client(t)
	c.register()
	const secret = "SECRET-ROUTER-PAGE-0815"
	cases := map[string]func(string, string) http.HandlerFunc{
		"page": func(string, string) http.HandlerFunc {
			return func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>" + secret + "</html>")) }
		},
		"error page": func(string, string) http.HandlerFunc {
			return func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("X-Secret", secret)
				http.Error(w, secret, http.StatusUnauthorized)
			}
		},
		"long page": func(string, string) http.HandlerFunc {
			return func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(strings.Repeat(secret, 100))) }
		},
		"redirect with a secret path": redirectTo("http://intranet.homelab.lan/" + secret),
	}
	for name, h := range cases {
		res := c.challengeWith(strings.ReplaceAll(name, " ", "-")+".homelab.lan", h)
		if strings.Contains(string(res.body), secret) || strings.Contains(string(res.body), "SECRET") {
			t.Errorf("%s: the answer reached the client: %s", name, res.body)
		}
		if !strings.Contains(string(res.body), "incorrectResponse") {
			t.Errorf("%s: %s", name, res.body)
		}
	}
	// A service that is not HTTP: its banner stays here too.
	v.addrFor["ssh.homelab.lan"] = netipMust("192.0.2.12")
	res := c.challengeWith("ssh.homelab.lan", func(string, string) http.HandlerFunc { return nil })
	if strings.Contains(string(res.body), "SECRET") || !strings.Contains(string(res.body), "connection") {
		t.Errorf("banner: %s", res.body)
	}

	// An address that does not answer: the client learns the kind, not the address.
	v.addrFor["down.homelab.lan"] = netipMust("192.0.2.99")
	res = c.challengeWith("down.homelab.lan", func(string, string) http.HandlerFunc { return nil })
	if strings.Contains(string(res.body), "192.0.2.99") || !strings.Contains(string(res.body), "could not connect") {
		t.Errorf("unreachable: %s", res.body)
	}

	v.Deliver(t)
	rows, err := v.TenantAudit.Read.QueryContext(t.Context(), `SELECT action || ' ' || target_id || ' ' || details_json FROM audit_entries`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	seen := 0
	for rows.Next() {
		var line string
		if serr := rows.Scan(&line); serr != nil {
			t.Fatal(serr)
		}
		if strings.Contains(line, "acme.challenge.validate") {
			seen++
		}
		if strings.Contains(line, "SECRET") {
			t.Errorf("audit holds the answer: %s", line)
		}
	}
	if rerr := rows.Err(); rerr != nil {
		t.Fatal(rerr)
	}
	if seen < 5 {
		t.Errorf("only %d validation entries in the audit log", seen)
	}
	if strings.Contains(logs.String(), "SECRET") {
		t.Errorf("the server log holds the answer:\n%s", logs.String())
	}
}
