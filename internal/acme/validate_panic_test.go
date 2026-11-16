package acme

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
)

// secretPanic is the text a panic must never carry into the audit log, the
// answer to the client or the server log: it stands for what a target sent.
const secretPanic = "SECRET-PANIC-TEXT-4711"

type hostilePanic struct{ text string }

// failedChallenge orders name, starts the challenge of the given type and
// returns the authorization once it is invalid.
func (c *client) failedChallenge(name, typ string) *answer {
	c.t.Helper()
	order := c.order(name)
	if order.code != http.StatusCreated {
		c.t.Fatalf("order %s: %d %s", name, order.code, order.body)
	}
	az := strs(order.json["authorizations"])[0]
	a := c.post(az, nil)
	for _, x := range list(a.json["challenges"]) {
		ch, _ := x.(map[string]any)
		if ch["type"] != typ {
			continue
		}
		url, _ := ch["url"].(string)
		if r := c.post(url, map[string]any{}); r.code != http.StatusOK {
			c.t.Fatalf("challenge: %d %s", r.code, r.body)
		}
	}
	return c.waitAuthz(az, "invalid")
}

// validationEntries are the audit entries of the validations: action, result
// and details, in order.
func validationEntries(t *testing.T, v *env) []struct{ result, details string } {
	t.Helper()
	v.Deliver(t)
	rows, err := v.TenantAudit.Read.QueryContext(t.Context(), `SELECT result, details_json FROM audit_entries WHERE action = ? ORDER BY seq`, ActionChallenge)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []struct{ result, details string }
	for rows.Next() {
		var e struct{ result, details string }
		if serr := rows.Scan(&e.result, &e.details); serr != nil {
			t.Fatal(serr)
		}
		out = append(out, e)
	}
	if rerr := rows.Err(); rerr != nil {
		t.Fatal(rerr)
	}
	return out
}

// TestValidatorPanicFailsOnlyTheChallenge (decision 10, step 90): a panic in
// the validator – in its own goroutine (the DNS lookup) or in the goroutine
// net/http dials in (the two network edges of SetNetwork) – fails that one
// challenge with serverInternal, writes one audit entry with the panic's type
// and no text, logs the stack at error level, and the server answers the
// next validation as before.
func TestValidatorPanicFailsOnlyTheChallenge(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		typ      string // challenge type
		install  func(v *env)
		wantType string
	}{
		"lookup edge, a string": {"http-01", func(v *env) {
			v.s.SetNetwork(v.s.valid.dial, func(context.Context, string) ([]netip.Addr, error) { panic(secretPanic) })
		}, "string"},
		"dial edge, an error": {"http-01", func(v *env) {
			v.s.SetNetwork(func(context.Context, string, string) (net.Conn, error) {
				panic(&net.OpError{Op: secretPanic})
			}, v.s.valid.lookupIP)
		}, "*net.OpError"},
		"txt lookup, a struct": {"dns-01", func(v *env) {
			v.s.valid.lookupTXT = func(context.Context, string) ([]string, error) { panic(hostilePanic{secretPanic}) }
		}, "acme.hostilePanic"},
		"runtime error": {"dns-01", func(v *env) {
			v.s.valid.lookupTXT = func(context.Context, string) ([]string, error) {
				return []string{nobody().text}, nil // nil pointer dereference
			}
		}, "runtime.errorString"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			v := newEnv(t, ca.ApprovalOpen)
			var logs lockedBuffer
			v.s.log = slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
			v.s.valid.log = v.s.log
			c := v.client(t)
			c.register()

			dial, lookupIP, lookupTXT := v.s.valid.dial, v.s.valid.lookupIP, v.s.valid.lookupTXT
			tc.install(v)
			res := c.failedChallenge("boom.homelab.lan", tc.typ)
			if !strings.Contains(string(res.body), "serverInternal") {
				t.Errorf("the challenge does not fail with serverInternal: %s", res.body)
			}
			if strings.Contains(string(res.body), secretPanic) {
				t.Errorf("the panic text reached the client: %s", res.body)
			}

			entries := validationEntries(t, v)
			if len(entries) != 1 {
				t.Fatalf("%d audit entries for the validation, want 1: %v", len(entries), entries)
			}
			if entries[0].result != "failure" {
				t.Errorf("result %q", entries[0].result)
			}
			var details map[string]any
			if err := json.Unmarshal([]byte(entries[0].details), &details); err != nil {
				t.Fatal(err)
			}
			if got, _ := details["panic"].(string); got != tc.wantType {
				t.Errorf("audit panic type %q, want %q", got, tc.wantType)
			}
			if strings.Contains(entries[0].details, secretPanic) {
				t.Errorf("the panic text is in the audit entry: %s", entries[0].details)
			}

			log := logs.String()
			if strings.Contains(log, secretPanic) {
				t.Errorf("the panic text is in the server log:\n%s", log)
			}
			var found bool
			for line := range strings.SplitSeq(log, "\n") {
				var rec map[string]any
				if json.Unmarshal([]byte(line), &rec) != nil || rec["msg"] != "acme validation panicked" {
					continue
				}
				found = true
				if rec["level"] != "ERROR" {
					t.Errorf("level %v, want ERROR", rec["level"])
				}
				if stack, _ := rec["stack"].(string); !strings.Contains(stack, "goroutine") || !strings.Contains(stack, "validate") {
					t.Errorf("no stack in the log record: %v", rec)
				}
			}
			if !found {
				t.Errorf("no panic record in the log:\n%s", log)
			}

			// The server lives and the next validation works.
			v.s.SetNetwork(dial, lookupIP)
			v.s.valid.lookupTXT = lookupTXT
			o := c.order("fine.homelab.lan")
			if o.code != http.StatusCreated {
				t.Fatalf("order after the panic: %d %s", o.code, o.body)
			}
			c.solve(o, tc.typ)
		})
	}
}

// TestValidatorPanicReleasesTheSlot: a panic gives back the place of the
// check – more panicking checks than parallelChecks in a row must not block
// the next one.
func TestValidatorPanicReleasesTheSlot(t *testing.T) {
	t.Parallel()
	v := newEnv(t, ca.ApprovalOpen)
	c := v.client(t)
	c.register()
	dial, lookupIP := v.s.valid.dial, v.s.valid.lookupIP
	v.s.SetNetwork(dial, func(context.Context, string) ([]netip.Addr, error) { panic("boom") })
	for i := range parallelChecks + 2 {
		c.failedChallenge("boom"+strings.Repeat("x", i)+".homelab.lan", "http-01")
	}
	v.s.SetNetwork(dial, lookupIP)
	c.solve(c.order("fine.homelab.lan"), "http-01")
	if n := len(validationEntries(t, v)); n != parallelChecks+3 {
		t.Errorf("%d validation entries, want %d", n, parallelChecks+3)
	}
}

// nobody returns nil; a function call keeps the vet check for a visible nil
// dereference quiet, because the test wants exactly that panic.
func nobody() *hostilePanic { return nil }
