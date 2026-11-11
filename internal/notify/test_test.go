package notify

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

// stubChannel records what it was sent and fails with err.
type stubChannel struct {
	name string
	err  error
	mu   sync.Mutex
	got  []Digest
}

func (s *stubChannel) Name() string { return s.name }

func (s *stubChannel) Send(_ context.Context, d Digest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.got = append(s.got, d)
	return s.err
}

func (s *stubChannel) sent() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.got)
}

func person(name string, bindings ...authz.Binding) keys.Who {
	for i := range bindings {
		bindings[i].Tenant = store.DefaultTenant
	}
	return keys.Who{
		Actor:     audit.Actor{Type: audit.ActorUser, ID: "usr_" + name, Name: name},
		SourceIP:  "192.0.2.10",
		Principal: &authz.Principal{Kind: authz.KindUser, UserID: "usr_" + name, Username: name, Bindings: bindings},
	}
}

func newTester(t *testing.T, channels ...Channel) (*Tester, *testinstance.Instance) {
	t.Helper()
	inst := testinstance.New(t, testinstance.Options{})
	return &Tester{
		Channels: channels, Server: "pki01", Clock: inst.Clock,
		Audit: inst.TenantAudit.Write, Scope: inst.Engine.Scope, Tenant: store.DefaultTenant,
	}, inst
}

// TestTesterSendsAndAudits: an admin's test goes through every channel at
// once, a failing channel does not stop the other one, and one audit entry
// holds the result per channel – with no address, URL or secret.
func TestTesterSendsAndAudits(t *testing.T) {
	t.Parallel()
	mail := &stubChannel{name: "email"}
	hook := &stubChannel{name: "webhook", err: errors.New("webhook hooks.homelab.lan answered 502 Bad Gateway\r\nsecond line " + strings.Repeat("x", 400))}
	tester, inst := newTester(t, mail, hook)

	results, err := tester.Send(t.Context(), person("alice", authz.Binding{Role: authz.Admin}))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || results[0].Channel != "email" || !results[0].OK || results[1].Channel != "webhook" || results[1].OK {
		t.Fatalf("results: %+v", results)
	}
	if strings.ContainsAny(results[1].Error, "\r\n") || len([]rune(results[1].Error)) > 301 || !strings.HasPrefix(results[1].Error, "webhook hooks.homelab.lan answered 502") {
		t.Errorf("error text not cleaned or clipped: %q", results[1].Error)
	}
	for _, c := range []*stubChannel{mail, hook} {
		if c.sent() != 1 || c.got[0].Server != "pki01" || len(c.got[0].Events) != 1 || c.got[0].Events[0].State != Test {
			t.Errorf("%s got %+v", c.name, c.got)
		}
	}
	if got := testEntries(t, inst); len(got) != 1 || got[0] != "notification.test/failure" {
		t.Fatalf("audit: %v", got)
	}
	var details string
	if err := inst.TenantAudit.Read.QueryRowContext(t.Context(), `SELECT details_json FROM audit_entries WHERE action = 'notification.test'`).Scan(&details); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"email":{"ok":true}`, `"webhook":{"error":"webhook hooks.homelab.lan answered 502`, `"ok":false`} {
		if !strings.Contains(details, want) {
			t.Errorf("audit details lack %q: %s", want, details)
		}
	}

	// All channels fine: the entry says success.
	hook.err = nil
	inst.Clock.Advance(time.Minute)
	if _, err := tester.Send(t.Context(), person("alice", authz.Binding{Role: authz.Admin})); err != nil {
		t.Fatal(err)
	}
	if got := testEntries(t, inst); len(got) != 2 || got[1] != "notification.test/success" {
		t.Errorf("audit: %v", got)
	}
}

// TestTesterRoles: only a tenant-wide admin sends; a refusal is audited as
// denied and sends nothing.
func TestTesterRoles(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name string
		who  keys.Who
		ok   bool
	}{
		{"admin", person("a", authz.Binding{Role: authz.Admin}), true},
		{"operator", person("o", authz.Binding{Role: authz.Operator}), false},
		{"viewer", person("v", authz.Binding{Role: authz.Viewer}), false},
		{"admin of one CA", person("c", authz.Binding{Role: authz.Admin, CA: "issuing"}), false},
		{"nobody", person("n"), false},
		{"nil principal", keys.Who{Actor: audit.Actor{Type: audit.ActorUser, Name: "x"}}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mail := &stubChannel{name: "email"}
			tester, inst := newTester(t, mail)
			_, err := tester.Send(t.Context(), tt.who)
			got := testEntries(t, inst)
			if tt.ok {
				if err != nil || mail.sent() != 1 || len(got) != 1 || got[0] != "notification.test/success" {
					t.Errorf("err %v, sent %d, audit %v", err, mail.sent(), got)
				}
				return
			}
			if !errors.Is(err, authz.ErrDenied) || mail.sent() != 0 {
				t.Errorf("err %v, sent %d", err, mail.sent())
			}
			if tt.name != "nil principal" && (len(got) != 1 || got[0] != "notification.test/denied") {
				t.Errorf("audit: %v", got)
			}
		})
	}
}

// TestTesterNeedsAChannelAndWaits: without a channel there is nothing to
// send (and nothing to audit); a second test within 10 seconds is refused
// with the time to wait.
func TestTesterNeedsAChannelAndWaits(t *testing.T) {
	t.Parallel()
	admin := person("alice", authz.Binding{Role: authz.Admin})
	empty, inst := newTester(t)
	if _, err := empty.Send(t.Context(), admin); !errors.Is(err, ErrNoChannel) {
		t.Errorf("no channel: %v", err)
	}
	if got := testEntries(t, inst); len(got) != 0 {
		t.Errorf("audit without a send: %v", got)
	}

	mail := &stubChannel{name: "email"}
	tester, inst := newTester(t, mail)
	if _, err := tester.Send(t.Context(), admin); err != nil {
		t.Fatal(err)
	}
	inst.Clock.Advance(4 * time.Second)
	_, err := tester.Send(t.Context(), admin)
	var wait *WaitError
	if !errors.As(err, &wait) || wait.RetryAfter != 6*time.Second || mail.sent() != 1 {
		t.Fatalf("second test: %v (sent %d)", err, mail.sent())
	}
	inst.Clock.Advance(6 * time.Second)
	if _, err := tester.Send(t.Context(), admin); err != nil || mail.sent() != 2 {
		t.Errorf("third test: %v (sent %d)", err, mail.sent())
	}
}

// testEntries are the "notification.*" entries of the tenant audit log (the
// instance's own set-up entries are not of interest).
func testEntries(t *testing.T, inst *testinstance.Instance) []string {
	t.Helper()
	var out []string
	for _, e := range testinstance.Audit(t, inst.TenantAudit) {
		if strings.HasPrefix(e, "notification.") {
			out = append(out, e)
		}
	}
	return out
}
