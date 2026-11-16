package acme

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// TestExpireStale: the job marks what ran out – a pending order after its 24
// hours, a passed authorization after its seven days – and leaves the rest.
func TestExpireStale(t *testing.T) {
	t.Parallel()
	v := newEnv(t, ca.ApprovalOpen)
	c := v.client(t)
	c.register()
	q := pkidb.New(v.Engine.PKI)
	id := func(url string) string { return url[strings.LastIndex(url, "/")+1:] }

	passed := c.readyOrder("passed.homelab.lan") // its authorization is valid for 7 days
	stale := c.order("stale.homelab.lan")
	staleAuthz := id(strs(stale.json["authorizations"])[0])
	passedAuthz := id(strs(passed.json["authorizations"])[0])

	v.expire(25*time.Hour, c)
	fresh := c.order("fresh.homelab.lan")
	if err := v.s.ExpireStale(t.Context()); err != nil {
		t.Fatal(err)
	}
	status := func(order *answer) string {
		o, err := q.GetACMEOrder(t.Context(), id(order.header.Get("Location")))
		if err != nil {
			t.Fatal(err)
		}
		return o.Status + " " + o.Error.String
	}
	if got := status(stale); !strings.HasPrefix(got, "invalid ") || !strings.Contains(got, "the order expired") {
		t.Errorf("stale order: %s", got)
	}
	if got := status(passed); !strings.HasPrefix(got, "invalid ") {
		t.Errorf("order of a passed authorization, its own 24 hours are over: %s", got)
	}
	if got := status(fresh); got != "pending " {
		t.Errorf("fresh order: %q", got)
	}
	if a, err := q.GetACMEAuthz(t.Context(), staleAuthz); err != nil || a.Status != "expired" {
		t.Errorf("stale authorization: %v %+v", err, a)
	}
	if a, err := q.GetACMEAuthz(t.Context(), passedAuthz); err != nil || a.Status != "valid" {
		t.Errorf("a valid authorization lasts seven days: %v %+v", err, a)
	}
	v.expire(ValidAuthzLifetime, c)
	if err := v.s.ExpireStale(t.Context()); err != nil {
		t.Fatal(err)
	}
	if a, err := q.GetACMEAuthz(t.Context(), passedAuthz); err != nil || a.Status != "expired" {
		t.Errorf("passed authorization after seven days: %v %+v", err, a)
	}
}

// TestDNS01Failures: what the client learns when the TXT lookup fails – the
// kind of the failure, never the resolver's address or the records found.
func TestDNS01Failures(t *testing.T) {
	t.Parallel()
	v := newEnv(t, ca.ApprovalOpen)
	c := v.client(t)
	c.register()
	for name, tc := range map[string]struct {
		lookup func(context.Context, string) ([]string, error)
		want   []string
		never  string
	}{
		"no record": {func(_ context.Context, n string) ([]string, error) {
			return nil, &net.DNSError{Err: "no such host", Name: n, IsNotFound: true}
		}, []string{"dns", "has no TXT record"}, ""},
		"resolver down": {func(context.Context, string) ([]string, error) {
			return nil, &net.OpError{Op: "read", Net: "udp", Addr: &net.UDPAddr{IP: net.ParseIP("10.9.8.7"), Port: 53}, Err: errors.New("refused")}
		}, []string{"dns", "the DNS lookup failed"}, "10.9.8.7"},
		"timeout": {func(context.Context, string) ([]string, error) {
			return nil, &net.DNSError{Err: "i/o timeout", Server: "10.9.8.7:53", IsTimeout: true}
		}, []string{"dns", "the DNS lookup timed out"}, "10.9.8.7"},
		"other records": {func(context.Context, string) ([]string, error) {
			return []string{"v=spf1 -all", "SECRET-TXT-RECORD"}, nil
		}, []string{"incorrectResponse", "found 2 record(s)"}, "SECRET-TXT-RECORD"},
		"no records": {func(context.Context, string) ([]string, error) { return nil, nil }, []string{"incorrectResponse", "found 0 record(s)"}, ""},
	} {
		v.s.valid.lookupTXT = tc.lookup
		res := c.failedChallenge(strings.ReplaceAll(name, " ", "-")+".homelab.lan", "dns-01")
		body := string(res.body)
		for _, w := range tc.want {
			if !strings.Contains(body, w) {
				t.Errorf("%s: %q missing in %s", name, w, body)
			}
		}
		if tc.never != "" && strings.Contains(body, tc.never) {
			t.Errorf("%s: %q reached the client: %s", name, tc.never, body)
		}
	}
}

// TestValidationErrorText: the text of a validation error is the type and the
// detail (it is what the log shows).
func TestValidationErrorText(t *testing.T) {
	t.Parallel()
	if got := vfail("connection", "port %d", 8080).Error(); got != "connection: port 8080" {
		t.Errorf("%q", got)
	}
}
