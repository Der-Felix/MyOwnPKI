package agent

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestGuardNoticeNamesTheRecordsAndNothingElse(t *testing.T) {
	t.Parallel()
	p := newRecordingProvider()
	g := testGuard(t.Context(), p, nil)
	if n := g.Notice(); n != "" {
		t.Fatalf("notice without a failure: %q", n)
	}
	p.cleanErr = fmt.Errorf("server answered: bad key %s", sentinelSecret)
	if err := g.Present("homelab.lan", "tok", "ka"); err != nil {
		t.Fatal(err)
	}
	if err := g.CleanUp("homelab.lan", "tok", "ka"); err == nil {
		t.Fatal("the failure was hidden")
	}
	n := g.Notice()
	if !strings.Contains(n, "a TXT record may remain at _acme-challenge.homelab.lan") || strings.Contains(n, "server answered") || strings.Contains(n, sentinelSecret) {
		t.Fatalf("notice %q", n)
	}
	// The same name twice is named once.
	g.warn("HomeLab.lan.", errors.New("again"))
	if got := g.Notice(); got != n {
		t.Fatalf("notice %q, want %q", got, n)
	}
	// Many names are cut off, with a count.
	for _, d := range []string{"a.lan", "b.lan", "c.lan", "d.lan"} {
		g.warn(d, errors.New("x"))
	}
	if got := g.Notice(); !strings.Contains(got, "and 2 more") || strings.Count(got, "_acme-challenge.") != 3 {
		t.Fatalf("notice %q", got)
	}
}

func TestWithDNSNotice(t *testing.T) {
	t.Parallel()
	p := newRecordingProvider()
	p.cleanErr = errors.New("boom")
	g := testGuard(t.Context(), p, nil)
	m := &Material{}
	if got, err := withDNSNotice(m, nil, g); got != m || err != nil || m.Notice != "" {
		t.Fatalf("no failure: %+v %v", got, err)
	}
	if err := g.Present("homelab.lan", "tok", "ka"); err != nil {
		t.Fatal(err)
	}
	_ = g.CleanUp("homelab.lan", "tok", "ka")
	if _, err := withDNSNotice(m, nil, nil); err != nil || m.Notice != "" {
		t.Fatalf("no guard: %q %v", m.Notice, err)
	}
	if _, err := withDNSNotice(m, nil, g); err != nil || !strings.Contains(m.Notice, "_acme-challenge.homelab.lan") {
		t.Fatalf("success: %q %v", m.Notice, err)
	}
	cause := errors.New("ACME issuance: the order failed")
	_, err := withDNSNotice(nil, cause, g)
	if !errors.Is(err, cause) || !strings.HasPrefix(err.Error(), "dns-01 cleanup failed: a TXT record may remain") || !strings.HasSuffix(err.Error(), cause.Error()) {
		t.Fatalf("failure: %v", err)
	}
}
