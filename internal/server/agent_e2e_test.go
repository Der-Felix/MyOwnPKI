package server

import (
	"context"
	"encoding/pem"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/agent"
)

// newTestAgent writes an agent.yaml in webroot mode and returns the agent,
// connected to the test server's agent listener.
func (e *agentEnv) newTestAgent(t *testing.T) (*agent.Agent, string) {
	t.Helper()
	dir := t.TempDir()
	www := filepath.Join(dir, "www")
	if err := os.MkdirAll(www, 0o750); err != nil { // the web server's directory exists before the agent
		t.Fatal(err)
	}
	e.webroot = www
	bundle := filepath.Join(dir, "root.pem")
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.rootDER})
	if err := os.WriteFile(bundle, pemData, 0o600); err != nil {
		t.Fatal(err)
	}
	q := func(p string) string { return `"` + strings.ReplaceAll(p, `\`, `\\`) + `"` }
	cfg, err := agent.ParseConfig("agent.yaml", []byte("server: https://pki.homelab.lan:8444\nca_bundle: "+q(bundle)+
		"\nhostname: proxy1.homelab.lan\nstate_dir: "+q(filepath.Join(dir, "state"))+
		"\nenrollment:\n  challenge: webroot\n  webroot: "+q(www)+"\npaths: ["+q(www)+"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	a, err := agent.New(cfg, slog.New(slog.DiscardHandler), "0.3.0-test")
	if err != nil {
		t.Fatal(err)
	}
	var d net.Dialer
	a.SetDial(func(ctx context.Context, network, _ string) (net.Conn, error) {
		return d.DialContext(ctx, network, e.srv.AgentAddr())
	})
	return a, www
}

// TestAgentEndToEnd (blocks B): the real agent against the real server, in
// webroot mode – enroll with a join token (verified), the check file is gone
// afterwards; the service renews the agent certificate at 2/3 with a new
// key; after the certificate expired it enrolls again with the key of the
// last one and stays the same agent.
func TestAgentEndToEnd(t *testing.T) {
	t.Parallel()
	e := newAgentEnv(t)
	ctx := t.Context()
	a, www := e.newTestAgent(t)
	token, _, err := e.srv.Agents().CreateJoinToken(ctx, console, "proxy1", []string{"proxy1.homelab.lan"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	res, err := a.Enroll(ctx, token)
	if err != nil || !res.Admitted() {
		t.Fatalf("enroll: %+v %v", res, err)
	}
	id := res.AgentID
	if left, _ := filepath.Glob(filepath.Join(www, ".well-known", "acme-challenge", "*")); len(left) != 0 {
		t.Errorf("check files left in the webroot: %v", left)
	}
	if _, err := a.Enroll(ctx, ""); err == nil || !strings.Contains(err.Error(), "enrolled") {
		t.Errorf("enroll twice: %v", err)
	}
	first := a.Identity().Leaf

	// Renewal: the clock at 6 of 7 days; Run renews, then sleeps – the
	// sleep ends the test run.
	runOnce(t, a, func() time.Time {
		if a.Identity().Leaf.SerialNumber.Cmp(first.SerialNumber) == 0 {
			return first.NotBefore.Add(6 * 24 * time.Hour)
		}
		return time.Now().UTC()
	})
	second := a.Identity().Leaf
	if second.SerialNumber.Cmp(first.SerialNumber) == 0 || string(second.RawSubjectPublicKeyInfo) == string(first.RawSubjectPublicKeyInfo) {
		t.Fatal("not renewed with a new key")
	}
	if c, err := e.srv.Agents().Identify(ctx, second, ""); err != nil || c.Agent.ID != id {
		t.Fatalf("the renewed certificate: %v", err)
	}

	// Expired: Run enrolls again with the key of the last certificate –
	// no token, a passed check – and it is the same agent.
	runOnce(t, a, func() time.Time {
		if a.Identity().Leaf.SerialNumber.Cmp(second.SerialNumber) == 0 {
			return second.NotAfter.Add(time.Hour)
		}
		return time.Now().UTC()
	})
	third := a.Identity().Leaf
	if third.SerialNumber.Cmp(second.SerialNumber) == 0 || string(third.RawSubjectPublicKeyInfo) != string(second.RawSubjectPublicKeyInfo) {
		t.Fatal("not enrolled again with the last key")
	}
	if c, err := e.srv.Agents().Identify(ctx, third, ""); err != nil || c.Agent.ID != id {
		t.Fatalf("enrolled again as another agent: %v", err)
	}
	if list, _ := e.srv.Agents().ListAgents(ctx, console); len(list) != 1 {
		t.Errorf("%d agents, want 1", len(list))
	}
}

// runOnce runs the agent's service until its first sleep.
func runOnce(t *testing.T, a *agent.Agent, now func() time.Time) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	var slept atomic.Bool
	a.Now = now
	a.Sleep = func(context.Context, time.Duration) error {
		slept.Store(true)
		cancel()
		return context.Canceled
	}
	if err := a.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if !slept.Load() {
		t.Fatal("Run ended without sleeping")
	}
}
