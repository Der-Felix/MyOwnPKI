// Command agentui starts a loopback-only UI fixture with one reported agent.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/agents"
	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/config"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/server"
	"github.com/Der-Felix/MyOwnPKI/internal/setup"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

var console = keys.Who{Actor: audit.Actor{Type: audit.ActorUser, Name: "console:agent-ui"}, Principal: authz.Console()}

type acceptChecker struct{}

func (acceptChecker) Check(context.Context, string, string, string, string) error { return nil }

func demoPassphrase(path string) ([]byte, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- the fixture created by this command
	if err != nil {
		return nil, err
	}
	defer clear(data)
	for line := range strings.SplitSeq(string(data), "\n") {
		if p, ok := strings.CutPrefix(strings.TrimRight(line, "\r"), "unseal passphrase: "); ok {
			return []byte(p), nil
		}
	}
	return nil, errors.New("no unseal passphrase in the demo fixture")
}

func reportFixture(ctx context.Context, svc *agents.Service) error {
	token, _, err := svc.CreateJoinToken(ctx, console, "UI fixture", []string{"proxy1.homelab.lan"}, 0)
	if err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return err
	}
	enrolled, err := svc.Enroll(ctx, agents.EnrollInput{Hostname: "proxy1.homelab.lan", Token: token, Method: agents.MethodWebroot,
		OS: "linux", Arch: "amd64", Version: "0.3.0-ui-fixture", SourceIP: "192.0.2.10", CSRDER: csr})
	if err != nil {
		return err
	}
	status, err := svc.EnrollStatus(ctx, agents.StatusInput{ID: enrolled.ID, Handle: enrolled.Handle, CheckReady: true, SourceIP: "192.0.2.10"})
	if err != nil {
		return err
	}
	if status.AgentID == "" {
		return errors.New("the fixture agent was not admitted")
	}
	now := clock.System{}.Now()
	caller := &agents.Caller{Agent: pkidb.Agent{ID: status.AgentID}, Who: console}
	return svc.Report(ctx, caller, agents.ReportInput{Version: "0.3.0-ui-fixture", OS: "linux", Arch: "amd64", Deployments: []agents.DeploymentReport{
		{Name: "proxy", Profile: "nginx", Names: []string{"proxy1.homelab.lan", "app.homelab.lan"}, Challenge: "webroot",
			State: "deployed", Serial: "0123456789ABCDEF", NotAfter: now.Add(60 * 24 * time.Hour).Format(time.RFC3339),
			DeployedAt: now.Add(-time.Hour).Format(time.RFC3339), Fingerprint: strings.Repeat("01", 32)},
		{Name: "broken", Profile: "file", Names: []string{"legacy.homelab.lan"}, Challenge: "webroot",
			State: "failed", LastError: "nginx configuration test failed (UI fixture)"},
	}})
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("agentui", flag.ContinueOnError)
	flags.SetOutput(stderr)
	listen := flags.String("listen", "127.0.0.1:9443", "loopback address for the admin UI")
	dataDir := flags.String("data-dir", "", "fixture directory (default: a new temporary directory)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	addr, err := netip.ParseAddrPort(*listen)
	if err != nil || !addr.Addr().IsLoopback() || !addr.Addr().Is4() {
		return errors.New("listen must be an IPv4 loopback address and port")
	}
	if *dataDir == "" {
		*dataDir, err = os.MkdirTemp("", "myownpki-agent-ui-")
		if err != nil {
			return err
		}
	}
	cfg := config.Default()
	cfg.DataDir = *dataDir
	cfg.Admin.Listen = *listen
	cfg.Public.Listen = ""
	cfg.ACME.BaseURL = ""
	cfg.Agent.BaseURL = "https://pki.homelab.lan:8444"
	cfg.Agent.Listen = "127.0.0.1:0"
	cfg.Agent.TLSIssuer = "issuing"
	cfg.Agent.CA = "agent-ca"
	clk := clock.System{}
	result, err := setup.Run(ctx, setup.Options{Config: cfg, Mode: setup.Demo, WithCA: true, CABaseURL: "http://pki.homelab.lan",
		Hostname: "pki01", Clock: clk, Who: console}, setup.NewLineInput(strings.NewReader(""), io.Discard))
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(stderr, nil))
	srv, err := server.Open(ctx, server.Options{Config: cfg, Log: log, Clock: clk, Hostname: "pki01", Version: "agent-ui-fixture"})
	if err != nil {
		return err
	}
	passphrase, err := demoPassphrase(result.DemoSecretsFile)
	if err != nil {
		return err
	}
	defer clear(passphrase)
	if unsealErr := srv.Unseal(ctx, passphrase, console); unsealErr != nil {
		return unsealErr
	}
	if _, createErr := srv.Agents().Engine.CreateIntermediate(ctx, ca.IntermediateRequest{
		CASettings: ca.CASettings{Name: "agent-ca", BaseURL: "http://pki.homelab.lan"}, Parent: "root",
		Subject: ca.Subject{CommonName: "Agent CA"}, EKULimit: []string{"clientAuth"}, Who: console,
	}); createErr != nil {
		return createErr
	}
	issuing := "issuing"
	if _, domainErr := srv.Agents().Engine.CreateDomain(ctx, ca.DomainRequest{Name: "homelab.lan",
		DomainSettings: ca.DomainSettings{CA: &issuing}, Who: console}); domainErr != nil {
		return domainErr
	}
	svc := srv.Agents()
	svc.Checker = acceptChecker{}
	if reportErr := reportFixture(ctx, svc); reportErr != nil {
		return reportErr
	}
	if listenErr := srv.Listen(ctx); listenErr != nil {
		return listenErr
	}
	_, _ = fmt.Fprintf(stdout, "Admin UI: https://%s/\n", srv.AdminAddr())
	_, _ = fmt.Fprintf(stdout, "Credentials fixture: %s\n", result.DemoSecretsFile)
	_, _ = fmt.Fprintln(stdout, "Agent: proxy1.homelab.lan (deployments: proxy=deployed, broken=failed)")
	return srv.Serve(ctx)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := 0
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil && !errors.Is(err, context.Canceled) {
		_, _ = fmt.Fprintln(os.Stderr, "agentui:", err)
		code = 1
	}
	stop()
	if code != 0 {
		os.Exit(code)
	}
}
