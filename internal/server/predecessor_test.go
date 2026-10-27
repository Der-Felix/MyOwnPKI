package server

import (
	"log/slog"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

func TestOverdueRevocationRunsAtUnsealOnce(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t)
	clk := clock.NewFake(time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC))
	pass := initialized(t, cfg, clk)
	srv, openErr := Open(t.Context(), Options{Config: cfg, Clock: clk, Log: slog.New(slog.DiscardHandler), Hostname: "pki01", Version: "test"})
	if openErr != nil {
		t.Fatal(openErr)
	}
	t.Cleanup(func() { _ = srv.Shutdown(t.Context()) })
	ctx := t.Context()
	if err := srv.Unseal(ctx, []byte(pass), console); err != nil {
		t.Fatal(err)
	}
	issued, issueErr := srv.engine.Issue(ctx, ca.Request{CA: "issuing", Preset: "server", DNSNames: []string{"unseal-plan.homelab.lan"}, Who: console})
	if issueErr != nil {
		t.Fatal(issueErr)
	}
	if err := srv.engine.PlanRevocation(ctx, ca.PlanRevocationRequest{CertificateID: issued.ID, PlannedAt: clk.Now().Add(time.Hour), Who: console}); err != nil {
		t.Fatal(err)
	}
	if err := srv.ring.Seal(ctx, console); err != nil {
		t.Fatal(err)
	}
	clk.Advance(2 * time.Hour)
	if err := srv.Unseal(ctx, []byte(pass), console); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := srv.engine.ExecuteDueRevocations(ctx); err != nil {
			t.Fatal(err)
		}
		srv.deliver(ctx)
	}
	info, err := srv.engine.Certificate(ctx, console, issued.ID)
	if err != nil || info.Status != ca.CertRevoked || info.RevocationReason != ca.ReasonSuperseded {
		t.Fatalf("after unseal: %+v, %v", info, err)
	}
	var audits int
	if err := srv.ta.Read.QueryRowContext(ctx, `SELECT count(*) FROM audit_entries WHERE action = 'certificate.revoke' AND target_id = ?`, issued.ID).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("final audits %d: %v", audits, err)
	}
	if _, err := pkidb.New(srv.pki.Read).GetRevocationPlan(ctx, issued.ID); err == nil {
		t.Fatal("executed plan remains")
	}
}
