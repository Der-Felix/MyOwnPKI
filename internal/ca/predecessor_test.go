package ca

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/predecessor"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

func predecessorCertificate(t *testing.T, v *env, name string) *Issued {
	t.Helper()
	v.clk.Advance(time.Second)
	return v.issue(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{name}, Who: tester})
}

func TestRenewalPredecessorChoicesAndFilter(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.chain(t, caOpts{})
	ctx := t.Context()

	delayed := predecessorCertificate(t, v, "delayed.homelab.lan")
	renewed, err := v.e.RenewCertificate(ctx, RenewCertRequest{ID: delayed.ID, Who: tester})
	if err != nil {
		t.Fatal(err)
	}
	if renewed.PlannedAt == nil || !renewed.PlannedAt.Equal(v.clk.Now().Add(7*24*time.Hour)) {
		t.Fatalf("default plan %v", renewed.PlannedAt)
	}
	info, err := v.e.Certificate(ctx, tester, delayed.ID)
	if err != nil || info.RevocationPlannedAt == nil {
		t.Fatalf("planned metadata: %+v, %v", info, err)
	}
	page, err := v.e.Certificates(ctx, tester, CertificateFilter{Status: "planned"})
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != delayed.ID {
		t.Fatalf("planned filter: %+v, %v", page, err)
	}
	if n, dueErr := v.e.RevocationsDue(ctx, tester); dueErr != nil || n != 1 {
		t.Fatalf("due count %d: %v", n, dueErr)
	}

	// A later replacement neither duplicates nor moves the existing plan.
	plannedAt := *info.RevocationPlannedAt
	v.clk.Advance(24 * time.Hour)
	if _, renewErr := v.e.RenewCertificate(ctx, RenewCertRequest{ID: delayed.ID, Who: tester}); renewErr != nil {
		t.Fatal(renewErr)
	}
	plan, err := pkidb.New(v.pki).GetRevocationPlan(ctx, delayed.ID)
	if err != nil || parseDBTime(plan.PlannedAt) != plannedAt {
		t.Fatalf("plan moved: %+v, %v", plan, err)
	}

	immediate := predecessorCertificate(t, v, "immediate.homelab.lan")
	now := predecessor.Policy{Choice: predecessor.Now}
	if _, immediateErr := v.e.RenewCertificate(ctx, RenewCertRequest{ID: immediate.ID, Predecessor: &now, Who: tester}); immediateErr != nil {
		t.Fatal(immediateErr)
	}
	info, err = v.e.Certificate(ctx, tester, immediate.ID)
	if err != nil || info.Status != CertRevoked || info.RevocationReason != ReasonSuperseded {
		t.Fatalf("immediate: %+v, %v", info, err)
	}

	never := predecessorCertificate(t, v, "never.homelab.lan")
	no := predecessor.Policy{Choice: predecessor.Never}
	if _, neverErr := v.e.RenewCertificate(ctx, RenewCertRequest{ID: never.ID, Predecessor: &no, Who: tester}); neverErr != nil {
		t.Fatal(neverErr)
	}
	info, err = v.e.Certificate(ctx, tester, never.ID)
	if err != nil || info.Status != CertValid || info.RevocationPlannedAt != nil {
		t.Fatalf("never: %+v, %v", info, err)
	}
}

func TestPlannedRevocationCancelRevokeNowAndRestartCatchup(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.chain(t, caOpts{})
	ctx := t.Context()
	canceled := predecessorCertificate(t, v, "cancel.homelab.lan")
	at := v.clk.Now().Add(24 * time.Hour)
	if err := v.e.PlanRevocation(ctx, PlanRevocationRequest{CertificateID: canceled.ID, PlannedAt: at, Who: tester}); err != nil {
		t.Fatal(err)
	}
	if err := v.e.CancelRevocationPlan(ctx, tester, canceled.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := pkidb.New(v.pki).GetRevocationPlan(ctx, canceled.ID); err == nil {
		t.Fatal("cancellation left a plan")
	}
	if err := v.e.PlanRevocation(ctx, PlanRevocationRequest{CertificateID: canceled.ID, PlannedAt: at, Who: tester}); err != nil {
		t.Fatal(err)
	}
	if _, err := v.e.Revoke(ctx, RevokeRequest{CertificateID: canceled.ID, Reason: ReasonSuperseded, Who: tester}); err != nil {
		t.Fatal(err)
	}
	if _, err := pkidb.New(v.pki).GetRevocationPlan(ctx, canceled.ID); err == nil {
		t.Fatal("revoke-now left a plan")
	}

	due := predecessorCertificate(t, v, "due.homelab.lan")
	if err := v.e.PlanRevocation(ctx, PlanRevocationRequest{CertificateID: due.ID, PlannedAt: at, Who: tester}); err != nil {
		t.Fatal(err)
	}
	v.clk.Advance(48 * time.Hour)
	restarted := *v.e
	for range 2 {
		if err := restarted.ExecuteDueRevocations(ctx); err != nil {
			t.Fatal(err)
		}
	}
	info, err := restarted.Certificate(ctx, tester, due.ID)
	if err != nil || info.Status != CertRevoked || info.RevocationReason != ReasonSuperseded {
		t.Fatalf("catch-up: %+v, %v", info, err)
	}
	der, _, err := restarted.LatestCRL(ctx, tester, info.CAID)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range crl.RevokedCertificateEntries {
		if SerialHex(entry.SerialNumber) == due.SerialHex && entry.ReasonCode == 4 {
			found = true
		}
	}
	if !found {
		t.Error("due certificate absent from CRL with superseded reason")
	}
	v.deliver()
	var audits int
	if err := v.audit.QueryRowContext(ctx, `SELECT count(*) FROM audit_entries WHERE action = 'certificate.revoke' AND target_id = ?`, due.ID).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("revocation audits %d: %v", audits, err)
	}
	for action, want := range map[string]int{ActionPlanRevocation: 3, ActionCancelRevocation: 1} {
		var count int
		if err := v.audit.QueryRowContext(ctx, `SELECT count(*) FROM audit_entries WHERE action = ?`, action).Scan(&count); err != nil || count != want {
			t.Errorf("%s audits %d, want %d: %v", action, count, want, err)
		}
	}
}

func TestRenewalLegacyPointerTriState(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.chain(t, caOpts{})
	ctx := t.Context()
	falseValue := false
	never := predecessorCertificate(t, v, "legacy-false.homelab.lan")
	if _, err := v.e.RenewCertificate(ctx, RenewCertRequest{ID: never.ID, RevokePrevious: &falseValue, Who: tester}); err != nil {
		t.Fatal(err)
	}
	info, err := v.e.Certificate(ctx, tester, never.ID)
	if err != nil || info.Status != CertValid || info.RevocationPlannedAt != nil {
		t.Fatalf("explicit false: %+v, %v", info, err)
	}

	trueValue := true
	now := predecessorCertificate(t, v, "legacy-true.homelab.lan")
	if _, trueErr := v.e.RenewCertificate(ctx, RenewCertRequest{ID: now.ID, RevokePrevious: &trueValue, Who: tester}); trueErr != nil {
		t.Fatal(trueErr)
	}
	info, err = v.e.Certificate(ctx, tester, now.ID)
	if err != nil || info.Status != CertRevoked || info.RevocationReason != ReasonSuperseded {
		t.Fatalf("explicit true: %+v, %v", info, err)
	}

	omitted := predecessorCertificate(t, v, "legacy-omitted.homelab.lan")
	if _, omittedErr := v.e.RenewCertificate(ctx, RenewCertRequest{ID: omitted.ID, Who: tester}); omittedErr != nil {
		t.Fatal(omittedErr)
	}
	info, err = v.e.Certificate(ctx, tester, omitted.ID)
	if err != nil || info.RevocationPlannedAt == nil || !info.RevocationPlannedAt.Equal(v.clk.Now().Add(7*24*time.Hour)) {
		t.Fatalf("omitted pointer: %+v, %v", info, err)
	}

	both := predecessorCertificate(t, v, "legacy-both.homelab.lan")
	after := predecessor.Policy{Choice: predecessor.After, Days: 2}
	if _, bothErr := v.e.RenewCertificate(ctx, RenewCertRequest{ID: both.ID, RevokePrevious: &falseValue, Predecessor: &after, Who: tester}); bothErr != nil {
		t.Fatal(bothErr)
	}
	info, err = v.e.Certificate(ctx, tester, both.ID)
	if err != nil || info.RevocationPlannedAt == nil || !info.RevocationPlannedAt.Equal(v.clk.Now().Add(48*time.Hour)) {
		t.Fatalf("predecessor did not win: %+v, %v", info, err)
	}
}

func TestPlanRevocationBounds(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.chain(t, caOpts{})
	cert := predecessorCertificate(t, v, "bounds.homelab.lan")
	for _, days := range []int{-1, 0, 31} {
		at := v.clk.Now().Add(time.Duration(days) * 24 * time.Hour)
		if err := v.e.PlanRevocation(t.Context(), PlanRevocationRequest{CertificateID: cert.ID, PlannedAt: at, Who: tester}); err == nil {
			t.Errorf("%d days accepted", days)
		}
	}
	if _, err := pkidb.New(v.pki).GetRevocationPlan(t.Context(), cert.ID); err == nil {
		t.Fatal("invalid bound created a plan")
	}
}
