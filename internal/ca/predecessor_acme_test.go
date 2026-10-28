package ca

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/predecessor"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

func acmeTestAccount(t *testing.T, ctx context.Context, v *env, id string) {
	t.Helper()
	stamp := v.clk.Now().Format(audit.TimeFormat)
	if err := pkidb.New(v.pki).InsertACMEAccount(ctx, pkidb.InsertACMEAccountParams{
		ID: id, KeyThumbprint: id, Jwk: "{}", Status: "valid", Contact: "[]", CreatedAt: stamp, UpdatedAt: stamp,
	}); err != nil {
		t.Fatal(err)
	}
}

func acmeTestOrder(t *testing.T, ctx context.Context, v *env, account string, cert *Issued, names ...string) {
	t.Helper()
	identifiers, _ := json.Marshal([]map[string]string{{"type": "dns", "value": names[0]}})
	if len(names) > 1 {
		identifiers, _ = json.Marshal([]map[string]string{{"type": "dns", "value": names[0]}, {"type": "dns", "value": names[1]}})
	}
	stamp := v.clk.Now().Format(audit.TimeFormat)
	q := pkidb.New(v.pki)
	orderID := "ord-" + cert.ID
	if err := q.InsertACMEOrder(ctx, pkidb.InsertACMEOrderParams{
		ID: orderID, AccountID: account, Status: "processing", Identifiers: string(identifiers), ExpiresAt: v.clk.Now().Add(time.Hour).Format(dbTime),
		CreatedAt: stamp, UpdatedAt: stamp,
	}); err != nil {
		t.Fatal(err)
	}
	n, err := q.SetACMEOrderValid(ctx, pkidb.SetACMEOrderValidParams{CertificateID: sql.NullString{String: cert.ID, Valid: true}, UpdatedAt: stamp, ID: orderID})
	if err != nil || n != 1 {
		t.Fatalf("link order %d: %v", n, err)
	}
}

func TestACMEPredecessorExactAccountAndNames(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.chain(t, caOpts{})
	ctx := t.Context()
	acmeTestAccount(t, ctx, v, "acct-good")
	acmeTestAccount(t, ctx, v, "acct-other")
	old := predecessorCertificate(t, v, "www.homelab.lan")
	otherName := predecessorCertificate(t, v, "other.homelab.lan")
	otherAccount := predecessorCertificate(t, v, "www.homelab.lan")
	successor := predecessorCertificate(t, v, "www.homelab.lan")
	acmeTestOrder(t, ctx, v, "acct-good", old, "WWW.homelab.lan")
	acmeTestOrder(t, ctx, v, "acct-good", otherName, "other.homelab.lan")
	acmeTestOrder(t, ctx, v, "acct-other", otherAccount, "www.homelab.lan")
	acmeTestOrder(t, ctx, v, "acct-good", successor, "www.homelab.lan")

	policy := predecessor.Policy{Choice: predecessor.After, Days: 3}
	names := map[string]struct{}{"dns:www.homelab.lan": {}}
	if err := v.e.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		_, ambiguous, err := v.e.ApplyACMEPredecessor(ctx, q, tx, "acct-good", successor.ID, names, policy, tester)
		if len(ambiguous) != 0 {
			t.Fatalf("ambiguous %v", ambiguous)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := pkidb.New(v.pki).GetRevocationPlan(ctx, old.ID); err != nil {
		t.Fatalf("exact predecessor not planned: %v", err)
	}
	for _, id := range []string{otherName.ID, otherAccount.ID} {
		if _, err := pkidb.New(v.pki).GetRevocationPlan(ctx, id); err == nil {
			t.Fatalf("unrelated certificate %s planned", id)
		}
	}

	multiOld := v.issue(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"a.homelab.lan", "b.homelab.lan"}, Who: tester})
	v.clk.Advance(time.Second)
	multiNew := v.issue(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"a.homelab.lan", "b.homelab.lan"}, Who: tester})
	acmeTestOrder(t, ctx, v, "acct-good", multiOld, "b.homelab.lan", "a.homelab.lan")
	acmeTestOrder(t, ctx, v, "acct-good", multiNew, "a.homelab.lan", "b.homelab.lan")
	multiNames := map[string]struct{}{"dns:a.homelab.lan": {}, "dns:b.homelab.lan": {}}
	if err := v.e.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		_, _, err := v.e.ApplyACMEPredecessor(ctx, q, tx, "acct-good", multiNew.ID, multiNames, policy, tester)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := pkidb.New(v.pki).GetRevocationPlan(ctx, multiOld.ID); err != nil {
		t.Fatalf("normalized multi-name predecessor not planned: %v", err)
	}
}
