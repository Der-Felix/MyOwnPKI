package ca

import (
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
)

// reportFixture issues one certificate per source class (docs/PHASE3.md D6)
// and the certificates the reports must leave out.
type reportFixture struct {
	ui, acme, agent, revoked, agentIdentity, imported *Issued
}

func (v *env) exec(t *testing.T, query string, args ...any) {
	t.Helper()
	if _, err := v.pki.ExecContext(t.Context(), query, args...); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
}

func newReportFixture(t *testing.T, v *env) reportFixture {
	t.Helper()
	var f reportFixture
	f.ui = v.issue(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"ui.homelab.lan"}})
	f.acme = v.issue(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"acme.homelab.lan"}})
	f.agent = v.issue(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"agent.homelab.lan"}})
	f.revoked = v.issue(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"revoked.homelab.lan"}})
	f.imported = v.issue(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"imported.homelab.lan"}})
	// An agent identity certificate: preset client, requested by the agent.
	f.agentIdentity = v.issue(t, Request{CA: "issuing", Preset: "client", Subject: Subject{CommonName: "host.homelab.lan"},
		Who: keys.Who{Actor: audit.Actor{Type: audit.ActorSystem, ID: "agt-1", Name: "agent"}, Principal: authz.Console()}})

	now := v.clk.Now().Format(audit.TimeFormat)
	v.exec(t, `INSERT INTO agents (id, hostname, status, enrollment_mode, proof, os, arch, agent_version, created_at, approved_at, approved_by, updated_at)
		VALUES ('agt-1', 'host.homelab.lan', 'active', 'manual', '{}', 'linux', 'amd64', '0.3.8', ?1, ?1, 'admin', ?1)`, now)
	for _, a := range []struct{ id, agent any }{{"acc-plain", nil}, {"acc-agent", "agt-1"}} {
		v.exec(t, `INSERT INTO acme_accounts (id, key_thumbprint, jwk, status, contact, agent_id, created_at, created_ip, updated_at)
			VALUES (?1, ?1, '{}', 'valid', '[]', ?2, ?3, '192.0.2.1', ?3)`, a.id, a.agent, now)
	}
	for _, o := range []struct {
		id, account string
		cert        *Issued
	}{{"ord-plain", "acc-plain", f.acme}, {"ord-agent", "acc-agent", f.agent}} {
		v.exec(t, `INSERT INTO acme_orders (id, account_id, status, identifiers, expires_at, certificate_id, created_at, updated_at)
			VALUES (?1, ?2, 'valid', '[]', ?3, ?4, ?3, ?3)`, o.id, o.account, now, o.cert.ID)
	}
	// The agent's own ACME order for its identity certificate does not exist;
	// a pending order of the plain account (no certificate) must not matter.
	v.exec(t, `INSERT INTO acme_orders (id, account_id, status, identifiers, expires_at, created_at, updated_at)
		VALUES ('ord-pending', 'acc-plain', 'pending', '[]', ?1, ?1, ?1)`, now)
	// Certificates are immutable by trigger; the test turns one of them into
	// an imported one by lifting the trigger for its own database.
	v.exec(t, `DROP TRIGGER certificates_no_update`)
	v.exec(t, `UPDATE certificates SET source = 'imported' WHERE id = ?`, f.imported.ID)
	if _, err := v.e.Revoke(t.Context(), RevokeRequest{CertificateID: f.revoked.ID, Reason: ReasonSuperseded, Who: tester}); err != nil {
		t.Fatal(err)
	}
	return f
}

// TestIssuanceSources: the source class comes from the order and the account
// (D6); imported certificates, agent identity certificates and certificates
// outside the window are no issuances.
func TestIssuanceSources(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.chain(t, caOpts{})
	f := newReportFixture(t, v)
	issuedAt := v.clk.Now()

	got, err := v.e.IssuanceSources(t.Context(), tester, issuedAt, issuedAt.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	count := map[string]int{}
	for _, is := range got {
		count[is.Source]++
		if !is.At.Equal(issuedAt) || is.At.Location() != time.UTC {
			t.Errorf("created at %v, want %v UTC", is.At, issuedAt)
		}
	}
	// ui: ui, revoked (a revoked certificate was still issued); acme: acme; agent: agent.
	if count[SourceUI] != 2 || count[SourceACME] != 1 || count[SourceAgent] != 1 || len(got) != 4 {
		t.Errorf("classes %v (imported %s and agent identity %s must be absent)", count, f.imported.ID, f.agentIdentity.ID)
	}

	// created_at has milliseconds; the bounds are inclusive below, exclusive above.
	if n, _ := v.e.IssuanceSources(t.Context(), tester, issuedAt.Add(time.Millisecond), issuedAt.Add(time.Hour)); len(n) != 0 {
		t.Errorf("window after the issuance: %d", len(n))
	}
	if n, _ := v.e.IssuanceSources(t.Context(), tester, issuedAt.Add(-time.Hour), issuedAt); len(n) != 0 {
		t.Errorf("window ending at the issuance: %d", len(n))
	}
	if n, _ := v.e.IssuanceSources(t.Context(), tester, issuedAt, issuedAt.Add(time.Millisecond)); len(n) != 4 {
		t.Errorf("window of one millisecond: %d", len(n))
	}

	// A later issuance lands in a later window only.
	v.clk.Advance(8 * day)
	later := v.issue(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"later.homelab.lan"}})
	got, err = v.e.IssuanceSources(t.Context(), tester, v.clk.Now().Add(-time.Hour), v.clk.Now().Add(time.Hour))
	if err != nil || len(got) != 1 || got[0].Source != SourceUI {
		t.Errorf("later window: %v %v (%s)", got, err, later.ID)
	}
}

// TestExpiryTimes: not revoked, not an agent identity certificate, imported
// ones included, window (after, until].
func TestExpiryTimes(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.chain(t, caOpts{})
	f := newReportFixture(t, v)
	end := f.ui.NotAfter // every certificate of the fixture has the same preset and start

	got, err := v.e.ExpiryTimes(t.Context(), tester, v.clk.Now(), end.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	// ui, acme, agent, imported: four. Revoked and the agent identity are out.
	if len(got) != 4 {
		t.Fatalf("%d expiry times: %v", len(got), got)
	}
	for _, g := range got {
		if g.Location() != time.UTC {
			t.Errorf("%v is not UTC", g)
		}
	}
	// The four certificates end in the same second. The window is (after,
	// until]: exclusive below, inclusive above.
	for _, tc := range []struct {
		name         string
		after, until time.Time
		want         int
	}{
		{"until = end", v.clk.Now(), end, 4},
		{"until just before the end", v.clk.Now(), end.Add(-time.Second), 0},
		{"after = end", end, end.Add(24 * time.Hour), 0},
		{"after just before the end", end.Add(-time.Second), end.Add(24 * time.Hour), 4},
		{"empty window", end, end, 0},
		{"before everything", v.clk.Now().Add(-24 * time.Hour), v.clk.Now(), 0},
	} {
		got, err := v.e.ExpiryTimes(t.Context(), tester, tc.after, tc.until)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, len(got), tc.want)
		}
	}
}

// TestReportReadsKeepCAScoping: a CA-scoped reader sees only its CA, like
// CertificateCounts; a tenant-wide reader also sees external certificates.
func TestReportReadsKeepCAScoping(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	root, _ := v.chain(t, caOpts{})
	v.addCA(t, "other", caOpts{parent: root})
	v.issue(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"mine.homelab.lan"}})
	v.issue(t, Request{CA: "other", Preset: "server", DNSNames: []string{"theirs.homelab.lan"}})
	now := v.clk.Now()

	var none time.Time
	tenant := signedIn("tv", none, authz.Binding{Role: authz.Viewer})
	scoped := signedIn("cv", none, authz.Binding{CA: "issuing", Role: authz.Viewer})
	stranger := signedIn("x", none)

	for name, tc := range map[string]struct {
		who  keys.Who
		want int
	}{"tenant viewer": {tenant, 2}, "CA viewer": {scoped, 1}, "no role": {stranger, 0}} {
		exp, err := v.e.ExpiryTimes(t.Context(), tc.who, now, now.Add(3650*day))
		if err != nil || len(exp) != tc.want {
			t.Errorf("%s expiry: %d %v, want %d", name, len(exp), err, tc.want)
		}
		iss, err := v.e.IssuanceSources(t.Context(), tc.who, now.Add(-time.Hour), now.Add(time.Hour))
		if err != nil || len(iss) != tc.want {
			t.Errorf("%s issuances: %d %v, want %d", name, len(iss), err, tc.want)
		}
	}
}

// TestReportMigrationIndexes: the queries use the new indexes of migration
// 0020 (the plans name them), so a report does not scan the tables.
func TestReportMigrationIndexes(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	for name, tc := range map[string]struct{ query, index string }{
		"issuance by created_at": {`SELECT id FROM certificates WHERE created_at >= 'a' AND created_at < 'b'`, "certificates_created_at"},
		"order of a certificate": {`SELECT id FROM acme_orders WHERE certificate_id = 'x'`, "acme_orders_certificate"},
		"expiry by not_after":    {`SELECT id FROM certificates WHERE not_after > 'a' AND not_after <= 'b'`, "certificates_not_after"},
	} {
		plan := queryPlan(t, v.pki, tc.query)
		if !strings.Contains(plan, tc.index) {
			t.Errorf("%s: plan %q does not use %s", name, plan, tc.index)
		}
	}
}

// queryPlan returns the detail lines of EXPLAIN QUERY PLAN for query.
func queryPlan(t *testing.T, db *sql.DB, query string) string {
	t.Helper()
	rows, err := db.QueryContext(t.Context(), "EXPLAIN QUERY PLAN "+query)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var plan string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err = rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		plan += detail + "\n"
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	return plan
}
