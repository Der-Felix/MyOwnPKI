package ca

import (
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/ca/legacy"
	"github.com/Der-Felix/MyOwnPKI/internal/ca/legacy/legacytest"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// The legacy fixture (PHASE1 step 15): a PKI built by legacy/pki.sh with
// what a homelab collects over the years – two intermediates (one with name
// constraints), certificates revoked for different reasons, a renewed
// certificate, an encrypted key, a self-signed certificate and a renewed
// intermediate (same key). Built once per test run; it needs bash and
// OpenSSL (CI on Linux; Git Bash with LEGACY_TEST_OPENSSL=/usr/bin/openssl).

const legacyKeyPass = "a passphrase for one leaf key"

var legacyOnce struct {
	sync.Once
	dir string
	err error
}

func legacyFixture(t *testing.T) string {
	t.Helper()
	bash, legacyOpenSSL := legacytest.NeedPkiSh(t)
	opensslBin(t)
	legacyOnce.Do(func() {
		legacyOnce.dir, legacyOnce.err = buildLegacyFixture(bash, legacyOpenSSL)
	})
	if legacyOnce.err != nil {
		t.Fatal(legacyOnce.err)
	}
	return legacyOnce.dir
}

// buildLegacyFixture runs pki.sh; the directory lives until the process
// ends (TestMain removes the parent of the temp dirs).
func buildLegacyFixture(bash, legacyOpenSSL string) (string, error) {
	dir, err := os.MkdirTemp("", "myownpki-legacy-")
	if err != nil {
		return "", err
	}
	var steps []legacytest.Step
	for _, s := range [][]string{
		{"init", "--org", "Homelab", "--country", "DE", "--cn", "Legacy Root CA", "--key", "rsa3072", "--no-pass",
			"--leaf-key", "rsa2048", "--aia-url", "http://pki.homelab.example", "--intermediate", "server-ca"},
		{"ca-new", "client-ca", "--no-pass", "--key", "rsa3072", "--permit-dns", "homelab.example", "--permit-ip", "192.0.2.0/24"},
		{"issue", "server", "--cn", "nas.homelab.example", "--dns", "nas.homelab.example", "--ip", "192.0.2.10", "--ca", "server-ca"},
		{"issue", "server", "--cn", "web.homelab.example", "--dns", "web.homelab.example", "--ca", "server-ca"},
		{"issue", "server", "--cn", "old.homelab.example", "--dns", "old.homelab.example", "--ca", "server-ca"},
		{"issue", "server", "--cn", "leak.homelab.example", "--dns", "leak.homelab.example", "--ca", "server-ca"},
		{"issue", "client", "--cn", "backup-job", "--ca", "client-ca"},
		{"revoke", "old.homelab.example", "--reason", "superseded"},
		{"revoke", "leak.homelab.example", "--reason", "keyCompromise"},
		{"revoke", "backup-job", "--reason", "cessationOfOperation"},
		{"renew", "web.homelab.example"},
		{"renew-ca", "server-ca"},
		{"selfsigned", "server", "--cn", "self.homelab.example", "--dns", "self.homelab.example"},
		{"crl"},
	} {
		steps = append(steps, legacytest.Step{Args: s})
	}
	steps = append(steps, legacytest.Step{
		Args: []string{"issue", "server", "--cn", "enc.homelab.example", "--dns", "enc.homelab.example", "--ca", "server-ca", "--key-pass"},
		Env:  []string{"PKI_KEY_PASS=" + legacyKeyPass},
	})
	return legacytest.PkiSh(bash, legacyOpenSSL, dir, steps)
}

func readLegacy(t *testing.T, dir string, leafPass string) *legacy.PKI {
	t.Helper()
	pw := legacy.Passphrases{}
	if leafPass != "" {
		pw.Leaf = []byte(leafPass)
	}
	p, err := legacy.Read(os.DirFS(dir), pw)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// legacyEnv is an engine whose clock stands just after the fixture was made.
func legacyEnv(t *testing.T, p *legacy.PKI) *env {
	t.Helper()
	v := newEnv(t)
	latest := p.Root.Cert.NotBefore
	for _, c := range p.CAs() {
		for _, cert := range c.Signed {
			latest = later(latest, cert.NotBefore)
		}
		if c.CRL != nil {
			latest = later(latest, c.CRL.ThisUpdate)
		}
	}
	v.clk.Set(latest.Add(time.Minute))
	return v
}

func later(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

func TestImportLegacyPkiSh(t *testing.T) {
	t.Parallel()
	dir := legacyFixture(t)
	p := readLegacy(t, dir, legacyKeyPass)
	if len(p.Problems) > 0 {
		t.Fatalf("reader problems: %v", p.Problems)
	}
	v := legacyEnv(t, p)
	ctx := t.Context()

	// A dry run reports and writes nothing.
	dry, err := v.e.ImportLegacy(ctx, LegacyImportRequest{PKI: p, DryRun: true, Who: tester})
	if err != nil {
		t.Fatalf("dry run: %v\n%v", err, dry.Problems)
	}
	if cas, _ := pkidb.New(v.pki).ListCAs(ctx); len(cas) != 0 || dry.Imported {
		t.Fatalf("dry run wrote %d CAs", len(cas))
	}

	rep, err := v.e.ImportLegacy(ctx, LegacyImportRequest{PKI: p, Who: tester})
	if err != nil {
		t.Fatalf("import: %v\n%v", err, rep.Problems)
	}
	if !rep.Imported || !rep.LegacyURLs || rep.BaseURL != "http://pki.homelab.example" {
		t.Errorf("report %+v", rep)
	}
	// 6 leaves under server-ca (nas, web, web renewed, old, leak, enc),
	// 1 under client-ca; the self-signed one is external.
	if rep.Certificates != 7 || rep.Revoked != 3 || rep.External != 1 {
		t.Errorf("certificates %d, revoked %d, external %d", rep.Certificates, rep.Revoked, rep.External)
	}
	// Keys: nas, web (old and new), old, leak, backup-job, enc (encrypted).
	if rep.Keys != 7 {
		t.Errorf("keys %d, want 7", rep.Keys)
	}
	q := pkidb.New(v.pki)
	for _, src := range p.CAs() {
		checkLegacyCA(t, v, q, p, src)
	}

	// The intermediate renewed by pki.sh (same key) keeps its older certificate.
	sc, err := q.GetCAByName(ctx, "server-ca")
	if err != nil {
		t.Fatal(err)
	}
	hist, err := q.ListCAHistory(ctx, sc.ID)
	if err != nil || len(hist) != 1 {
		t.Fatalf("history of server-ca: %d %v", len(hist), err)
	}
	// Name constraints come from the certificate.
	cc, err := q.GetCAByName(ctx, "client-ca")
	if err != nil {
		t.Fatal(err)
	}
	nc, err := q.ListNameConstraints(ctx, cc.ID)
	if err != nil || len(nc) != 2 {
		t.Fatalf("name constraints of client-ca: %+v %v", nc, err)
	}

	// The imported intermediate issues on: new URLs, the chain verifies.
	v.clk.Advance(time.Minute)
	out := v.issue(t, Request{CA: "server-ca", Preset: "server", DNSNames: []string{"git.homelab.example"}})
	cert := parse(t, out.CertDER)
	if len(cert.CRLDistributionPoints) != 1 || cert.CRLDistributionPoints[0] != "http://pki.homelab.example/crl/server-ca/1.crl" {
		t.Errorf("CDP %v", cert.CRLDistributionPoints)
	}
	opensslVerifyAt(t, v.clk.Now(), out.Chain, out.CertDER, "sslserver")

	// A second import of the same directory is refused as a whole.
	if _, err := v.e.ImportLegacy(ctx, LegacyImportRequest{PKI: p, Who: tester}); err == nil {
		t.Error("second import accepted")
	}
	var actions []string
	for _, r := range v.auditRows(t) {
		actions = append(actions, r.action+"/"+r.result)
	}
	for _, want := range []string{ActionCAImportLegacy + "/success", ActionImportLegacy + "/success", ActionImportLegacy + "/denied", ActionCRLSign + "/success"} {
		if !slices.Contains(actions, want) {
			t.Errorf("audit has no %s: %v", want, actions)
		}
	}
}

// checkLegacyCA compares one CA before (pki.sh files) and after (pki.db):
// serials, revocations with time and reason, CRL numbers.
func checkLegacyCA(t *testing.T, v *env, q *pkidb.Queries, p *legacy.PKI, src *legacy.CA) {
	t.Helper()
	ctx := t.Context()
	row, err := q.GetCAByName(ctx, src.Name)
	if err != nil {
		t.Fatal(err)
	}
	if row.LegacyUrls != 1 {
		t.Errorf("CA %s: legacy URLs not set", src.Name)
	}

	// Serials and revocations of the end-entity certificates.
	type rev struct{ at, reason string }
	want := map[string]*rev{}
	for _, e := range src.Index {
		if src.Signed[e.Serial].IsCA {
			continue
		}
		want[e.Serial] = nil
		if e.Revoked != nil {
			want[e.Serial] = &rev{e.Revoked.Time.Format(time.RFC3339), e.Revoked.Reason}
		}
	}
	got := map[string]*rev{}
	eachRow(t, v.pki, `SELECT c.serial_hex, r.revoked_at, r.reason FROM certificates c
		LEFT JOIN revocations r ON r.certificate_id = c.id WHERE c.ca_id = ?`, []any{row.ID}, func(rows *sql.Rows) {
		var serial string
		var at, reason sql.NullString
		if serr := rows.Scan(&serial, &at, &reason); serr != nil {
			t.Fatal(serr)
		}
		got[serial] = nil
		if at.Valid {
			ts, perr := time.Parse(audit.TimeFormat, at.String)
			if perr != nil {
				t.Fatal(perr)
			}
			got[serial] = &rev{ts.Format(time.RFC3339), reason.String}
		}
	})
	if len(got) != len(want) {
		t.Errorf("CA %s: %d certificates imported, index.txt has %d", src.Name, len(got), len(want))
	}
	for s, w := range want {
		g, ok := got[s]
		switch {
		case !ok:
			t.Errorf("CA %s: serial %s missing", src.Name, s)
		case (g == nil) != (w == nil) || (g != nil && *g != *w):
			t.Errorf("CA %s: serial %s: revocation %+v, pki.sh %+v", src.Name, s, g, w)
		}
	}

	// CRL numbers: pki.sh's CRL is kept with its number; an online CA signs
	// the next one, the number crlnumber names.
	type crlRow struct {
		number int64
		source string
		der    []byte
	}
	var list []crlRow
	show := func() string {
		var s []string
		for _, r := range list {
			s = append(s, fmt.Sprintf("%d/%s", r.number, r.source))
		}
		return strings.Join(s, ", ")
	}
	eachRow(t, v.pki, `SELECT number, source, crl_der FROM crls WHERE ca_id = ? ORDER BY number`, []any{row.ID}, func(rows *sql.Rows) {
		var r crlRow
		if serr := rows.Scan(&r.number, &r.source, &r.der); serr != nil {
			t.Fatal(serr)
		}
		list = append(list, r)
	})
	if len(list) == 0 || list[0].source != "uploaded" || list[0].number != src.CRL.Number.Int64() {
		t.Fatalf("CA %s: CRLs %s, pki.sh's CRL number %v", src.Name, show(), src.CRL.Number)
	}
	if src.Name == "root" {
		if len(list) != 1 || row.KeyMode != KeyModeOffline {
			t.Errorf("CA %s: offline root: %d CRLs, key mode %s", src.Name, len(list), row.KeyMode)
		}
		return
	}
	if len(list) != 2 || list[1].source != "signed" || list[1].number != src.NextCRLNumber {
		t.Fatalf("CA %s: CRLs after the import: %s, crlnumber says %d", src.Name, show(), src.NextCRLNumber)
	}
	signed, err := x509.ParseRevocationList(list[1].der)
	if err != nil {
		t.Fatal(err)
	}
	if err := signed.CheckSignatureFrom(src.Cert); err != nil {
		t.Errorf("CA %s: signed CRL: %v", src.Name, err)
	}
	// The same entries as pki.sh's CRL: serial, time, reason.
	entry := func(e x509.RevocationListEntry) string {
		return SerialHex(e.SerialNumber) + " " + e.RevocationTime.UTC().Format(time.RFC3339) + " " + big.NewInt(int64(e.ReasonCode)).String()
	}
	var before, after []string
	for _, e := range src.CRL.RevokedCertificateEntries {
		before = append(before, entry(e))
	}
	for _, e := range signed.RevokedCertificateEntries {
		after = append(after, entry(e))
	}
	slices.Sort(before)
	slices.Sort(after)
	if !slices.Equal(before, after) {
		t.Errorf("CA %s: CRL entries\n pki.sh: %v\n server: %v", src.Name, before, after)
	}
	text := opensslText(t, "crl", list[1].der)
	if !strings.Contains(text, "X509v3 CRL Number") {
		t.Errorf("CA %s: openssl crl -text:\n%s", src.Name, text)
	}

	// openssl verify -crl_check_all: revoked leaves fail, the others pass.
	for _, e := range src.Index {
		cert := src.Signed[e.Serial]
		if cert.IsCA || cert.NotAfter.Before(v.clk.Now()) {
			continue
		}
		res, ok := opensslWithCRLs(t, v.clk.Now(), [][]byte{src.Cert.Raw, p.Root.Cert.Raw}, [][]byte{list[1].der, p.Root.CRL.Raw}, cert.Raw, "-crl_check_all")
		if ok == (e.Revoked != nil) {
			t.Errorf("CA %s: serial %s (revoked %v): openssl\n%s", src.Name, e.Serial, e.Revoked != nil, res)
		}
	}
}

func TestImportLegacyRootOnline(t *testing.T) {
	t.Parallel()
	dir := legacyFixture(t)
	p := readLegacy(t, dir, "")
	v := legacyEnv(t, p)
	rep, err := v.e.ImportLegacy(t.Context(), LegacyImportRequest{PKI: p, RootOnline: true, BaseURL: "http://ca.homelab.example/", Who: tester})
	if err != nil {
		t.Fatalf("import: %v\n%v", err, rep.Problems)
	}
	// Another base URL: no legacy aliases, and a warning names the old URLs.
	if rep.LegacyURLs || rep.BaseURL != "http://ca.homelab.example" || !containsText(rep.Warnings, "point to http://pki.homelab.example") {
		t.Errorf("report %+v", rep)
	}
	// Without PKI_KEY_PASS the encrypted leaf key stays behind, with a warning.
	if rep.Keys != 6 || !containsText(rep.Warnings, "PKI_KEY_PASS") {
		t.Errorf("keys %d, warnings %v", rep.Keys, rep.Warnings)
	}
	root, err := pkidb.New(v.pki).GetCAByName(t.Context(), "root")
	if err != nil {
		t.Fatal(err)
	}
	if root.KeyMode != KeyModeOnlineEncrypted || root.CrlNumber != p.Root.NextCRLNumber {
		t.Errorf("online root: key mode %s, CRL number %d (pki.sh next %d)", root.KeyMode, root.CrlNumber, p.Root.NextCRLNumber)
	}
	// A root still issues no end-entity certificates (decision 81).
	_, err = v.e.Issue(t.Context(), Request{CA: "root", Preset: "server", DNSNames: []string{"x.homelab.example"}, Who: tester})
	var d *DeniedError
	if !errors.As(err, &d) {
		t.Errorf("issue from the imported root: %v", err)
	}
}

// TestImportLegacyRefuses: a broken directory is refused as a whole, with
// every problem named, and nothing is written.
func TestImportLegacyRefuses(t *testing.T) {
	t.Parallel()
	src := legacyFixture(t)
	dir := filepath.Join(t.TempDir(), "pki")
	if err := os.CopyFS(dir, os.DirFS(src)); err != nil {
		t.Fatal(err)
	}
	// A certificate file of the index is gone.
	p := readLegacy(t, src, "")
	var victim string
	for _, e := range p.Intermediates[1].Index { // server-ca
		victim = e.File
	}
	if err := os.Remove(filepath.Join(dir, "intermediate", "server-ca", "newcerts", victim+".pem")); err != nil {
		t.Fatal(err)
	}
	broken := readLegacy(t, dir, "")
	v := legacyEnv(t, broken)
	rep, err := v.e.ImportLegacy(t.Context(), LegacyImportRequest{PKI: broken, Who: tester})
	var d *DeniedError
	if !errors.As(err, &d) || !containsText(rep.Problems, victim) {
		t.Fatalf("missing newcerts file: %v %v", err, rep.Problems)
	}
	if cas, _ := pkidb.New(v.pki).ListCAs(t.Context()); len(cas) != 0 {
		t.Errorf("refused import wrote %d CAs", len(cas))
	}
	rows := v.auditRows(t)
	if len(rows) != 1 || rows[0].action != ActionImportLegacy || rows[0].result != "denied" {
		t.Errorf("audit %+v", rows)
	}
}

func containsText(list []string, sub string) bool {
	return slices.ContainsFunc(list, func(s string) bool { return strings.Contains(s, sub) })
}

// eachRow runs a query and calls fn for every row.
func eachRow(t *testing.T, db *sql.DB, query string, args []any, fn func(*sql.Rows)) {
	t.Helper()
	rows, err := db.QueryContext(t.Context(), query, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		fn(rows)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}
