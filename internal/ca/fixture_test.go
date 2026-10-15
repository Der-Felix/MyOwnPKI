package ca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca/preset"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/ids"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
	"github.com/Der-Felix/MyOwnPKI/internal/testutil"
)

// Step 7 has no CA creation yet (step 8), so these tests build root and
// intermediate CAs in memory and store them exactly like real CAs: key
// encrypted in pki.db, rows in cas / ca_generations / ca_name_constraints.

var t0 = time.Date(2026, 10, 13, 8, 0, 0, 0, time.UTC)

const baseURL = "http://pki.homelab.lan"

// tester runs as the console: every permission, no step-up. The permission
// rules themselves are tested with signed-in users in authz_test.go.
var tester = keys.Who{Actor: audit.Actor{Type: audit.ActorUser, ID: "u-1", Name: "it-admin"}, SourceIP: "192.0.2.10", Principal: authz.Console()}

// unsealed is one keyring for every test: Init and Unseal use the production
// Argon2id parameters (256 MiB), so they run once. After unseal the keyring
// only needs its root key in memory – each test has its own databases.
var unsealed *keys.Keyring

func TestMain(m *testing.M) {
	code, err := runTests(m)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(code)
}

func runTests(m *testing.M) (int, error) {
	dir, err := os.MkdirTemp("", "myownpki-ca-")
	if err != nil {
		return 0, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	ctx := context.Background()
	l := store.Layout{DataDir: dir}
	clk := clock.NewFake(t0)
	if _, err = store.Migrate(ctx, l, store.DefaultTenant, clk.Now); err != nil {
		return 0, err
	}
	sys, err := store.Open(ctx, l.SystemDB())
	if err != nil {
		return 0, err
	}
	defer func() { _ = sys.Close() }()
	ia, err := store.Open(ctx, l.InstanceAuditDB())
	if err != nil {
		return 0, err
	}
	defer func() { _ = ia.Close() }()
	unsealed = keys.New(sys.Write, ia.Write, clk)
	rk, err := keys.NewRecoveryKey(nil)
	if err != nil {
		return 0, err
	}
	pass := "correct horse battery staple"
	if err := unsealed.Init(ctx, []byte(pass), rk, tester); err != nil {
		return 0, err
	}
	if err := unsealed.Unseal(ctx, []byte(pass), tester); err != nil {
		return 0, err
	}
	return m.Run(), nil
}

type env struct {
	e          *Engine
	clk        *clock.Fake
	pki, audit *sql.DB
	keygen     bool
	deliver    func()
}

func newEnv(t *testing.T) *env {
	t.Helper()
	l := store.Layout{DataDir: t.TempDir()}
	v := &env{clk: clock.NewFake(t0), keygen: true}
	if _, err := store.Migrate(t.Context(), l, store.DefaultTenant, v.clk.Now); err != nil {
		t.Fatal(err)
	}
	open := func(kind store.Kind) *sql.DB {
		path, err := l.TenantDB(store.DefaultTenant, kind)
		if err != nil {
			t.Fatal(err)
		}
		db, err := store.Open(t.Context(), path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db.Write
	}
	v.pki, v.audit = open(store.KindPKI), open(store.KindAudit)
	presets, err := preset.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	scope := store.TenantScope(store.DefaultTenant)
	v.e = &Engine{
		PKI: v.pki, Audit: v.audit, Scope: scope, Keys: unsealed, Presets: presets, Clock: v.clk,
		ServerKeygen: func(context.Context) (bool, error) { return v.keygen, nil },
	}
	d := &audit.Deliverer{
		Routes: []audit.Route{{Source: "pki", From: v.pki, To: v.audit, Scope: scope}},
		Clock:  v.clk, Log: slog.New(slog.DiscardHandler),
	}
	v.deliver = func() {
		if _, err := d.DeliverPending(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	return v
}

type fixtureCA struct {
	name string
	id   string
	cert *x509.Certificate
	key  crypto.Signer
}

type caOpts struct {
	parent              *fixtureCA
	key                 crypto.Signer // nil = new ECDSA P-384
	notBefore, notAfter time.Time     // zero = t0-24h / t0+10y
	maxValidity         int           // 0 = 825
	// Name constraints, written into the certificate and the database...
	permitDNS, excludeDNS, permitIP []string
	// ...or only into one of them, to test each layer alone.
	dbOnlyPermitDNS, certOnlyPermitDNS []string
	ekuLimit                           []x509.ExtKeyUsage
	keyMode, status                    string
}

var ekuOID = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageServerAuth: "1.3.6.1.5.5.7.3.1",
	x509.ExtKeyUsageClientAuth: "1.3.6.1.5.5.7.3.2",
}

func mustKey(t *testing.T, c elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// addCA creates a CA certificate and stores it as generation 1.
func (v *env) addCA(t *testing.T, name string, o caOpts) *fixtureCA {
	t.Helper()
	ctx := t.Context()
	key := o.key
	if key == nil {
		key = mustKey(t, elliptic.P384())
	}
	if o.notBefore.IsZero() {
		o.notBefore = t0.Add(-24 * time.Hour)
	}
	if o.notAfter.IsZero() {
		o.notAfter = t0.AddDate(10, 0, 0)
	}
	serial, err := newSerial(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "Test " + name, Organization: []string{"MyOwnPKI Test"}},
		NotBefore:    o.notBefore, NotAfter: o.notAfter,
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         append(append([]string{}, o.permitDNS...), o.certOnlyPermitDNS...),
		ExcludedDNSDomains:          o.excludeDNS,
		ExtKeyUsage:                 o.ekuLimit,
	}
	for _, c := range o.permitIP {
		_, n, perr := net.ParseCIDR(c)
		if perr != nil {
			t.Fatal(perr)
		}
		tmpl.PermittedIPRanges = append(tmpl.PermittedIPRanges, n)
	}
	signerCert, signerKey, kind := tmpl, key, "root"
	if o.parent != nil {
		signerCert, signerKey, kind = o.parent.cert, o.parent.key, "intermediate"
		tmpl.MaxPathLenZero = true
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, key.Public(), signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	alg, err := keyAlgorithm(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	caID, _ := ids.New("ca", t0, nil)
	keyID, _ := ids.New("key", t0, nil)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	envl, err := unsealed.EncryptKey(keyID, keys.PurposeCA, alg, pkcs8)
	if err != nil {
		t.Fatal(err)
	}
	now := t0.Format(audit.TimeFormat)
	if err := keys.SaveKey(ctx, v.pki, keys.StoredKey{ID: keyID, Purpose: keys.PurposeCA, Algorithm: alg, Envelope: envl}, now); err != nil {
		t.Fatal(err)
	}

	q := pkidb.New(v.pki)
	limit := []string{}
	for _, u := range o.ekuLimit {
		limit = append(limit, ekuOID[u])
	}
	limitJSON, _ := json.Marshal(limit)
	or := func(s, def string) string {
		if s == "" {
			return def
		}
		return s
	}
	maxV := int64(825)
	if o.maxValidity != 0 {
		maxV = int64(o.maxValidity)
	}
	p := pkidb.InsertCAParams{
		ID: caID, Name: name, Kind: kind, Status: or(o.status, StatusActive), KeyMode: or(o.keyMode, KeyModeOnlineEncrypted),
		NcCritical: 1, EkuLimit: string(limitJSON), PublicBaseUrl: baseURL, CrlDays: 7, MaxValidityDays: maxV,
		CreatedAt: now, UpdatedAt: now,
	}
	gen := pkidb.InsertCAGenerationParams{
		CaID: caID, Generation: 1, KeyID: sql.NullString{String: keyID, Valid: true}, KeyAlgorithm: alg,
		SubjectDn: cert.Subject.String(), SerialHex: sql.NullString{String: SerialHex(cert.SerialNumber), Valid: true},
		NotBefore:         sql.NullString{String: cert.NotBefore.Format(dbTime), Valid: true},
		NotAfter:          sql.NullString{String: cert.NotAfter.Format(dbTime), Valid: true},
		CertDer:           der,
		FingerprintSha256: sql.NullString{String: fingerprint(der), Valid: true},
		SkiHex:            sql.NullString{String: strings.ToUpper(hex.EncodeToString(cert.SubjectKeyId)), Valid: true},
		CreatedAt:         now,
	}
	if o.parent != nil {
		p.ParentID = sql.NullString{String: o.parent.id, Valid: true}
		p.PathLen = sql.NullInt64{Int64: 0, Valid: true}
		gen.IssuerCaID = sql.NullString{String: o.parent.id, Valid: true}
		gen.IssuerGeneration = sql.NullInt64{Int64: 1, Valid: true}
	}
	if err := q.InsertCA(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := q.InsertCAGeneration(ctx, gen); err != nil {
		t.Fatal(err)
	}
	if err := q.SetCurrentGeneration(ctx, pkidb.SetCurrentGenerationParams{CurrentGeneration: sql.NullInt64{Int64: 1, Valid: true}, UpdatedAt: now, ID: caID}); err != nil {
		t.Fatal(err)
	}
	nc := func(kind string, values []string, permitted int64) {
		for _, val := range values {
			if err := q.InsertNameConstraint(ctx, pkidb.InsertNameConstraintParams{CaID: caID, Kind: kind, Value: val, Permitted: permitted}); err != nil {
				t.Fatal(err)
			}
		}
	}
	nc("dns", o.permitDNS, 1)
	nc("dns", o.dbOnlyPermitDNS, 1)
	nc("dns", o.excludeDNS, 0)
	nc("ip", o.permitIP, 1)
	return &fixtureCA{name: name, id: caID, cert: cert, key: key}
}

func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// chain builds the usual setup: root "root" and intermediate "issuing".
func (v *env) chain(t *testing.T, inter caOpts) (root, issuing *fixtureCA) {
	t.Helper()
	root = v.addCA(t, "root", caOpts{})
	inter.parent = root
	if inter.key == nil {
		inter.key = mustKey(t, elliptic.P256())
	}
	return root, v.addCA(t, "issuing", inter)
}

// makeCSR creates a PEM CSR with the given template.
func makeCSR(t *testing.T, key crypto.Signer, tmpl *x509.CertificateRequest) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// auditRows returns "action/result" plus details of the tenant log, after
// delivering the outbox.
func (v *env) auditRows(t *testing.T) []auditRow {
	t.Helper()
	v.deliver()
	rows, err := v.audit.QueryContext(t.Context(), `SELECT action, result, target_id, details_json FROM audit_entries ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []auditRow
	for rows.Next() {
		var r auditRow
		var d string
		if err = rows.Scan(&r.action, &r.result, &r.target, &d); err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal([]byte(d), &r.details); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	r, err := audit.Verify(t.Context(), v.audit, v.e.Scope)
	if err != nil || r.Break != nil {
		t.Fatalf("tenant audit chain: %v %+v", err, r.Break)
	}
	return out
}

type auditRow struct {
	action, result, target string
	details                map[string]any
}

// opensslVerify runs `openssl verify -x509_strict -purpose` at the fake
// clock's time. Skipped when OpenSSL is not installed (it is in CI).
func opensslVerify(t *testing.T, chain []*fixtureCA, leafDER []byte, purpose string) {
	t.Helper()
	ders := make([][]byte, len(chain))
	for i, c := range chain {
		ders[i] = c.cert.Raw
	}
	opensslVerifyAt(t, t0, ders, leafDER, purpose)
}

// opensslBin returns the openssl binary (OpenSSL 3 or newer); skipped
// locally, fatal in CI.
func opensslBin(t *testing.T) string {
	t.Helper()
	return testutil.OpenSSL(t)
}

// opensslVerifyAt verifies leafDER against chain (issuer first, root last)
// at the given time.
func opensslVerifyAt(t *testing.T, at time.Time, chain [][]byte, leafDER []byte, purpose string) {
	t.Helper()
	bin := opensslBin(t)
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if werr := os.WriteFile(p, data, 0o600); werr != nil {
			t.Fatal(werr)
		}
		return p
	}
	pemOf := func(der []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}) }
	args := []string{"verify", "-x509_strict", "-attime", strconv.FormatInt(at.Unix(), 10), "-CAfile", write("root.pem", pemOf(chain[len(chain)-1]))}
	if len(chain) > 1 {
		var b bytes.Buffer
		for _, c := range chain[:len(chain)-1] {
			b.Write(pemOf(c))
		}
		args = append(args, "-untrusted", write("inter.pem", b.Bytes()))
	}
	if purpose != "any" {
		args = append(args, "-purpose", purpose)
	}
	args = append(args, write("leaf.pem", pemOf(leafDER)))
	out, err := exec.CommandContext(t.Context(), bin, args...).CombinedOutput()
	if err != nil || !bytes.Contains(out, []byte(": OK")) {
		t.Errorf("openssl %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// opensslWithCRLs runs `openssl verify` with CRL checking and returns the
// output and whether OpenSSL said OK. flags: e.g. -crl_check_all,
// -extended_crl.
func opensslWithCRLs(t *testing.T, at time.Time, chain, crls [][]byte, leafDER []byte, flags ...string) (string, bool) {
	t.Helper()
	bin := opensslBin(t)
	dir := t.TempDir()
	write := func(name, typ string, ders ...[]byte) string {
		var b bytes.Buffer
		for _, d := range ders {
			b.Write(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: d}))
		}
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	args := []string{"verify", "-x509_strict", "-attime", strconv.FormatInt(at.Unix(), 10), "-CAfile", write("root.pem", "CERTIFICATE", chain[len(chain)-1])}
	if len(chain) > 1 {
		args = append(args, "-untrusted", write("inter.pem", "CERTIFICATE", chain[:len(chain)-1]...))
	}
	args = append(args, "-CRLfile", write("crls.pem", "X509 CRL", crls...))
	args = append(args, flags...)
	args = append(args, write("leaf.pem", "CERTIFICATE", leafDER))
	out, err := exec.CommandContext(t.Context(), bin, args...).CombinedOutput()
	return string(out), err == nil && bytes.Contains(out, []byte(": OK"))
}

// opensslText runs `openssl <kind> -noout -text` on a DER object.
func opensslText(t *testing.T, kind string, der []byte) string {
	t.Helper()
	bin := opensslBin(t)
	p := filepath.Join(t.TempDir(), "obj.der")
	if err := os.WriteFile(p, der, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.CommandContext(t.Context(), bin, kind, "-inform", "DER", "-in", p, "-noout", "-text").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl %s -text: %v\n%s", kind, err, out)
	}
	return string(out)
}
