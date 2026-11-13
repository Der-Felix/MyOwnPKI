package ca

import (
	"context"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"io"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// failingRand fails the test's request when anything reads randomness: a plan
// draws no serial, no key and no signature.
type failingRand struct{ reads int }

func (r *failingRand) Read([]byte) (int, error) {
	r.reads++
	return 0, errors.New("a plan must not read randomness")
}

// rowCounts counts what an issuance writes: certificates, their names, keys,
// the outbox (the audit entries of business changes) and the audit log
// itself (refusals are written there directly).
func (v *env) rowCounts(t *testing.T) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, c := range []struct {
		db    *sql.DB
		table string
	}{
		{v.pki, "certificates"}, {v.pki, "certificate_sans"}, {v.pki, "keys"}, {v.pki, "outbox"}, {v.pki, "blocked_keys"},
		{v.audit, "audit_entries"},
	} {
		var n int
		if err := c.db.QueryRowContext(t.Context(), "SELECT count(*) FROM "+c.table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		out[c.table] = n
	}
	return out
}

// planSilently runs Engine.Plan with an engine whose randomness fails when
// read, and proves that nothing was written: no row, no audit entry.
func (v *env) planSilently(t *testing.T, req Request) (*Plan, error) {
	t.Helper()
	if req.Who.Actor.Name == "" {
		req.Who = tester
	}
	before := v.rowCounts(t)
	rnd := &failingRand{}
	v.e.Rand = rnd
	defer func() { v.e.Rand = nil }()
	p, err := v.e.Plan(t.Context(), req)
	if rnd.reads != 0 {
		t.Errorf("the plan read randomness %d time(s)", rnd.reads)
	}
	if after := v.rowCounts(t); !maps.Equal(before, after) {
		t.Errorf("the plan wrote rows: before %v, after %v", before, after)
	}
	return p, err
}

func tlsCSR(t *testing.T, cn string, dns ...string) []byte {
	t.Helper()
	return makeCSR(t, mustKey(t, elliptic.P256()), &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}, DNSNames: dns})
}

// planRow is one request, planned and then issued with the same clock.
type planRow struct {
	name string
	ca   caOpts
	// prepare changes the environment before the request is built.
	prepare func(t *testing.T, v *env)
	req     func(t *testing.T, v *env) Request

	wantPreset string
	// A refusal: the plan gate or collected check that must be named, and a text every plan must contain.
	refused    bool
	wantStop   string
	wantReason string
	sealed     bool
	wantNote   string
}

func planRows() []planRow {
	permit := caOpts{permitDNS: []string{"homelab.lan"}, permitIP: []string{"10.0.0.0/8"}}
	srv := func(r Request) func(*testing.T, *env) Request {
		return func(*testing.T, *env) Request { return r }
	}
	longName := strings.Repeat("a", 60) + ".homelab.lan" // 72 characters: too long for a CN
	return []planRow{
		{name: "server names and key from a CSR", ca: permit, wantPreset: "server", req: func(t *testing.T, _ *env) Request {
			t.Helper()
			return Request{CA: "issuing", Preset: "server", CSR: tlsCSR(t, ""), DNSNames: []string{"nas.homelab.lan", "NAS2.homelab.lan"}, IPAddresses: []string{"10.0.0.5"}}
		}},
		{name: "wildcard adds the base domain", ca: permit, wantPreset: "wildcard", wantNote: "added the base domain", req: srv(Request{
			CA: "issuing", Preset: "wildcard", Subject: Subject{CommonName: "*.homelab.lan"}, DNSNames: []string{"*.sub.homelab.lan"}})},
		{name: "CN becomes the first SAN", ca: permit, wantPreset: "server", req: srv(Request{
			CA: "issuing", Preset: "server", Subject: Subject{CommonName: "nas.homelab.lan"}})},
		{name: "subject defaults fill what is empty", ca: permit, wantPreset: "server", req: srv(Request{
			CA: "issuing", Preset: "server", DNSNames: []string{"nas.homelab.lan"}, Subject: Subject{Organization: "Mine"},
			SubjectDefaults: Subject{CommonName: "never", Organization: "Default Org", OrganizationalUnit: "Lab", Locality: "Berlin", Province: "BE", Country: "DE"}})},
		{name: "custom usages with an unknown EKU", ca: permit, wantPreset: "custom", req: srv(Request{
			CA: "issuing", Preset: "custom", Subject: Subject{CommonName: "custom"},
			CustomKeyUsage: []string{"digitalSignature"}, CustomExtKeyUsage: []string{"clientAuth", "1.3.6.1.4.1.311.10.3.12"}})},
		{name: "critical EKU of a time stamping certificate", ca: permit, wantPreset: "timestamp", req: srv(Request{
			CA: "issuing", Preset: "timestamp", Subject: Subject{CommonName: "Homelab TSA", Country: "de"}})},
		{name: "OCSP responder gets the nocheck extension", ca: permit, wantPreset: "ocsp", req: srv(Request{
			CA: "issuing", Preset: "ocsp", Subject: Subject{CommonName: "Homelab OCSP Responder"}})},
		{name: "validity capped at the CA maximum", ca: caOpts{maxValidity: 100}, wantPreset: "server", wantNote: "capped at the CA maximum", req: srv(Request{
			CA: "issuing", Preset: "server", DNSNames: []string{"nas.homelab.lan"}})},
		{name: "explicit validity", ca: permit, wantPreset: "server", req: srv(Request{
			CA: "issuing", Preset: "server", DNSNames: []string{"nas.homelab.lan"}, ValidityDays: 30})},
		{name: "validity shortened to the CA certificate", ca: caOpts{notAfter: t0.AddDate(0, 0, 40)}, wantPreset: "server", wantNote: "shortened to the end of the CA certificate", req: srv(Request{
			CA: "issuing", Preset: "server", DNSNames: []string{"nas.homelab.lan"}})},
		{name: "SAN types the preset does not take are dropped", ca: permit, wantPreset: "server", wantNote: "ignored 2", req: func(t *testing.T, _ *env) Request {
			t.Helper()
			csr := makeCSR(t, mustKey(t, elliptic.P256()), &x509.CertificateRequest{
				Subject: pkix.Name{CommonName: "web.homelab.lan"}, DNSNames: []string{"web.homelab.lan"}, EmailAddresses: []string{"a@homelab.lan", "b@homelab.lan"}})
			return Request{CA: "issuing", Preset: "server", CSR: csr}
		}},
		{name: "CSR names are ignored on request", ca: permit, wantPreset: "server", req: func(t *testing.T, _ *env) Request {
			t.Helper()
			return Request{CA: "issuing", Preset: "server", CSR: tlsCSR(t, "ignored", "evil.example"), IgnoreCSRNames: true, DNSNames: []string{"nas.homelab.lan"}}
		}},
		{name: "a long derived CN is left out, the SAN is critical", ca: permit, wantPreset: "server", wantNote: "no common name", req: srv(Request{
			CA: "issuing", Preset: "server", DNSNames: []string{longName}})},
		{name: "Ed25519 key gets its warning", ca: permit, wantPreset: "server", req: func(t *testing.T, _ *env) Request {
			t.Helper()
			_, k, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			return Request{CA: "issuing", Preset: "server", CSR: makeCSR(t, k, &x509.CertificateRequest{}), DNSNames: []string{"nas.homelab.lan"}}
		}},
		{name: "RSA key from a CSR", ca: permit, wantPreset: "server", req: func(t *testing.T, _ *env) Request {
			t.Helper()
			k, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			return Request{CA: "issuing", Preset: "server", CSR: makeCSR(t, k, &x509.CertificateRequest{}), DNSNames: []string{"nas.homelab.lan"}}
		}},
		{name: "server-side key", ca: permit, wantPreset: "server", req: srv(Request{
			CA: "issuing", Preset: "server", KeyAlgorithm: AlgECDSAP384, DNSNames: []string{"nas.homelab.lan"}})},
		{name: "server-side RSA key, key usage with keyEncipherment", ca: permit, wantPreset: "server", req: srv(Request{
			CA: "issuing", Preset: "server", KeyAlgorithm: AlgRSA2048, DNSNames: []string{"nas.homelab.lan"}})},

		// Refusals: the plan gives the reasons issuance gives.
		{name: "name outside the constraints, validity too long, all at once", ca: permit, refused: true, wantReason: "exceeds the maximum", req: srv(Request{
			CA: "issuing", Preset: "server", DNSNames: []string{"nas.homelab.lan", "evil.example", "Bad_Name.homelab.lan"}, ValidityDays: 9999})},
		{name: "hostile CSR names", ca: permit, refused: true, wantReason: "evil.example", req: func(t *testing.T, _ *env) Request {
			t.Helper()
			return Request{CA: "issuing", Preset: "server", CSR: tlsCSR(t, "<script>alert(1)</script>", "evil.example", "10.example.com")}
		}},
		{name: "EKU limit of the CA", ca: caOpts{ekuLimit: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, refused: true, wantReason: "extended key usage", req: srv(Request{
			CA: "issuing", Preset: "client", Subject: Subject{CommonName: "laptop"}})},
		{name: "explicit validity above the maximum", ca: caOpts{maxValidity: 100}, refused: true, wantReason: "exceeds the maximum", req: srv(Request{
			CA: "issuing", Preset: "server", DNSNames: []string{"nas.homelab.lan"}, ValidityDays: 200})},
		{name: "explicit validity beyond the CA certificate", ca: caOpts{notAfter: t0.AddDate(0, 0, 40)}, refused: true, wantReason: "would end after the CA certificate", req: srv(Request{
			CA: "issuing", Preset: "server", DNSNames: []string{"nas.homelab.lan"}, ValidityDays: 90})},
		{name: "renewal of a certificate that does not exist", ca: permit, refused: true, wantReason: "to renew doesn't exist", req: srv(Request{
			CA: "issuing", Preset: "server", DNSNames: []string{"nas.homelab.lan"}, RenewalOf: "crt-nothing"})},
		{name: "no name at all", ca: permit, refused: true, wantReason: "needs at least one name", req: srv(Request{CA: "issuing", Preset: "server"})},
		{name: "a root CA does not issue leaves", ca: permit, refused: true, wantStop: CheckCA, wantReason: "root CA only signs", req: srv(Request{
			CA: "root", Preset: "server", DNSNames: []string{"nas.homelab.lan"}})},
		{name: "unknown CA", ca: permit, refused: true, wantStop: CheckCA, wantReason: "there is no CA named", req: srv(Request{
			CA: "nope", Preset: "server", DNSNames: []string{"nas.homelab.lan"}})},
		{name: "unknown preset", ca: permit, refused: true, wantStop: CheckPreset, wantReason: "no preset named", req: srv(Request{
			CA: "issuing", Preset: "nope", DNSNames: []string{"nas.homelab.lan"}})},
		{name: "expired CA certificate", ca: caOpts{notAfter: t0.Add(-time.Hour)}, refused: true, wantStop: CheckCAValidity, wantReason: "is not valid now", req: srv(Request{
			CA: "issuing", Preset: "server", DNSNames: []string{"nas.homelab.lan"}})},
		{name: "retired CA", ca: caOpts{status: StatusRetired}, refused: true, wantStop: CheckCA, wantReason: "not active", req: srv(Request{
			CA: "issuing", Preset: "server", DNSNames: []string{"nas.homelab.lan"}})},
		{name: "offline CA key", ca: caOpts{keyMode: KeyModeOffline}, refused: true, wantStop: CheckCA, wantReason: "offline", req: srv(Request{
			CA: "issuing", Preset: "server", DNSNames: []string{"nas.homelab.lan"}})},
		{name: "blocked key", ca: permit, refused: true, wantStop: CheckKey, wantReason: "reported compromised", req: func(t *testing.T, v *env) Request {
			t.Helper()
			k := mustKey(t, elliptic.P256())
			h, err := spkiHash(k.Public())
			if err != nil {
				t.Fatal(err)
			}
			if err := pkidb.New(v.pki).BlockKey(t.Context(), pkidb.BlockKeyParams{
				SpkiSha256: h, Reason: "keyCompromise", SourceType: "certificate", SourceID: "crt-x", BlockedAt: t0.Format(dbTime), BlockedBy: "test",
			}); err != nil {
				t.Fatal(err)
			}
			return Request{CA: "issuing", Preset: "server", CSR: makeCSR(t, k, &x509.CertificateRequest{}), DNSNames: []string{"nas.homelab.lan"}}
		}},
		{name: "RSA key that is too small", ca: permit, refused: true, wantStop: CheckKey, wantReason: "not allowed", req: func(t *testing.T, _ *env) Request {
			t.Helper()
			k, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // a key below the policy minimum is the case under test
			if err != nil {
				t.Fatal(err)
			}
			return Request{CA: "issuing", Preset: "server", CSR: makeCSR(t, k, &x509.CertificateRequest{}), DNSNames: []string{"nas.homelab.lan"}}
		}},
		{name: "not a CSR", ca: permit, refused: true, wantStop: CheckKey, wantReason: "no PEM block", req: srv(Request{
			CA: "issuing", Preset: "server", CSR: []byte("hello"), DNSNames: []string{"nas.homelab.lan"}})},
		{name: "key algorithm together with a CSR", ca: permit, refused: true, wantStop: CheckKey, wantReason: "brings its own key", req: func(t *testing.T, _ *env) Request {
			t.Helper()
			return Request{CA: "issuing", Preset: "server", CSR: tlsCSR(t, ""), KeyAlgorithm: AlgECDSAP256, DNSNames: []string{"nas.homelab.lan"}}
		}},
		{name: "server-side key generation is off", ca: permit, refused: true, wantStop: CheckKey, wantReason: "switched off", prepare: func(_ *testing.T, v *env) { v.keygen = false },
			req: srv(Request{CA: "issuing", Preset: "server", DNSNames: []string{"nas.homelab.lan"}})},
		{name: "key algorithm that cannot be generated", ca: permit, refused: true, wantStop: CheckKey, wantReason: "can't be generated", req: srv(Request{
			CA: "issuing", Preset: "server", KeyAlgorithm: "rsa-1024", DNSNames: []string{"nas.homelab.lan"}})},
		{name: "custom usages on a fixed preset", ca: permit, refused: true, wantStop: CheckUsages, wantReason: "fixed key usages", req: srv(Request{
			CA: "issuing", Preset: "server", DNSNames: []string{"nas.homelab.lan"}, CustomKeyUsage: []string{"digitalSignature"}})},

		// A sealed key ring: issuance returns ErrSealed, the plan records it.
		{name: "sealed key ring, allowed by policy", ca: permit, sealed: true, wantPreset: "server", req: srv(Request{
			CA: "issuing", Preset: "server", DNSNames: []string{"nas.homelab.lan"}})},
		{name: "sealed key ring and a refusal", ca: permit, sealed: true, refused: true, wantReason: "Bad_Name", req: srv(Request{
			CA: "issuing", Preset: "server", DNSNames: []string{"Bad_Name.homelab.lan"}})},
	}
}

func TestPlanEquivalence(t *testing.T) {
	t.Parallel()
	for _, row := range planRows() {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			v := newEnv(t)
			root, issuing := v.chain(t, row.ca)
			if row.prepare != nil {
				row.prepare(t, v)
			}
			req := row.req(t, v)
			if row.sealed {
				v.e.Keys = keys.New(nil, nil, v.clk) // never unsealed
			}
			v.checkEquivalence(t, row, req, []*fixtureCA{issuing, root})
		})
	}
}

// checkEquivalence plans req silently, issues it with the same clock and
// compares the two.
func (v *env) checkEquivalence(t *testing.T, row planRow, req Request, chain []*fixtureCA) {
	t.Helper()
	if req.Who.Actor.Name == "" {
		req.Who = tester
	}
	plan, perr := v.planSilently(t, req)
	if perr != nil {
		t.Fatalf("plan: %v", perr)
	}
	if !plan.GeneratedAt.Equal(v.clk.Now()) {
		t.Errorf("generated at %s, clock %s", plan.GeneratedAt, v.clk.Now())
	}
	if plan.Sealed != row.sealed {
		t.Errorf("sealed %v, want %v", plan.Sealed, row.sealed)
	}
	if plan.StoppedAt != row.wantStop {
		t.Errorf("stopped at %q, want %q", plan.StoppedAt, row.wantStop)
	}
	if plan.Allowed == row.refused {
		t.Fatalf("allowed %v with reasons %q, want refused %v", plan.Allowed, plan.Reasons, row.refused)
	}
	checkPlanChecks(t, plan)

	out, err := v.e.Issue(t.Context(), req)
	switch {
	case row.sealed:
		if !errors.Is(err, keys.ErrSealed) {
			t.Fatalf("issue on a sealed key ring: %v", err)
		}
		return
	case row.refused:
		var d *DeniedError
		if !errors.As(err, &d) || !errors.Is(err, ErrDenied) {
			t.Fatalf("issue: want a denial, got %v", err)
		}
		if !slices.Equal(plan.Reasons, d.Reasons) {
			t.Errorf("reasons differ\n plan:  %q\n issue: %q", plan.Reasons, d.Reasons)
		}
		if !slices.Equal(plan.DroppedCSRNames, d.DroppedCSRNames) {
			t.Errorf("dropped names differ: plan %q, issue %q", plan.DroppedCSRNames, d.DroppedCSRNames)
		}
		if !strings.Contains(strings.Join(plan.Reasons, "\n"), row.wantReason) {
			t.Errorf("reasons %q lack %q", plan.Reasons, row.wantReason)
		}
		return
	}
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if len(plan.Reasons) != 0 {
		t.Errorf("an allowed plan has reasons: %q", plan.Reasons)
	}
	if row.wantPreset != "" && plan.Preset != row.wantPreset {
		t.Errorf("preset %q, want %q", plan.Preset, row.wantPreset)
	}
	if row.wantNote != "" && !strings.Contains(strings.Join(plan.Notes, "\n"), row.wantNote) {
		t.Errorf("notes %q lack %q", plan.Notes, row.wantNote)
	}
	comparePlanWithCertificate(t, plan, out, chain)
	if plan.CA != "issuing" || plan.Generation != 1 {
		t.Errorf("CA %q generation %d", plan.CA, plan.Generation)
	}
}

// checkPlanChecks: the problems of the checks, concatenated, are the reasons;
// a plan stopped at a gate ends with that gate and says it is not collected.
func checkPlanChecks(t *testing.T, plan *Plan) {
	t.Helper()
	var joined []string
	for _, c := range plan.Checks {
		joined = append(joined, c.Problems...)
		if checkTitles[c.Name] == "" || c.Title() == "" {
			t.Errorf("check %q has no title", c.Name)
		}
	}
	if !slices.Equal(joined, plan.Reasons) {
		t.Errorf("the checks' problems %q are not the reasons %q", joined, plan.Reasons)
	}
	if plan.StoppedAt != "" {
		last := plan.Checks[len(plan.Checks)-1]
		if last.Name != plan.StoppedAt || last.Collected || len(last.Problems) == 0 {
			t.Errorf("stopped at %q but the last check is %+v", plan.StoppedAt, last)
		}
	} else if len(plan.Checks) < 5 || !plan.Checks[len(plan.Checks)-1].Collected {
		t.Errorf("a plan that ran through ends with the collected checks: %+v", plan.Checks)
	}
	for _, c := range plan.Checks {
		if want := slices.Contains([]string{CheckNames, CheckConstraints, CheckEKULimit, CheckValidity, CheckRenewal}, c.Name); c.Collected != want {
			t.Errorf("check %q: collected %v, want %v", c.Name, c.Collected, want)
		}
	}
}

// comparePlanWithCertificate: what the plan says is what the certificate has.
func comparePlanWithCertificate(t *testing.T, plan *Plan, out *Issued, chain []*fixtureCA) {
	t.Helper()
	cert := parse(t, out.CertDER)
	if got := cert.Subject.String(); got != plan.SubjectDN {
		t.Errorf("subject %q, plan %q", got, plan.SubjectDN)
	}
	if cert.Subject.CommonName != plan.Subject.CommonName || first(cert.Subject.Organization) != plan.Subject.Organization ||
		first(cert.Subject.Country) != plan.Subject.Country {
		t.Errorf("subject fields %v, plan %+v", cert.Subject, plan.Subject)
	}
	var names []string
	for _, n := range cert.DNSNames {
		names = append(names, "dns:"+n)
	}
	for _, ip := range cert.IPAddresses {
		names = append(names, "ip:"+ip.String())
	}
	for _, e := range cert.EmailAddresses {
		names = append(names, "email:"+e)
	}
	for _, u := range cert.URIs {
		names = append(names, "uri:"+u.String())
	}
	var planned []string
	for _, n := range plan.Names {
		planned = append(planned, n.Type+":"+n.Value)
	}
	if !slices.Equal(names, planned) {
		t.Errorf("names %q, plan %q", names, planned)
	}
	if !cert.NotBefore.Equal(plan.NotBefore) || !cert.NotAfter.Equal(plan.NotAfter) {
		t.Errorf("validity %s – %s, plan %s – %s", cert.NotBefore, cert.NotAfter, plan.NotBefore, plan.NotAfter)
	}
	if want := plan.GeneratedAt.Add(-Backdate); plan.NotBefore.Before(want) {
		t.Errorf("notBefore %s is before the clock minus the backdate (%s)", plan.NotBefore, want)
	}
	if plan.Days <= 0 || plan.MaxValidityDays <= 0 {
		t.Errorf("days %d, CA maximum %d", plan.Days, plan.MaxValidityDays)
	}
	if got := keyUsageNames(cert.KeyUsage); !slices.Equal(got, plan.KeyUsage) {
		t.Errorf("key usage %q, plan %q", got, plan.KeyUsage)
	}

	// Extended key usage: names, order and criticality.
	var ekus []string
	critical := false
	if ext, ok := findExt(cert, oidExtKeyUsage); ok {
		var oids []asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(ext.Value, &oids); err != nil {
			t.Fatal(err)
		}
		for _, oid := range oids {
			ekus = append(ekus, ekuName(oid))
		}
		critical = ext.Critical
	}
	if !slices.Equal(ekus, plan.ExtKeyUsage) || critical != plan.ExtKeyUsageCritical {
		t.Errorf("EKU %q critical %v, plan %q critical %v", ekus, critical, plan.ExtKeyUsage, plan.ExtKeyUsageCritical)
	}

	// The extension list: the same OIDs with the same criticality. A new
	// extension in buildTemplate that describeExtensions misses fails here.
	want, got := map[string]bool{}, map[string]bool{}
	for _, e := range cert.Extensions {
		want[e.Id.String()] = e.Critical
	}
	for _, e := range plan.Extensions {
		if _, dup := got[e.OID]; dup {
			t.Errorf("extension %s listed twice", e.OID)
		}
		got[e.OID] = e.Critical
		if e.Name == "other" {
			t.Errorf("extension %s is not described", e.OID)
		}
	}
	if !maps.Equal(want, got) {
		t.Errorf("extensions\n cert: %v\n plan: %v", want, got)
	}
	for _, e := range plan.Extensions {
		switch e.Name {
		case "subjectKeyIdentifier":
			if out.KeyID == "" && e.Detail != strings.ToUpper(hex.EncodeToString(cert.SubjectKeyId)) {
				t.Errorf("SKI %q, certificate %X", e.Detail, cert.SubjectKeyId)
			}
			if out.KeyID != "" && !strings.Contains(e.Detail, "derived from the new key") {
				t.Errorf("a server-side key has no SKI yet, the plan says %q", e.Detail)
			}
		case "authorityKeyIdentifier":
			if e.Detail != strings.ToUpper(hex.EncodeToString(cert.AuthorityKeyId)) {
				t.Errorf("AKI %q, certificate %X", e.Detail, cert.AuthorityKeyId)
			}
		}
	}
	if len(cert.IssuingCertificateURL) != 1 || cert.IssuingCertificateURL[0] != plan.AIAURL ||
		len(cert.CRLDistributionPoints) != 1 || cert.CRLDistributionPoints[0] != plan.CDPURL {
		t.Errorf("AIA %v CDP %v, plan %q %q", cert.IssuingCertificateURL, cert.CRLDistributionPoints, plan.AIAURL, plan.CDPURL)
	}

	// Chain: the issuing CA first, the root last, the fingerprints of the stored certificates.
	if len(plan.Chain) != len(out.Chain) || len(plan.Chain) != len(chain) {
		t.Fatalf("chain of %d links, issued chain %d", len(plan.Chain), len(out.Chain))
	}
	for i, link := range plan.Chain {
		if link.SHA256 != fingerprint(out.Chain[i]) || link.Root != (i == len(plan.Chain)-1) {
			t.Errorf("chain link %d: %+v, want fingerprint %s", i, link, fingerprint(out.Chain[i]))
		}
		if c := parse(t, out.Chain[i]); link.Subject != c.Subject.String() || !link.NotAfter.Equal(c.NotAfter) {
			t.Errorf("chain link %d: %+v, certificate %s until %s", i, link, c.Subject, c.NotAfter)
		}
	}
	if cert.Issuer.String() != plan.Chain[0].Subject {
		t.Errorf("issuer %s, first link %s", cert.Issuer, plan.Chain[0].Subject)
	}

	wantSource := "csr"
	if out.KeyID != "" {
		wantSource = "server"
	}
	if plan.KeySource != wantSource || plan.KeyAlgorithm != out.KeyAlgorithm {
		t.Errorf("key %s %s, issued %s %s", plan.KeySource, plan.KeyAlgorithm, wantSource, out.KeyAlgorithm)
	}
	if !slices.Equal(plan.Notes, out.Notes) || !slices.Equal(plan.Warnings, out.Warnings) || !slices.Equal(plan.DroppedCSRNames, out.DroppedCSRNames) {
		t.Errorf("notes %q warnings %q dropped %q, issued %q %q %q", plan.Notes, plan.Warnings, plan.DroppedCSRNames, out.Notes, out.Warnings, out.DroppedCSRNames)
	}
}

// Every built-in preset, with a CSR key and a server-side key: the plan lists
// the extensions its certificate carries.
func TestPlanEquivalenceEveryPreset(t *testing.T) {
	v := newEnv(t)
	root, issuing := v.chain(t, caOpts{permitDNS: []string{"homelab.lan"}, permitIP: []string{"10.0.0.0/8"}})
	for _, name := range v.e.Presets.Names() {
		for _, source := range []string{"csr", "server"} {
			t.Run(name+"/"+source, func(t *testing.T) {
				req := presetRequests[name]
				req.CA, req.Preset = "issuing", name
				if source == "csr" {
					req.CSR = makeCSR(t, mustKey(t, elliptic.P256()), &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored when the request has a CN"}})
				}
				v.checkEquivalence(t, planRow{wantPreset: name}, req, []*fixtureCA{issuing, root})
			})
		}
	}
}

// A refused plan lists every reason of the collected checks together; a gate
// ends the plan and says so.
func TestPlanCollectsAndLabelsReasons(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.chain(t, caOpts{permitDNS: []string{"homelab.lan"}, maxValidity: 100})
	plan, err := v.planSilently(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"evil.example", "Bad_Name.homelab.lan"},
		ValidityDays: 200, RenewalOf: "crt-none"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Allowed || plan.StoppedAt != "" {
		t.Fatalf("allowed %v, stopped at %q", plan.Allowed, plan.StoppedAt)
	}
	problems := map[string]int{}
	for _, c := range plan.Checks {
		problems[c.Name] = len(c.Problems)
	}
	for _, name := range []string{CheckNames, CheckConstraints, CheckValidity, CheckRenewal} {
		if problems[name] == 0 {
			t.Errorf("the collected check %q found nothing: %v", name, problems)
		}
	}
	if problems[CheckPreset]+problems[CheckCA]+problems[CheckKey] != 0 {
		t.Errorf("gates that passed list problems: %v", problems)
	}
	// The same list, in the same order, is what issuance refuses with.
	_, ierr := v.e.Issue(t.Context(), Request{CA: "issuing", Preset: "server", DNSNames: []string{"evil.example", "Bad_Name.homelab.lan"},
		ValidityDays: 200, RenewalOf: "crt-none", Who: tester})
	var d *DeniedError
	if !errors.As(ierr, &d) || !slices.Equal(d.Reasons, plan.Reasons) || len(d.Reasons) < 4 {
		t.Fatalf("issue %v, plan reasons %q", ierr, plan.Reasons)
	}

	// A gate: nothing after it ran, and the plan says it stopped there.
	gate, err := v.planSilently(t, Request{CA: "issuing", Preset: "nope", DNSNames: []string{"evil.example"}})
	if err != nil {
		t.Fatal(err)
	}
	if gate.StoppedAt != CheckPreset || len(gate.Reasons) != 1 || gate.Checks[len(gate.Checks)-1].Collected {
		t.Errorf("gate: %+v", gate)
	}
	for _, c := range gate.Checks {
		if c.Name == CheckNames {
			t.Errorf("a check after the gate ran: %+v", gate.Checks)
		}
	}
}

// What a plan must not do or give: permissions are the engine's, nothing is
// audited (not even a refusal), and the clock decides notBefore.
func TestPlanPermissionsAuditAndClock(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.chain(t, caOpts{permitDNS: []string{"homelab.lan"}})
	req := Request{CA: "issuing", Preset: "server", DNSNames: []string{"nas.homelab.lan"}}

	// A viewer, and a caller without a principal, get the error Issue gives –
	// not a plan – and nothing is written.
	for name, who := range map[string]keys.Who{
		"viewer":       signedIn("view", time.Time{}, authz.Binding{Role: authz.Viewer}),
		"no principal": {Actor: tester.Actor},
	} {
		r := req
		r.Who = who
		plan, err := v.planSilently(t, r)
		var d *DeniedError
		if plan != nil || !errors.As(err, &d) || d.Cause == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("%s: plan %v, error %v", name, plan, err)
		}
	}
	// An operator of another CA may not see this CA's plan either.
	other := signedIn("op", time.Time{}, authz.Binding{CA: "elsewhere", Role: authz.Operator})
	r := req
	r.Who = other
	if plan, err := v.planSilently(t, r); plan != nil || !errors.Is(err, authz.ErrDenied) {
		t.Errorf("operator of another CA: %v %v", plan, err)
	}

	// Refusals and failures leave no audit entry; a sealed plan neither.
	if rows := v.auditRows(t); len(rows) != 0 {
		t.Errorf("audit entries after plans: %+v", rows)
	}

	// notBefore follows the injectable clock: now minus the backdate.
	v.clk.Advance(36*time.Hour + 17*time.Second + 500*time.Millisecond)
	plan, err := v.planSilently(t, req)
	if err != nil || !plan.Allowed {
		t.Fatalf("plan: %+v %v", plan, err)
	}
	now := v.clk.Now().UTC().Truncate(time.Second)
	if !plan.GeneratedAt.Equal(now) || !plan.NotBefore.Equal(now.Add(-Backdate)) || !plan.NotAfter.Equal(plan.NotBefore.Add(time.Duration(plan.Days)*day-time.Second)) {
		t.Errorf("generated %s, validity %s – %s (%d days), clock %s", plan.GeneratedAt, plan.NotBefore, plan.NotAfter, plan.Days, now)
	}
	out := v.issue(t, req)
	if !out.NotBefore.Equal(plan.NotBefore) || !out.NotAfter.Equal(plan.NotAfter) {
		t.Errorf("issued %s – %s, plan %s – %s", out.NotBefore, out.NotAfter, plan.NotBefore, plan.NotAfter)
	}
}

// An ACME order goes through the same plan: CA, preset and validity come from
// the domains, and the plan names the domain that applied.
func TestPlanEquivalenceACMEOrder(t *testing.T) {
	t.Parallel()
	v := domainEnv(t)
	if _, err := v.e.CreateDomain(t.Context(), DomainRequest{Name: "homelab.lan", DomainSettings: DomainSettings{CA: ptr("issuing"), IPRanges: []string{"10.1.0.0/16"}, ValidityDays: ptr(30)}, Who: tester}); err != nil {
		t.Fatal(err)
	}
	ran := false
	mk := func(dns, ips []string) Request {
		return Request{CSR: acmeCSR(t, []string{"ignored.example"}, nil), DNSNames: dns, IPAddresses: ips, Who: acmeWho,
			ACME: &ACMEOrder{OrderID: "ord-1", AccountID: "acc-1", Stored: func(context.Context, *sql.Tx, *Issued) error { ran = true; return nil }}}
	}

	// A plan does not run the callbacks that store an order.
	req := mk([]string{"NAS.homelab.lan"}, []string{"10.1.2.3"})
	plan, err := v.planSilently(t, req)
	if err != nil || ran {
		t.Fatalf("plan: %v, stored callback ran: %v", err, ran)
	}
	if !plan.Allowed || plan.CA != "issuing" || plan.Preset != "server" || !slices.Equal(plan.Domains, []string{"homelab.lan"}) || plan.Days != 30 {
		t.Fatalf("plan %+v", plan)
	}
	out, err := v.e.Issue(t.Context(), req)
	if err != nil || !ran {
		t.Fatalf("issue: %v (stored %v)", err, ran)
	}
	cert := parse(t, out.CertDER)
	if !slices.Equal(cert.DNSNames, []string{"nas.homelab.lan"}) || len(cert.IPAddresses) != 1 || !cert.NotBefore.Equal(plan.NotBefore) || !cert.NotAfter.Equal(plan.NotAfter) {
		t.Errorf("certificate %v %v %s %s, plan %+v", cert.DNSNames, cert.IPAddresses, cert.NotBefore, cert.NotAfter, plan)
	}
	if got := fingerprint(out.Chain[0]); got != plan.Chain[0].SHA256 {
		t.Errorf("chain %s, plan %s", got, plan.Chain[0].SHA256)
	}

	// Refusals of an order: the same reasons.
	for name, r := range map[string]Request{
		"no domain":  mk([]string{"nas.elsewhere.example"}, nil),
		"CA by hand": func() Request { r := mk([]string{"nas.homelab.lan"}, nil); r.CA = "open"; return r }(),
		"no names":   mk(nil, nil),
	} {
		p, perr := v.planSilently(t, r)
		if perr != nil {
			t.Fatalf("%s: %v", name, perr)
		}
		_, ierr := v.e.Issue(t.Context(), r)
		var d *DeniedError
		if !errors.As(ierr, &d) || p.Allowed || !slices.Equal(p.Reasons, d.Reasons) || p.StoppedAt != CheckACMEOrder {
			t.Errorf("%s: plan %+v, issue %v", name, p, ierr)
		}
	}
}

// The template has no serial and tolerates a missing key: both are drawn by commit.
func TestBuildTemplateDrawsNothing(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.chain(t, caOpts{})
	is, err := loadIssuer(t.Context(), pkidb.New(v.pki), "issuing")
	if err != nil {
		t.Fatal(err)
	}
	p, _ := v.e.Presets.Get("server")
	l := leaf{preset: p, alg: AlgECDSAP256, subject: pkix.Name{CommonName: "a.homelab.lan"}, names: Names{DNS: []string{"a.homelab.lan"}},
		v: computeValidity(t0, 0, p.ValidityDays, 825, is.certs[0].NotBefore, is.certs[0].NotAfter)}
	tmpl, err := buildTemplate(is, l)
	if err != nil {
		t.Fatal(err)
	}
	if tmpl.SerialNumber != nil || tmpl.SubjectKeyId != nil {
		t.Errorf("template without a key: serial %v, SKI %x", tmpl.SerialNumber, tmpl.SubjectKeyId)
	}
	l.pub = &mustKey(t, elliptic.P256()).PublicKey
	if tmpl, err = buildTemplate(is, l); err != nil || len(tmpl.SubjectKeyId) != 20 {
		t.Errorf("template with a key: %v %x", err, tmpl.SubjectKeyId)
	}
}

// Two plans of the same request agree, and the order of the random draws of an
// issuance is what it always was: the key first, then the serial. An Ed25519
// key reads exactly 32 bytes, so the serial is the next draw of the stream.
func TestPlanIsRepeatableAndIssuanceDrawsKeyThenSerial(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.chain(t, caOpts{})
	req := Request{CA: "issuing", Preset: "server", KeyAlgorithm: AlgEd25519, DNSNames: []string{"a.homelab.lan"}}
	a, err := v.planSilently(t, req)
	if err != nil {
		t.Fatal(err)
	}
	b, err := v.planSilently(t, req)
	if err != nil || len(a.Extensions) != len(b.Extensions) || !a.NotBefore.Equal(b.NotBefore) || !slices.Equal(a.Names, b.Names) {
		t.Fatalf("plans differ: %+v %+v %v", a, b, err)
	}

	v.e.Rand = &stream{}
	out := v.issue(t, req)
	v.e.Rand = nil
	replay := &stream{}
	if _, rerr := io.ReadFull(replay, make([]byte, ed25519.SeedSize)); rerr != nil {
		t.Fatal(rerr)
	}
	want, err := newSerial(replay)
	if err != nil {
		t.Fatal(err)
	}
	if out.SerialHex != SerialHex(want) {
		t.Errorf("serial %s, want %s (the draw right after the key)", out.SerialHex, SerialHex(want))
	}
}

// stream is a deterministic byte stream for the order-of-draws test.
type stream struct{ n byte }

func (s *stream) Read(p []byte) (int, error) {
	for i := range p {
		s.n = s.n*31 + 7
		p[i] = s.n
	}
	return len(p), nil
}
