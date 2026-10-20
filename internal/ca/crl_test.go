package ca

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/ids"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

func parseCRL(t *testing.T, der []byte) *x509.RevocationList {
	t.Helper()
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	return crl
}

// idpURLs reads the fullName URIs of a CRL's issuingDistributionPoint.
func idpURLs(t *testing.T, crl *x509.RevocationList) ([]string, bool) {
	t.Helper()
	for _, e := range crl.Extensions {
		if !e.Id.Equal(oidIssuingDistributionPoint) {
			continue
		}
		var idp struct {
			DP struct {
				FullName []asn1.RawValue `asn1:"optional,tag:0"`
			} `asn1:"optional,tag:0"`
		}
		if _, err := asn1.Unmarshal(e.Value, &idp); err != nil {
			t.Fatal(err)
		}
		var urls []string
		for _, n := range idp.DP.FullName {
			urls = append(urls, string(n.Bytes))
		}
		return urls, e.Critical
	}
	return nil, false
}

func (v *env) revoke(t *testing.T, id, reason string) *RevokeResult {
	t.Helper()
	r, err := v.e.Revoke(t.Context(), RevokeRequest{CertificateID: id, Reason: reason, Who: tester})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	return r
}

func TestRevocationIsPublishedInTheCRL(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	root, issuing := v.chain(t, caOpts{})
	good := v.issue(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"a.homelab.lan"}})
	bad := v.issue(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"b.homelab.lan"}})

	res := v.revoke(t, bad.ID, ReasonSuperseded)
	if !res.Published || res.CRL == nil || res.CRL.Number != 1 || res.CRL.Entries != 1 || len(res.Warnings) != 0 {
		t.Fatalf("revoke: %+v", res)
	}
	crl := parseCRL(t, res.CRL.DER)
	if crl.Number.Int64() != 1 || !slices.Equal(crl.AuthorityKeyId, issuing.cert.SubjectKeyId) || crl.CheckSignatureFrom(issuing.cert) != nil {
		t.Error("CRL: number 1, AKI = SKI of the issuing generation, signed by it")
	}
	if !crl.ThisUpdate.Equal(t0.Add(-Backdate)) || !crl.NextUpdate.Equal(t0.Add(7*day)) {
		t.Errorf("CRL times %v – %v", crl.ThisUpdate, crl.NextUpdate)
	}
	if len(crl.RevokedCertificateEntries) != 1 || SerialHex(crl.RevokedCertificateEntries[0].SerialNumber) != bad.SerialHex ||
		crl.RevokedCertificateEntries[0].ReasonCode != 4 {
		t.Errorf("entries %+v", crl.RevokedCertificateEntries)
	}
	// No issuingDistributionPoint: with it, OpenSSL refuses the CRL for
	// certificates without a CRL distribution point ("different CRL scope") –
	// the test fixture's intermediate has none, like legacy certificates
	// issued without AIA_BASE_URL. -crl_check_all below proves they work.
	if urls, _ := idpURLs(t, crl); urls != nil {
		t.Errorf("unexpected issuingDistributionPoint %v", urls)
	}

	// The root's CRL comes from the maintainer (it was missing).
	signed, err := v.e.RenewCRLs(t.Context(), "test")
	if err != nil || len(signed) != 1 || signed[0].CA != "root" {
		t.Fatalf("renew: %+v %v", signed, err)
	}
	crls := [][]byte{res.CRL.DER, signed[0].DER}
	chain := [][]byte{issuing.cert.Raw, root.cert.Raw}
	text := opensslText(t, "crl", res.CRL.DER)
	for _, want := range []string{"Superseded", "CRL Number", "Authority Key Identifier"} {
		if !strings.Contains(text, want) {
			t.Errorf("openssl crl -text lacks %q:\n%s", want, text)
		}
	}
	for _, flags := range [][]string{{"-crl_check"}, {"-crl_check_all"}, {"-crl_check_all", "-extended_crl"}} {
		if out, ok := opensslWithCRLs(t, t0, chain, crls, good.CertDER, flags...); !ok {
			t.Errorf("good leaf with %v:\n%s", flags, out)
		}
		if out, ok := opensslWithCRLs(t, t0, chain, crls, bad.CertDER, flags...); ok || !strings.Contains(out, "certificate revoked") {
			t.Errorf("revoked leaf with %v:\n%s", flags, out)
		}
	}

	actions := map[string]int{}
	for _, row := range v.auditRows(t) {
		actions[row.action+"/"+row.result]++
	}
	if actions["certificate.revoke/success"] != 1 || actions["crl.sign/success"] != 2 {
		t.Errorf("audit %v", actions)
	}
}

func TestRevocationRules(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.chain(t, caOpts{})
	out := v.issue(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"a.homelab.lan"}})
	future := t0.Add(day)
	for want, req := range map[string]RevokeRequest{
		"there is no certificateHold":  {CertificateID: out.ID, Reason: "certificateHold"},
		"only goes with keyCompromise": {CertificateID: out.ID, Reason: ReasonSuperseded, InvalidityDate: &t0},
		"in the future":                {CertificateID: out.ID, Reason: ReasonKeyCompromise, InvalidityDate: &future},
		"not allowed":                  {CertificateID: out.ID, Reason: ReasonCACompromise},
	} {
		req.Who = tester
		_, err := v.e.Revoke(t.Context(), req)
		if got := deniedErr(t, err); !strings.Contains(got, want) {
			t.Errorf("%q, want %q", got, want)
		}
	}
	// An unknown ID is "not found", like one the caller may not read.
	if _, err := v.e.Revoke(t.Context(), RevokeRequest{CertificateID: "crt_nope", Reason: ReasonSuperseded, Who: tester}); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown certificate: %v", err)
	}
	v.revoke(t, out.ID, ReasonCessationOfOperation)
	if _, err := v.e.Revoke(t.Context(), RevokeRequest{CertificateID: out.ID, Reason: ReasonSuperseded, Who: tester}); !strings.Contains(deniedErr(t, err), "final") {
		t.Error("revoked twice")
	}
	if _, err := v.e.RevokeCA(t.Context(), RevokeCARequest{Name: "root", Reason: ReasonCACompromise, Who: tester}); !strings.Contains(deniedErr(t, err), "a root can't be revoked") {
		t.Error("revoked a root")
	}
	for _, s := range []string{`DELETE FROM revocations`, `UPDATE revocations SET reason = 'superseded'`, `DELETE FROM crls`, `UPDATE crls SET number = 99`} {
		if _, err := v.pki.ExecContext(t.Context(), s); err == nil {
			t.Errorf("%s: allowed", s)
		}
	}
}

func TestKeyCompromiseBlocksTheKey(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	root, issuing := v.chain(t, caOpts{})
	leafKey := mustKey(t, elliptic.P256())
	v.addCA(t, "other", caOpts{parent: root})
	csr := makeCSR(t, leafKey, &x509.CertificateRequest{DNSNames: []string{"a.homelab.lan"}})
	out := v.issue(t, Request{CA: "issuing", Preset: "server", CSR: csr})
	inv := t0.Add(-time.Hour)
	if _, err := v.e.Revoke(t.Context(), RevokeRequest{CertificateID: out.ID, Reason: ReasonKeyCompromise, InvalidityDate: &inv, Who: tester}); err != nil {
		t.Fatal(err)
	}
	// The same key in a new CSR – for any CA of the tenant – is refused.
	for _, ca := range []string{"issuing", "other"} {
		if got := v.denied(t, Request{CA: ca, Preset: "server", CSR: makeCSR(t, leafKey, &x509.CertificateRequest{DNSNames: []string{"b.homelab.lan"}})}); !strings.Contains(got, "reported compromised (keyCompromise, certificate") {
			t.Errorf("%s: %q", ca, got)
		}
	}
	latest, _ := pkidb.New(v.pki).GetLatestCRL(t.Context(), pkidb.GetLatestCRLParams{CaID: issuing.id, Generation: 1})
	if e := parseCRL(t, latest.CrlDer).RevokedCertificateEntries[0]; e.ReasonCode != 1 || !hasExt(e.Extensions, oidInvalidityDate) {
		t.Errorf("keyCompromise entry: reason %d, extensions %v", e.ReasonCode, e.Extensions)
	}

	// cACompromise blocks the CA key and stops everything below the CA.
	res, err := v.e.RevokeCA(t.Context(), RevokeCARequest{Name: "issuing", Reason: ReasonCACompromise, Who: tester})
	if err != nil || !res.Published || !strings.Contains(strings.Join(res.Warnings, "|"), "can't issue any more") {
		t.Fatalf("revoke CA: %+v %v", res, err)
	}
	if e := parseCRL(t, res.CRL.DER).RevokedCertificateEntries; len(e) != 1 || e[0].ReasonCode != 2 || e[0].SerialNumber.Cmp(issuing.cert.SerialNumber) != 0 {
		t.Errorf("root CRL entries %+v", e)
	}
	if got := v.denied(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"c.homelab.lan"}}); !strings.Contains(got, "is revoked") {
		t.Errorf("issue below a revoked CA: %q", got)
	}
	if got := v.denied(t, Request{CA: "other", Preset: "server", CSR: makeCSR(t, issuing.key, &x509.CertificateRequest{DNSNames: []string{"d.homelab.lan"}})}); !strings.Contains(got, "cACompromise") {
		t.Errorf("CSR with the compromised CA key: %q", got)
	}
	_ = root
}

func hasExt(exts []pkix.Extension, oid asn1.ObjectIdentifier) bool {
	for _, e := range exts {
		if e.Id.Equal(oid) {
			return true
		}
	}
	return false
}

func TestRevocationWhileSealedIsPublishedAtUnseal(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.chain(t, caOpts{})
	out := v.issue(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"a.homelab.lan"}})
	v.e.Keys = keys.New(nil, nil, v.clk) // sealed

	res := v.revoke(t, out.ID, ReasonKeyCompromise)
	if res.Published || res.CRL != nil || !strings.Contains(strings.Join(res.Warnings, "|"), "sealed") {
		t.Fatalf("sealed revocation: %+v", res)
	}
	status := func() CRLStatus {
		t.Helper()
		all, err := CRLStatuses(t.Context(), v.pki, v.clk.Now())
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range all {
			if s.CA == "issuing" {
				return s
			}
		}
		t.Fatal("no status for issuing")
		return CRLStatus{}
	}
	if s := status(); s.Unpublished != 1 || !strings.Contains(s.Message(true), "1 revocation(s) not yet published") || !strings.Contains(s.Message(true), "sealed") {
		t.Errorf("status while sealed: %+v %q", s, s.Message(true))
	}
	if _, err := v.e.RenewCRLs(t.Context(), "timer"); !errors.Is(err, keys.ErrSealed) {
		t.Errorf("renewal while sealed: %v", err)
	}

	v.e.Keys = unsealed // unseal
	if signed, err := v.e.RenewCRLs(t.Context(), "unseal"); err != nil || len(signed) != 2 {
		t.Fatalf("at unseal: %+v %v", signed, err)
	}
	if s := status(); s.Unpublished != 0 || s.State != CRLOK || s.Message(false) != "" {
		t.Errorf("after unseal: %+v %q", s, s.Message(false))
	}
}

func TestCRLNumbersAndRenewalTiming(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	// A new online CA comes with CRL number 1 (root 30 days, issuing 7).
	for _, res := range []*CAResult{v.root(t, "root", nil), v.intermediate(t, "issuing", "root", nil)} {
		if c := res.CRL; c == nil || c.Number != 1 || c.Generation != 1 || c.Entries != 0 || !c.NextUpdate.After(v.clk.Now()) {
			t.Errorf("%s: first CRL %+v", res.Name, c)
		}
	}
	renew := func(want int) []CRLResult {
		t.Helper()
		got, err := v.e.RenewCRLs(t.Context(), "timer")
		if err != nil || len(got) != want {
			t.Fatalf("renew at %v: %d CRLs, want %d (%v)", v.clk.Now(), len(got), want, err)
		}
		return got
	}
	renew(0) // both fresh
	v.clk.Advance(2 * day)
	renew(0) // less than a third of 7 days
	v.clk.Advance(12 * time.Hour)
	if got := renew(1); got[0].CA != "issuing" || got[0].Number != 2 {
		t.Errorf("issuing after 2.5 days: %+v", got)
	}

	// A renewal of the CA adds generation 2 with its first CRL at once: it
	// continues the CA's numbers.
	res, err := v.e.RenewCA(t.Context(), RenewRequest{Name: "issuing", Who: tester})
	if err != nil {
		t.Fatal(err)
	}
	if c := res.CRL; c == nil || c.Generation != 2 || c.Number != 3 || parseCRL(t, c.DER).CheckSignatureFrom(parse(t, res.CertDER)) != nil {
		t.Errorf("generation 2: %+v", c)
	}
	renew(0)
	// Without renewals: warning from half of the lifetime, then expired.
	states := func() map[string]string {
		all, _ := CRLStatuses(t.Context(), v.pki, v.clk.Now())
		m := map[string]string{}
		for _, s := range all {
			m[s.CA+"/"+itoa(s.Generation)] = s.State
		}
		return m
	}
	v.clk.Advance(4 * day)
	if s := states(); s["issuing/2"] != CRLWarning || s["issuing/1"] != CRLWarning || s["root/1"] != CRLOK {
		t.Errorf("after 4 days: %v", s)
	}
	v.clk.Advance(4 * day)
	if s := states(); s["issuing/2"] != CRLExpired {
		t.Errorf("after 8 days: %v", s)
	}
}

// TestExpiredEntriesStayForOneCRLCycle: RFC 5280 §3.3 – an entry stays until
// it was on a regular CRL after the certificate expired: notAfter + crl_days.
func TestExpiredEntriesStayForOneCRLCycle(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	_, issuing := v.chain(t, caOpts{})
	out := v.issue(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"a.homelab.lan"}, ValidityDays: 30})
	v.revoke(t, out.ID, ReasonSuperseded)
	entries := func(at time.Time) int {
		t.Helper()
		v.clk.Set(at)
		res, err := v.e.SignCRL(t.Context(), issuing.id, 1, "test", tester)
		if err != nil {
			t.Fatal(err)
		}
		return res.Entries
	}
	if n := entries(out.NotAfter.Add(time.Hour)); n != 1 {
		t.Errorf("right after expiry: %d entries", n)
	}
	if n := entries(out.NotAfter.Add(7*day - time.Hour)); n != 1 {
		t.Errorf("before notAfter + crl_days: %d entries", n)
	}
	if n := entries(out.NotAfter.Add(7*day + time.Hour)); n != 0 {
		t.Errorf("after notAfter + crl_days: %d entries", n)
	}
}

// rootCRL signs a CRL as an offline root would.
func rootCRL(t *testing.T, r *offlineRoot, number int64, this, next time.Time, revoked []x509.RevocationListEntry, extra ...pkix.Extension) []byte {
	t.Helper()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(number), ThisUpdate: this, NextUpdate: next, RevokedCertificateEntries: revoked, ExtraExtensions: extra,
	}, r.cert, r.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestUploadOfflineRootCRL(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	off := newOfflineRoot(t, "Offline Root", t0.Add(-day))
	v.importRoot(t, "offline-root", off)
	nc := NameConstraints{}
	ir := v.intermediate(t, "issuing", "offline-root", nil)
	if _, err := v.e.InstallCACertificate(t.Context(), "issuing", off.sign(t, ir.Offline, nc, nil), tester); err != nil {
		t.Fatal(err)
	}
	inter := parse(t, mustGen(t, v, ir.ID, 1).CertDer)
	upload := func(data []byte) ([]string, error) {
		t.Helper()
		_, w, err := v.e.UploadCRL(t.Context(), "offline-root", data, tester)
		return w, err
	}

	if s := offlineStatus(t, v); s.State != CRLMissing || !strings.Contains(s.Message(false), "upload") {
		t.Errorf("before upload: %+v", s)
	}
	first := rootCRL(t, off, 4096, t0.Add(-time.Hour), t0.Add(180*day), nil)
	w, err := upload(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: first}))
	if err != nil || !strings.Contains(strings.Join(w, "|"), "before") {
		t.Fatalf("upload: %v %v", w, err)
	}
	other := newOfflineRoot(t, "Other Root", t0.Add(-day))
	for want, data := range map[string][]byte{
		"not higher than the newest one (4096)": first,
		"not signed by any generation":          rootCRL(t, other, 5000, t0.Add(-time.Hour), t0.Add(day), nil),
		"has passed already":                    rootCRL(t, off, 5001, t0.Add(-2*day), t0.Add(-day), nil),
		"in the future":                         rootCRL(t, off, 5002, t0.Add(time.Hour), t0.Add(day), nil),
		"delta CRL":                             rootCRL(t, off, 5003, t0.Add(-time.Hour), t0.Add(day), nil, pkix.Extension{Id: oidDeltaCRLIndicator, Critical: true, Value: []byte{2, 1, 1}}),
		"can't be parsed":                       []byte("not a crl"),
	} {
		if _, uerr := upload(data); !strings.Contains(deniedErr(t, uerr), want) {
			t.Errorf("want %q: %v", want, err)
		}
	}
	if s := offlineStatus(t, v); s.State != CRLOK || s.Number != 4096 || s.Source != "uploaded" {
		t.Errorf("after upload: %+v", s)
	}

	// The root revokes our intermediate: the next upload marks it.
	revoked := []x509.RevocationListEntry{{SerialNumber: inter.SerialNumber, RevocationTime: t0, ReasonCode: 2}}
	w, err = upload(rootCRL(t, off, 4097, t0.Add(-time.Hour), t0.Add(180*day), revoked))
	if err != nil || !strings.Contains(strings.Join(w, "|"), "can't issue any more") {
		t.Fatalf("upload with a revoked intermediate: %v %v", w, err)
	}
	if got := v.denied(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"a.homelab.lan"}}); !strings.Contains(got, "is revoked") {
		t.Errorf("issue below the revoked intermediate: %q", got)
	}
	if _, err := pkidb.New(v.pki).GetBlockedKey(t.Context(), mustSPKI(t, inter)); err != nil {
		t.Errorf("cACompromise must block the intermediate's key: %v", err)
	}

	v.clk.Advance(100 * day)
	if s := offlineStatus(t, v); s.State != CRLWarning || !strings.Contains(s.Message(false), "offline root and upload it") {
		t.Errorf("past half of the lifetime: %+v %q", s, s.Message(false))
	}
}

func offlineStatus(t *testing.T, v *env) CRLStatus {
	t.Helper()
	all, err := CRLStatuses(t.Context(), v.pki, v.clk.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range all {
		if s.CA == "offline-root" {
			return s
		}
	}
	t.Fatal("no status for offline-root")
	return CRLStatus{}
}

func mustGen(t *testing.T, v *env, caID string, gen int64) pkidb.CaGeneration {
	t.Helper()
	g, err := pkidb.New(v.pki).GetCAGeneration(t.Context(), pkidb.GetCAGenerationParams{CaID: caID, Generation: gen})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func mustSPKI(t *testing.T, c *x509.Certificate) string {
	t.Helper()
	h, err := spkiHash(c.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestCRLStateThresholds(t *testing.T) {
	t.Parallel()
	this := t0
	next := t0.Add(9 * day)
	for elapsed, want := range map[time.Duration]string{
		2 * day: CRLOK, 3 * day: CRLRenewDue, 4*day + 12*time.Hour: CRLWarning, 9 * day: CRLExpired,
	} {
		if got := crlState(this, next, this.Add(elapsed), true); got != want {
			t.Errorf("after %v: %s, want %s", elapsed, got, want)
		}
	}
	if got := crlState(this, next, this.Add(3*day), false); got != CRLOK {
		t.Errorf("offline root after a third: %s – nobody here can renew it, so no renew_due", got)
	}
}

// TestImportedCertificatesKeepTheGenerationsCRL: a legacy-imported
// certificate may outlive its CA. The generation keeps signing CRLs until that
// certificate has expired plus crl_days (RFC 5280 §3.3), not only until its
// own notAfter.
func TestImportedCertificatesKeepTheGenerationsCRL(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	caEnd := t0.Add(60 * day)
	_, issuing := v.chain(t, caOpts{notAfter: caEnd})
	leafEnd := t0.Add(200 * day)
	id := v.importedLeaf(t, issuing, leafEnd)
	v.revoke(t, id, ReasonSuperseded)

	sign := func(at time.Time) (int, error) {
		t.Helper()
		v.clk.Set(at)
		all, err := CRLStatuses(t.Context(), v.pki, at)
		if err != nil {
			t.Fatal(err)
		}
		listed := slices.ContainsFunc(all, func(s CRLStatus) bool { return s.CA == "issuing" && s.Generation == 1 })
		res, err := v.e.SignCRL(t.Context(), issuing.id, 1, "test", tester)
		if (err == nil) != listed {
			t.Errorf("at %v: status listed %v, but SignCRL: %v", at, listed, err)
		}
		if err != nil {
			return 0, err
		}
		return res.Entries, nil
	}
	if n, err := sign(caEnd.Add(day)); err != nil || n != 1 {
		t.Errorf("CA expired, imported certificate still valid: %d entries, %v", n, err)
	}
	if n, err := sign(leafEnd.Add(7*day - time.Hour)); err != nil || n != 1 {
		t.Errorf("before the certificate's notAfter + crl_days: %d entries, %v", n, err)
	}
	if _, err := sign(leafEnd.Add(7*day + time.Hour)); !strings.Contains(deniedErr(t, err), "needs no CRL any more") {
		t.Errorf("after notAfter + crl_days: %v", err)
	}

	// Without such a certificate the generation's own notAfter counts.
	v2 := newEnv(t)
	_, plain := v2.chain(t, caOpts{notAfter: caEnd})
	v2.clk.Set(caEnd.Add(time.Hour))
	if _, err := v2.e.SignCRL(t.Context(), plain.id, 1, "test", tester); !strings.Contains(deniedErr(t, err), "needs no CRL any more") {
		t.Errorf("expired generation without certificates: %v", err)
	}
}

// importedLeaf stores a certificate as the legacy importer will: signed by
// generation 1 of issuer, valid until notAfter – possibly beyond the CA.
func (v *env) importedLeaf(t *testing.T, issuer *fixtureCA, notAfter time.Time) string {
	t.Helper()
	key := mustKey(t, elliptic.P256())
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x1e9ac7), Subject: pkix.Name{CommonName: "legacy.homelab.lan"},
		NotBefore: t0.Add(-day), NotAfter: notAfter, DNSNames: []string{"legacy.homelab.lan"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer.cert, key.Public(), issuer.key)
	if err != nil {
		t.Fatal(err)
	}
	cert := parse(t, der)
	id, err := ids.New("crt", v.clk.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := pkidb.New(v.pki).InsertCertificate(t.Context(), pkidb.InsertCertificateParams{
		ID: id, CaID: sql.NullString{String: issuer.id, Valid: true}, CaGeneration: sql.NullInt64{Int64: 1, Valid: true},
		Source: "imported", SerialHex: SerialHex(cert.SerialNumber), SubjectDn: cert.Subject.String(), CommonName: cert.Subject.CommonName,
		NotBefore: cert.NotBefore.UTC().Format(dbTime), NotAfter: cert.NotAfter.UTC().Format(dbTime), KeyAlgorithm: "ecdsa-p256",
		CertDer: der, FingerprintSha256: fingerprint(der), RequestedBy: "legacy import", CreatedAt: v.clk.Now().Format(dbTime),
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

// TestRootCRLHoldIsFinal: certificateHold on the offline root's CRL marks our
// intermediate as revoked for good, with a warning that says so.
func TestRootCRLHoldIsFinal(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	off := newOfflineRoot(t, "Offline Root", t0.Add(-day))
	v.importRoot(t, "offline-root", off)
	ir := v.intermediate(t, "issuing", "offline-root", nil)
	if _, err := v.e.InstallCACertificate(t.Context(), "issuing", off.sign(t, ir.Offline, NameConstraints{}, nil), tester); err != nil {
		t.Fatal(err)
	}
	inter := parse(t, mustGen(t, v, ir.ID, 1).CertDer)
	hold := []x509.RevocationListEntry{{SerialNumber: inter.SerialNumber, RevocationTime: t0, ReasonCode: reasonCodeCertificateHold}}
	_, w, err := v.e.UploadCRL(t.Context(), "offline-root", rootCRL(t, off, 1, t0.Add(-time.Hour), t0.Add(30*day), hold), tester)
	want := "certificateHold is not supported – for MyOwnPKI this CA is revoked for good"
	if err != nil || !strings.Contains(strings.Join(w, "|"), want) {
		t.Fatalf("upload with a hold: %v %v", w, err)
	}
	if r, rerr := pkidb.New(v.pki).GetCARevocation(t.Context(), pkidb.GetCARevocationParams{CaID: ir.ID, Generation: 1}); rerr != nil ||
		r.Reason != ReasonUnspecified {
		t.Errorf("recorded revocation: %+v %v", r, rerr)
	}

	// The root lifts the hold: the next CRL lacks the entry – still revoked.
	v.clk.Advance(day)
	now := v.clk.Now()
	if _, _, uerr := v.e.UploadCRL(t.Context(), "offline-root", rootCRL(t, off, 2, now.Add(-time.Hour), now.Add(30*day), nil), tester); uerr != nil {
		t.Fatal(uerr)
	}
	if got := v.denied(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"a.homelab.lan"}}); !strings.Contains(got, "is revoked") {
		t.Errorf("issue after the hold was lifted: %q", got)
	}
	noted := slices.ContainsFunc(v.auditRows(t), func(r auditRow) bool {
		note, _ := r.details["note"].(string)
		return r.action == ActionCARevoke && strings.Contains(note, want)
	})
	if !noted {
		t.Error("the audit entry of the revocation lacks the hold note")
	}
}
