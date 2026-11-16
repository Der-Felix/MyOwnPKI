package ca

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// Found by fuzzing: x509.ParseRevocationList ignores what follows the CRL, and uploadCRL stored and served the
// DER as it came – so the signature covered only the first part of what the public listener handed out.
func TestUploadedCRLHasNothingAfterIt(t *testing.T) {
	t.Parallel()
	crl := testCRL(t)
	if _, err := parseUploadedCRL(crl); err != nil {
		t.Fatalf("the plain CRL: %v", err)
	}
	for name, tail := range map[string]string{"a byte": "x", "a newline": "\n", "a second CRL": string(crl)} {
		_, err := parseUploadedCRL(append(append([]byte{}, crl...), tail...))
		if err == nil || !strings.Contains(err.Error(), "there is data after the CRL") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// offlineFixture is an imported offline root with the intermediate "issuing"
// signed by it and installed – the setup every CRL upload below needs.
type offlineFixture struct {
	v       *env
	off     *offlineRoot
	inter   *x509.Certificate
	interID string
}

func newOfflineFixture(t *testing.T) *offlineFixture {
	t.Helper()
	v := newEnv(t)
	off := newOfflineRoot(t, "Offline Root", t0.Add(-day))
	v.importRoot(t, "offline-root", off)
	ir := v.intermediate(t, "issuing", "offline-root", nil)
	if _, err := v.e.InstallCACertificate(t.Context(), "issuing", off.sign(t, ir.Offline, NameConstraints{}, nil), tester); err != nil {
		t.Fatal(err)
	}
	return &offlineFixture{v: v, off: off, inter: parse(t, mustGen(t, v, ir.ID, 1).CertDer), interID: ir.ID}
}

// signCRL signs a CRL template as the offline root would.
func signCRL(t *testing.T, r *offlineRoot, tmpl *x509.RevocationList) []byte {
	t.Helper()
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, r.cert, r.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func (f *offlineFixture) crlTemplate(number int64) *x509.RevocationList {
	return &x509.RevocationList{Number: big.NewInt(number), ThisUpdate: t0.Add(-time.Hour), NextUpdate: t0.Add(30 * day)}
}

// uploadedCRLs counts the CRLs of source "uploaded" and returns the CRL
// number the CA row holds.
func (f *offlineFixture) uploaded(t *testing.T) (count int, number int64) {
	t.Helper()
	if err := f.v.pki.QueryRowContext(t.Context(), `SELECT count(*) FROM crls WHERE source = 'uploaded'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if err := f.v.pki.QueryRowContext(t.Context(), `SELECT crl_number FROM cas WHERE name = 'offline-root'`).Scan(&number); err != nil {
		t.Fatal(err)
	}
	return count, number
}

// TestUploadCRLRefusals: every refused upload names its reason, changes
// nothing (no CRL stored, the CA's CRL number stays) and is audited as denied.
func TestUploadCRLRefusals(t *testing.T) {
	t.Parallel()
	other := newOfflineRoot(t, "Other Root", t0.Add(-day))
	// The root's own key under a certificate with another key identifier:
	// the signature verifies, the authority key identifier doesn't.
	wrongAKI := func(f *offlineFixture) *offlineRoot {
		fake := *f.off.cert
		fake.SubjectKeyId = []byte{9, 9, 9}
		return &offlineRoot{cert: &fake, key: f.off.key}
	}
	tests := []struct {
		name string
		data func(t *testing.T, f *offlineFixture) []byte
		want []string // every one must be among the reasons
	}{
		{"signed by another root", func(t *testing.T, f *offlineFixture) []byte {
			return signCRL(t, other, f.crlTemplate(5000))
		}, []string{"not signed by any generation of root \"offline-root\""}},
		{"right key, wrong authority key identifier", func(t *testing.T, f *offlineFixture) []byte {
			return signCRL(t, wrongAKI(f), f.crlTemplate(5000))
		}, []string{"not signed by any generation"}},
		{"SHA-1 signature", func(t *testing.T, f *offlineFixture) []byte {
			tmpl := f.crlTemplate(5000)
			tmpl.SignatureAlgorithm = x509.ECDSAWithSHA1
			return signCRL(t, f.off, tmpl)
		}, []string{"only SHA-2 (RSA, ECDSA) and Ed25519 signatures are accepted"}},
		{"CRL number zero", func(t *testing.T, f *offlineFixture) []byte {
			return signCRL(t, f.off, f.crlTemplate(0))
		}, []string{"the CRL has no CRL number"}},
		{"CRL number beyond 63 bits", func(t *testing.T, f *offlineFixture) []byte {
			tmpl := f.crlTemplate(0)
			tmpl.Number = new(big.Int).Lsh(big.NewInt(1), 63)
			return signCRL(t, f.off, tmpl)
		}, []string{"larger than this server can store (63 bits)"}},
		{"thisUpdate one second beyond the clock skew", func(t *testing.T, f *offlineFixture) []byte {
			tmpl := f.crlTemplate(5000)
			tmpl.ThisUpdate = t0.Add(5*time.Minute + time.Second)
			return signCRL(t, f.off, tmpl)
		}, []string{"thisUpdate 2026-10-13T08:05:01Z is in the future"}},
		{"nextUpdate is now", func(t *testing.T, f *offlineFixture) []byte {
			tmpl := f.crlTemplate(5000)
			tmpl.NextUpdate = t0
			return signCRL(t, f.off, tmpl)
		}, []string{"nextUpdate 2026-10-13T08:00:00Z has passed already"}},
		{"unknown critical extension", func(t *testing.T, f *offlineFixture) []byte {
			tmpl := f.crlTemplate(5000)
			tmpl.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}, Critical: true, Value: []byte{5, 0}}}
			return signCRL(t, f.off, tmpl)
		}, []string{"unknown critical CRL extension 1.3.6.1.4.1.99999.1"}},
		{"delta CRL", func(t *testing.T, f *offlineFixture) []byte {
			tmpl := f.crlTemplate(5000)
			tmpl.ExtraExtensions = []pkix.Extension{{Id: oidDeltaCRLIndicator, Critical: true, Value: []byte{2, 1, 1}}}
			return signCRL(t, f.off, tmpl)
		}, []string{"this is a delta CRL – upload the full CRL"}},
		{"non-critical delta indicator is a delta CRL too", func(t *testing.T, f *offlineFixture) []byte {
			tmpl := f.crlTemplate(5000)
			tmpl.ExtraExtensions = []pkix.Extension{{Id: oidDeltaCRLIndicator, Value: []byte{2, 1, 1}}}
			return signCRL(t, f.off, tmpl)
		}, []string{"this is a delta CRL"}},
		{"several reasons at once", func(t *testing.T, f *offlineFixture) []byte {
			tmpl := f.crlTemplate(5000)
			tmpl.ThisUpdate, tmpl.NextUpdate = t0.Add(-3*day), t0.Add(-2*day)
			tmpl.ExtraExtensions = []pkix.Extension{{Id: oidDeltaCRLIndicator, Critical: true, Value: []byte{2, 1, 1}}}
			return signCRL(t, other, tmpl)
		}, []string{"not signed by any generation", "has passed already", "this is a delta CRL"}},
		{"PEM of another type", func(t *testing.T, f *offlineFixture) []byte {
			return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signCRL(t, f.off, f.crlTemplate(5000))})
		}, []string{"expected a PEM block -----BEGIN X509 CRL----- or a DER file"}},
		{"PEM with text after it", func(t *testing.T, f *offlineFixture) []byte {
			p := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: signCRL(t, f.off, f.crlTemplate(5000))})
			return append(p, "trailing\n"...)
		}, []string{"there is data after the CRL – upload exactly one CRL"}},
		{"PEM with the same CRL twice", func(t *testing.T, f *offlineFixture) []byte {
			p := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: signCRL(t, f.off, f.crlTemplate(5000))})
			return append(p, p...)
		}, []string{"there is data after the CRL – upload exactly one CRL"}},
		{"DER with a byte after it", func(t *testing.T, f *offlineFixture) []byte {
			return append(signCRL(t, f.off, f.crlTemplate(5000)), 0)
		}, []string{"there is data after the CRL – upload exactly one CRL"}},
		{"more than 4 MiB", func(*testing.T, *offlineFixture) []byte {
			return make([]byte, MaxCRLSize+1)
		}, []string{"the CRL is larger than 4 MiB"}},
		{"not a CRL", func(*testing.T, *offlineFixture) []byte { return []byte("not a crl") }, []string{"the CRL can't be parsed"}},
		{"empty", func(*testing.T, *offlineFixture) []byte { return nil }, []string{"the CRL can't be parsed"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newOfflineFixture(t)
			_, _, err := f.v.e.UploadCRL(t.Context(), "offline-root", tt.data(t, f), tester)
			got := deniedErr(t, err)
			for _, want := range tt.want {
				if !strings.Contains(got, want) {
					t.Errorf("reasons %q lack %q", got, want)
				}
			}
			if n, number := f.uploaded(t); n != 0 || number != 0 {
				t.Errorf("a refused upload left %d CRLs and CRL number %d", n, number)
			}
			var denied bool
			for _, row := range f.v.auditRows(t) {
				denied = denied || (row.action == ActionCRLUpload && row.result == "denied" && row.target == "offline-root")
			}
			if !denied {
				t.Error("the refusal is not in the audit log")
			}
		})
	}
}

// TestUploadCRLNumberMustRise: the number is compared with every CRL of the
// CA – across generations of the root – and with the number on the CA row.
func TestUploadCRLNumberMustRise(t *testing.T) {
	t.Parallel()
	f := newOfflineFixture(t)
	up := func(off *offlineRoot, number int64) (*CRLResult, error) {
		res, _, err := f.v.e.UploadCRL(t.Context(), "offline-root", signCRL(t, off, f.crlTemplate(number)), tester)
		return res, err
	}
	if res, err := up(f.off, 10); err != nil || res.Generation != 1 || res.Number != 10 {
		t.Fatalf("first upload: %+v %v", res, err)
	}
	for _, number := range []int64{10, 9, 1} {
		if _, err := up(f.off, number); !strings.Contains(deniedErr(t, err), "CRL number "+strconv.FormatInt(number, 10)+" is not higher than the newest one (10)") {
			t.Errorf("number %d: %v", number, err)
		}
	}

	// A renewed root (generation 2, new key) continues the numbers of the CA.
	renewed := newOfflineRoot(t, "Offline Root", t0.Add(-day))
	if res := f.v.importRoot(t, "offline-root", renewed); res.Generation != 2 {
		t.Fatalf("renewed root: %+v", res)
	}
	if _, err := up(renewed, 10); !strings.Contains(deniedErr(t, err), "not higher than the newest one (10)") {
		t.Errorf("generation 2 restarts at 10: %v", err)
	}
	res, err := up(renewed, 11)
	if err != nil || res.Generation != 2 || res.Number != 11 {
		t.Fatalf("generation 2: %+v %v", res, err)
	}
	// The old key still signs a CRL the server accepts, if the number rises:
	// the CRL belongs to generation 1.
	if res, err = up(f.off, 12); err != nil || res.Generation != 1 {
		t.Errorf("generation 1 after the renewal: %+v %v", res, err)
	}
	if n, number := f.uploaded(t); n != 3 || number != 12 {
		t.Errorf("%d CRLs, CRL number %d, want 3 and 12", n, number)
	}
}

// TestUploadCRLBoundaries: the limits themselves are accepted, one second
// beyond is refused (the refusals are in TestUploadCRLRefusals).
func TestUploadCRLBoundaries(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		mod  func(*x509.RevocationList)
	}{
		{"thisUpdate exactly at the clock skew", func(c *x509.RevocationList) { c.ThisUpdate = t0.Add(5 * time.Minute) }},
		{"nextUpdate one second ahead", func(c *x509.RevocationList) { c.NextUpdate = t0.Add(time.Second) }},
		{"number 2^63-1", func(c *x509.RevocationList) { c.Number = new(big.Int).SetInt64(1<<63 - 1) }},
		{"critical issuingDistributionPoint", func(c *x509.RevocationList) {
			c.ExtraExtensions = []pkix.Extension{{Id: oidIssuingDistributionPoint, Critical: true, Value: []byte{0x30, 0}}}
		}},
		{"unknown non-critical extension", func(c *x509.RevocationList) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}, Value: []byte{5, 0}}}
		}},
		{"ECDSA with SHA-512", func(c *x509.RevocationList) { c.SignatureAlgorithm = x509.ECDSAWithSHA512 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newOfflineFixture(t)
			tmpl := f.crlTemplate(5000)
			tt.mod(tmpl)
			der := signCRL(t, f.off, tmpl)
			res, _, err := f.v.e.UploadCRL(t.Context(), "offline-root", der, tester)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(res.DER, der) || res.Number != tmpl.Number.Int64() || !res.ThisUpdate.Equal(tmpl.ThisUpdate) || !res.NextUpdate.Equal(tmpl.NextUpdate) {
				t.Errorf("result %+v", res)
			}
			var stored []byte
			if err := f.v.pki.QueryRowContext(t.Context(), `SELECT crl_der FROM crls WHERE source = 'uploaded'`).Scan(&stored); err != nil || !bytes.Equal(stored, der) {
				t.Errorf("stored CRL is not the uploaded one: %v", err)
			}
		})
	}
}

// TestUploadCRLTargets: which CAs take an uploaded CRL, and who may upload.
func TestUploadCRLTargets(t *testing.T) {
	t.Parallel()
	f := newOfflineFixture(t)
	crl := signCRL(t, f.off, f.crlTemplate(5000))
	// "issuing" signs its CRLs itself; "nothing" doesn't exist.
	for name, want := range map[string]string{
		"issuing": `CA "issuing" signs its CRLs itself – only the CRL of an offline root is uploaded`,
		"nothing": `there is no CA named "nothing"`,
	} {
		if _, _, err := f.v.e.UploadCRL(t.Context(), name, crl, tester); !strings.Contains(deniedErr(t, err), want) {
			t.Errorf("%s: %v", name, err)
		}
	}

	var noStepUp time.Time
	tests := []struct {
		name string
		who  keys.Who
		want error
	}{
		{"viewer", signedIn("view", f.v.clk.Now(), authz.Binding{Role: authz.Viewer}), authz.ErrDenied},
		{"operator", signedIn("op", f.v.clk.Now(), authz.Binding{CA: "offline-root", Role: authz.Operator}), authz.ErrDenied},
		{"admin of another CA", signedIn("other", f.v.clk.Now(), authz.Binding{CA: "issuing", Role: authz.Admin}), authz.ErrDenied},
		{"admin without a second factor", signedIn("adm", noStepUp, authz.Binding{Role: authz.Admin}), authz.ErrStepUpRequired},
		{"admin whose step-up is six minutes old", signedIn("adm", f.v.clk.Now().Add(-6*time.Minute), authz.Binding{Role: authz.Admin}), authz.ErrStepUpRequired},
		{"nobody", keys.Who{Actor: tester.Actor}, authz.ErrDenied},
	}
	for _, tt := range tests {
		if _, _, err := f.v.e.UploadCRL(t.Context(), "offline-root", crl, tt.who); !errors.Is(err, tt.want) || !errors.Is(err, ErrDenied) {
			t.Errorf("%s: %v, want %v", tt.name, err, tt.want)
		}
	}
	if n, _ := f.uploaded(t); n != 0 {
		t.Errorf("a refused user stored %d CRLs", n)
	}
	admin := signedIn("adm", f.v.clk.Now(), authz.Binding{Role: authz.Admin})
	if _, _, err := f.v.e.UploadCRL(t.Context(), "offline-root", crl, admin); err != nil {
		t.Errorf("tenant admin with a fresh second factor: %v", err)
	}
}

// TestUploadCRLRevokesListedIntermediates: what the root's CRL does to our
// intermediate, per CRL reason code (RFC 5280 §5.3.1).
func TestUploadCRLRevokesListedIntermediates(t *testing.T) {
	t.Parallel()
	const (
		hold    = "certificateHold is not supported"
		removed = "removeFromCRL is not supported"
	)
	tests := []struct {
		code       int
		reason     string // recorded
		blocksKey  bool
		warnsOnly  string // a substring of the warning about the reason code, "" = none
		noteInLogs bool
	}{
		{0, ReasonUnspecified, false, "", false},
		{1, ReasonKeyCompromise, true, "", false},
		{2, ReasonCACompromise, true, "", false},
		{3, ReasonAffiliationChanged, false, "", false},
		{4, ReasonSuperseded, false, "", false},
		{5, ReasonCessationOfOperation, false, "", false},
		{6, ReasonUnspecified, false, hold, true},
		{7, ReasonUnspecified, false, "reason code 7 is not used by MyOwnPKI", true},
		{8, ReasonUnspecified, false, removed, true},
		{9, ReasonPrivilegeWithdrawn, false, "", false},
		{10, ReasonUnspecified, false, "reason code 10 is not used by MyOwnPKI", true},
	}
	for _, tt := range tests {
		t.Run(strconv.Itoa(tt.code), func(t *testing.T) {
			t.Parallel()
			f := newOfflineFixture(t)
			listedAt := t0.Add(-2 * time.Hour)
			unknown := big.NewInt(0x5eed)
			tmpl := f.crlTemplate(7)
			tmpl.RevokedCertificateEntries = []x509.RevocationListEntry{
				{SerialNumber: unknown, RevocationTime: listedAt, ReasonCode: 1}, // not one of ours
				{SerialNumber: f.inter.SerialNumber, RevocationTime: listedAt, ReasonCode: tt.code},
			}
			res, warnings, err := f.v.e.UploadCRL(t.Context(), "offline-root", signCRL(t, f.off, tmpl), tester)
			if err != nil {
				t.Fatal(err)
			}
			if res.Entries != 2 {
				t.Errorf("entries %d, want 2", res.Entries)
			}
			all := strings.Join(warnings, "|")
			if n := strings.Count(all, "the root revoked CA"); n != 1 || !strings.Contains(all, `"issuing" generation 1 (`+tt.reason+`)`) {
				t.Errorf("warnings %q", all)
			}
			if tt.warnsOnly == "" && strings.Contains(all, "not supported") || tt.warnsOnly != "" && !strings.Contains(all, tt.warnsOnly) {
				t.Errorf("warnings %q, want %q", all, tt.warnsOnly)
			}
			q := pkidb.New(f.v.pki)
			rev, err := q.GetCARevocation(t.Context(), pkidb.GetCARevocationParams{CaID: f.interID, Generation: 1})
			if err != nil {
				t.Fatal(err)
			}
			if rev.Reason != tt.reason || rev.Source != "root_crl" || rev.RevokedAt != "2026-10-13T06:00:00.000Z" || rev.RevokedBy != "u-1" {
				t.Errorf("revocation row %+v", rev)
			}
			blocked, berr := q.GetBlockedKey(t.Context(), mustSPKI(t, f.inter))
			if tt.blocksKey {
				wantReason := tt.reason
				if berr != nil || blocked.Reason != wantReason || blocked.SourceType != "ca" || blocked.SourceID != f.interID+"/1" {
					t.Errorf("blocked key %+v %v", blocked, berr)
				}
			} else if !errors.Is(berr, sql.ErrNoRows) {
				t.Errorf("the key of an intermediate revoked for %s is blocked: %v", tt.reason, berr)
			}
			// The CA stops issuing at once.
			if got := f.v.denied(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"a.homelab.lan"}}); !strings.Contains(got, "is revoked") {
				t.Errorf("issue below the revoked intermediate: %q", got)
			}
			var noted bool
			for _, row := range f.v.auditRows(t) {
				if row.action != ActionCARevoke {
					continue
				}
				_, noted = row.details["note"]
			}
			if noted != tt.noteInLogs {
				t.Errorf("audit note present: %v, want %v", noted, tt.noteInLogs)
			}
		})
	}
}

// TestUploadCRLRevokesOnlyOnce: the root keeps listing the intermediate on
// every later CRL; the second upload doesn't revoke it again, warn again or
// move the recorded time.
func TestUploadCRLRevokesOnlyOnce(t *testing.T) {
	t.Parallel()
	f := newOfflineFixture(t)
	entry := func(at time.Time) []x509.RevocationListEntry {
		return []x509.RevocationListEntry{{SerialNumber: f.inter.SerialNumber, RevocationTime: at, ReasonCode: 4}}
	}
	first := f.crlTemplate(1)
	first.RevokedCertificateEntries = entry(t0.Add(-3 * time.Hour))
	if _, w, err := f.v.e.UploadCRL(t.Context(), "offline-root", signCRL(t, f.off, first), tester); err != nil || !strings.Contains(strings.Join(w, "|"), "the root revoked CA") {
		t.Fatalf("first upload: %v %v", w, err)
	}
	second := f.crlTemplate(2)
	second.RevokedCertificateEntries = entry(t0.Add(-time.Hour))
	_, w, err := f.v.e.UploadCRL(t.Context(), "offline-root", signCRL(t, f.off, second), tester)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(w, "|"), "the root revoked CA") {
		t.Errorf("the second upload revoked again: %v", w)
	}
	var n int
	var at string
	if err := f.v.pki.QueryRowContext(t.Context(), `SELECT count(*), min(revoked_at) FROM ca_revocations`).Scan(&n, &at); err != nil || n != 1 || at != "2026-10-13T05:00:00.000Z" {
		t.Errorf("%d revocation rows, revoked at %q (%v)", n, at, err)
	}
	revokes := 0
	for _, row := range f.v.auditRows(t) {
		if row.action == ActionCARevoke {
			revokes++
		}
	}
	if revokes != 1 {
		t.Errorf("%d ca.revoke audit entries, want 1", revokes)
	}
}
