package ca

import (
	"crypto/x509"
	"database/sql"
	"encoding/asn1"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

func (v *env) caRevocations(t *testing.T) int {
	t.Helper()
	var n int
	if err := v.pki.QueryRowContext(t.Context(), `SELECT count(*) FROM ca_revocations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestRevokeCAReasons: what each reason does – the entry on the parent's CRL
// (RFC 5280 §5.3.1 reason codes), the blocked key (only for the two
// compromise reasons) and the audit entry.
func TestRevokeCAReasons(t *testing.T) {
	t.Parallel()
	tests := []struct {
		reason string
		code   int
		blocks bool
	}{
		{ReasonUnspecified, 0, false},
		{ReasonKeyCompromise, 1, true},
		{ReasonCACompromise, 2, true},
		{ReasonAffiliationChanged, 3, false},
		{ReasonSuperseded, 4, false},
		{ReasonCessationOfOperation, 5, false},
		{ReasonPrivilegeWithdrawn, 9, false},
	}
	for _, tt := range tests {
		t.Run(tt.reason, func(t *testing.T) {
			t.Parallel()
			v := newEnv(t)
			_, issuing := v.chain(t, caOpts{})
			res, err := v.e.RevokeCA(t.Context(), RevokeCARequest{Name: "issuing", Reason: tt.reason, Who: tester})
			if err != nil {
				t.Fatal(err)
			}
			if res.Serial != SerialHex(issuing.cert.SerialNumber) || !res.Published || res.CRL == nil {
				t.Fatalf("result %+v", res)
			}
			// The parent's CRL: one entry, the CA's serial, the reason, now.
			crl := parseCRL(t, res.CRL.DER)
			if len(crl.RevokedCertificateEntries) != 1 {
				t.Fatalf("root CRL entries %+v", crl.RevokedCertificateEntries)
			}
			e := crl.RevokedCertificateEntries[0]
			if e.SerialNumber.Cmp(issuing.cert.SerialNumber) != 0 || e.ReasonCode != tt.code || !e.RevocationTime.Equal(t0) {
				t.Errorf("entry %+v, want serial %s, reason %d, time %v", e, res.Serial, tt.code, t0)
			}
			if err := crl.CheckSignatureFrom(mustGenCert(t, v, "root")); err != nil {
				t.Errorf("the root CRL is not signed by the root: %v", err)
			}

			blocked, berr := pkidb.New(v.pki).GetBlockedKey(t.Context(), mustSPKI(t, issuing.cert))
			switch {
			case tt.blocks && (berr != nil || blocked.Reason != tt.reason || blocked.SourceType != "ca" || blocked.SourceID != issuing.id+"/1"):
				t.Errorf("blocked key %+v %v", blocked, berr)
			case !tt.blocks && !errors.Is(berr, sql.ErrNoRows):
				t.Errorf("a key revoked for %s is blocked: %v", tt.reason, berr)
			}

			found := false
			for _, row := range v.auditRows(t) {
				if row.action != ActionCARevoke || row.result != "success" {
					continue
				}
				found = true
				_, hasBlock := row.details["blocked_key"]
				if row.details["name"] != "issuing" || row.details["reason"] != tt.reason || row.details["parent"] != "root" ||
					row.details["serial"] != res.Serial || hasBlock != tt.blocks {
					t.Errorf("audit details %v", row.details)
				}
			}
			if !found {
				t.Error("no success entry in the audit log")
			}
			if got := v.denied(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"a.homelab.lan"}}); !strings.Contains(got, `CA "issuing" generation 1 is revoked (`+tt.reason+`, 2026-10-13)`) {
				t.Errorf("issue below the revoked CA: %q", got)
			}
		})
	}
}

// TestRevokeCAInvalidityDate: the date goes into the revocation row and the
// CRL entry, for the two compromise reasons only.
func TestRevokeCAInvalidityDate(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.chain(t, caOpts{})
	when := t0.Add(-36 * time.Hour)
	res, err := v.e.RevokeCA(t.Context(), RevokeCARequest{Name: "issuing", Reason: ReasonCACompromise, InvalidityDate: &when, Who: tester})
	if err != nil {
		t.Fatal(err)
	}
	entry := parseCRL(t, res.CRL.DER).RevokedCertificateEntries[0]
	var got time.Time
	var found bool
	for _, ext := range entry.Extensions {
		if ext.Id.Equal(oidInvalidityDate) {
			found = true
			if _, err := asn1.Unmarshal(ext.Value, &got); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !found || !got.Equal(when) {
		t.Errorf("invalidity date in the CRL entry: %v (found %v), want %v", got, found, when)
	}
	var stored string
	if err := v.pki.QueryRowContext(t.Context(), `SELECT invalidity_date FROM ca_revocations`).Scan(&stored); err != nil || stored != "2026-10-11T20:00:00Z" {
		t.Errorf("stored invalidity date %q (%v)", stored, err)
	}
}

// TestRevokeCARefusals: every refusal names its reason and revokes nothing.
func TestRevokeCARefusals(t *testing.T) {
	t.Parallel()
	future := t0.Add(day)
	today := t0
	tests := []struct {
		name string
		req  RevokeCARequest
		want string
	}{
		{"unknown CA", RevokeCARequest{Name: "nothing", Reason: ReasonSuperseded}, `there is no CA named "nothing"`},
		{"a root", RevokeCARequest{Name: "root", Reason: ReasonCACompromise}, "a root can't be revoked by anyone; remove it from the trust stores and retire it"},
		{"a generation that doesn't exist", RevokeCARequest{Name: "issuing", Generation: 7, Reason: ReasonSuperseded}, `CA "issuing" has no signed generation 7`},
		{"a negative generation", RevokeCARequest{Name: "issuing", Generation: -1, Reason: ReasonSuperseded}, `CA "issuing" has no signed generation -1`},
		{"certificateHold", RevokeCARequest{Name: "issuing", Reason: "certificateHold"}, `revocation reason "certificateHold" is not allowed`},
		{"no reason", RevokeCARequest{Name: "issuing"}, `revocation reason "" is not allowed`},
		{"an invalidity date with a harmless reason", RevokeCARequest{Name: "issuing", Reason: ReasonSuperseded, InvalidityDate: &today}, "an invalidity date only goes with keyCompromise or cACompromise"},
		{"an invalidity date in the future", RevokeCARequest{Name: "issuing", Reason: ReasonCACompromise, InvalidityDate: &future}, "the invalidity date is in the future"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			v := newEnv(t)
			v.chain(t, caOpts{})
			tt.req.Who = tester
			_, err := v.e.RevokeCA(t.Context(), tt.req)
			if got := deniedErr(t, err); !strings.Contains(got, tt.want) {
				t.Errorf("reasons %q, want %q", got, tt.want)
			}
			if n := v.caRevocations(t); n != 0 {
				t.Errorf("%d CA revocations after a refusal", n)
			}
			if got := v.issue(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"a.homelab.lan"}}); got == nil {
				t.Error("the CA stopped issuing")
			}
			denied := false
			for _, row := range v.auditRows(t) {
				denied = denied || (row.action == ActionCARevoke && row.result == "denied")
			}
			if !denied {
				t.Error("the refusal is not in the audit log")
			}
		})
	}
}

// TestRevokeCAOfflineParentAndPending: below an offline root the revocation
// happens on the root; a CA without a certificate has nothing to revoke.
func TestRevokeCAOfflineParentAndPending(t *testing.T) {
	t.Parallel()
	f := newOfflineFixture(t)
	_, err := f.v.e.RevokeCA(t.Context(), RevokeCARequest{Name: "issuing", Reason: ReasonCACompromise, Who: tester})
	if got := deniedErr(t, err); !strings.Contains(got, `CA "issuing" was signed by the offline root "offline-root" – revoke it there and upload the root's new CRL`) {
		t.Errorf("below an offline root: %q", got)
	}
	if n := f.v.caRevocations(t); n != 0 {
		t.Errorf("%d revocations", n)
	}

	p := newPendingFixture(t)
	for gen, want := range map[int64]string{0: `CA "issuing" has no signed generation`, 1: `CA "issuing" has no signed generation 1`} {
		_, err := p.v.e.RevokeCA(t.Context(), RevokeCARequest{Name: "issuing", Generation: gen, Reason: ReasonCACompromise, Who: tester})
		if got := deniedErr(t, err); !strings.Contains(got, want) {
			t.Errorf("pending CA, generation %d: %q, want %q", gen, got, want)
		}
	}
}

// TestRevokeCATwice: a revocation is final, and revoking an older generation
// leaves the current one working.
func TestRevokeCATwice(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.chain(t, caOpts{})
	res, err := v.e.RenewCA(t.Context(), RenewRequest{Name: "issuing", Who: tester})
	if err != nil || res.Generation != 2 {
		t.Fatalf("renew: %+v %v", res, err)
	}
	// Generation 1 is not the current one: no "can't issue" warning.
	first, err := v.e.RevokeCA(t.Context(), RevokeCARequest{Name: "issuing", Generation: 1, Reason: ReasonSuperseded, Who: tester})
	if err != nil || len(first.Warnings) != 0 {
		t.Fatalf("revoke generation 1: %+v %v", first, err)
	}
	if _, err := v.e.RevokeCA(t.Context(), RevokeCARequest{Name: "issuing", Generation: 1, Reason: ReasonCACompromise, Who: tester}); !strings.Contains(deniedErr(t, err),
		`CA "issuing" generation 1 is revoked already – a revocation is final`) {
		t.Errorf("generation 1 twice: %v", err)
	}
	if out := v.issue(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"a.homelab.lan"}}); parse(t, out.CertDER).IssuingCertificateURL[0] != baseURL+"/ca/issuing/2.crt" {
		t.Errorf("the leaf is not from generation 2: %v", parse(t, out.CertDER).IssuingCertificateURL)
	}
	// Generation 0 means the current one: now the CA can't issue.
	cur, err := v.e.RevokeCA(t.Context(), RevokeCARequest{Name: "issuing", Reason: ReasonKeyCompromise, Who: tester})
	if err != nil || len(cur.Warnings) != 1 || !strings.Contains(cur.Warnings[0], `CA "issuing" can't issue any more – its current generation is revoked; renew it with a new key`) {
		t.Fatalf("revoke the current generation: %+v %v", cur, err)
	}
	if cur.Serial == first.Serial {
		t.Error("both generations have the same serial")
	}
	if n := v.caRevocations(t); n != 2 {
		t.Errorf("%d CA revocations, want 2", n)
	}
	// The root's CRL lists both.
	crl := parseCRL(t, cur.CRL.DER)
	if len(crl.RevokedCertificateEntries) != 2 {
		t.Errorf("root CRL: %+v", crl.RevokedCertificateEntries)
	}
}

// TestRevokeCAWhileSealed: the revocation is stored, the CRL waits for the
// unseal, and the warning says so.
func TestRevokeCAWhileSealed(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.chain(t, caOpts{})
	v.e.Keys = keys.New(nil, nil, v.clk)
	res, err := v.e.RevokeCA(t.Context(), RevokeCARequest{Name: "issuing", Reason: ReasonCACompromise, Who: tester})
	if err != nil {
		t.Fatal(err)
	}
	if res.Published || res.CRL != nil || !strings.Contains(strings.Join(res.Warnings, "|"), "the server is sealed: the revocation is stored, but takes effect only when the CRL is signed at unseal") {
		t.Errorf("sealed revocation: %+v", res)
	}
	if n := v.caRevocations(t); n != 1 {
		t.Errorf("%d CA revocations, want 1", n)
	}
}

// TestRevokeCAPermissions: a CA is revoked by whoever manages its issuer, with
// a fresh second factor – not by its own administrator.
func TestRevokeCAPermissions(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.chain(t, caOpts{})
	var noStepUp time.Time
	now := v.clk.Now()
	for _, tt := range []struct {
		name string
		who  keys.Who
		want error
	}{
		{"viewer", signedIn("view", now, authz.Binding{Role: authz.Viewer}), authz.ErrDenied},
		{"operator of the issuer", signedIn("op", now, authz.Binding{CA: "root", Role: authz.Operator}), authz.ErrDenied},
		{"admin of the CA itself", signedIn("self", now, authz.Binding{CA: "issuing", Role: authz.Admin}), authz.ErrDenied},
		{"admin of the issuer without a second factor", signedIn("adm", noStepUp, authz.Binding{CA: "root", Role: authz.Admin}), authz.ErrStepUpRequired},
		{"nobody", keys.Who{Actor: tester.Actor}, authz.ErrDenied},
	} {
		if _, err := v.e.RevokeCA(t.Context(), RevokeCARequest{Name: "issuing", Reason: ReasonSuperseded, Who: tt.who}); !errors.Is(err, tt.want) || !errors.Is(err, ErrDenied) {
			t.Errorf("%s: %v, want %v", tt.name, err, tt.want)
		}
	}
	if n := v.caRevocations(t); n != 0 {
		t.Errorf("a refused user revoked a CA (%d rows)", n)
	}
	admin := signedIn("adm", now, authz.Binding{CA: "root", Role: authz.Admin})
	if _, err := v.e.RevokeCA(t.Context(), RevokeCARequest{Name: "issuing", Reason: ReasonSuperseded, Who: admin}); err != nil {
		t.Errorf("admin of the issuer with a fresh second factor: %v", err)
	}
}

func mustGenCert(t *testing.T, v *env, name string) *x509.Certificate {
	t.Helper()
	ca, err := pkidb.New(v.pki).GetCAByName(t.Context(), name)
	if err != nil {
		t.Fatal(err)
	}
	return parse(t, mustGen(t, v, ca.ID, ca.CurrentGeneration.Int64).CertDer)
}
