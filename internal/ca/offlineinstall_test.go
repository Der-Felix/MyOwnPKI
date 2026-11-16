package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// pendingFixture is an imported offline root with the intermediate "issuing"
// ordered and waiting for the root's signature.
type pendingFixture struct {
	v   *env
	off *offlineRoot
	ir  *CAResult
	nc  NameConstraints
}

func newPendingFixture(t *testing.T) *pendingFixture {
	t.Helper()
	v := newEnv(t)
	off := newOfflineRoot(t, "Offline Root", t0.Add(-day))
	v.importRoot(t, "offline-root", off)
	nc := NameConstraints{PermittedDNS: []string{"homelab.lan"}}
	ir := v.intermediate(t, "issuing", "offline-root", func(r *IntermediateRequest) { r.NameConstraints = nc })
	if ir.Status != StatusPendingSignature || ir.Offline == nil {
		t.Fatalf("pending intermediate: %+v", ir)
	}
	return &pendingFixture{v: v, off: off, ir: ir, nc: nc}
}

func (f *pendingFixture) signed(t *testing.T, mod func(*x509.Certificate, *crypto.PublicKey)) []byte {
	t.Helper()
	return f.off.sign(t, f.ir.Offline, f.nc, mod)
}

// pending reports whether generation 1 of "issuing" still waits for its
// certificate, and the status of the CA.
func (f *pendingFixture) state(t *testing.T) (waiting bool, status string, current sql.NullInt64) {
	t.Helper()
	var der []byte
	if err := f.v.pki.QueryRowContext(t.Context(), `SELECT g.cert_der, c.status, c.current_generation FROM ca_generations g
		JOIN cas c ON c.id = g.ca_id WHERE c.name = 'issuing' AND g.generation = 1`).Scan(&der, &status, &current); err != nil {
		t.Fatal(err)
	}
	return der == nil, status, current
}

// TestInstallCACertificateRefusals: a certificate that differs from the
// order in any way is refused with the reason – and nothing changes: the
// generation keeps waiting and the CA stays pending.
func TestInstallCACertificateRefusals(t *testing.T) {
	t.Parallel()
	otherSubject, err := asn1.Marshal(pkix.Name{CommonName: "Another CA", Organization: []string{"Homelab"}}.ToRDNSequence())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		mod  func(*x509.Certificate, *crypto.PublicKey)
		want string
	}{
		{"SHA-1 signature", func(c *x509.Certificate, _ *crypto.PublicKey) { c.SignatureAlgorithm = x509.ECDSAWithSHA1 },
			"only SHA-2 (RSA, ECDSA) and Ed25519 signatures are accepted; sign with sha384"},
		{"another subject than the CSR", func(c *x509.Certificate, _ *crypto.PublicKey) { c.RawSubject = otherSubject },
			"differs from the CSR"},
		{"already expired", func(c *x509.Certificate, _ *crypto.PublicKey) {
			c.NotBefore, c.NotAfter = t0.Add(-day), t0.Add(-time.Hour)
		}, "the certificate is not valid now (valid from 2026-10-12 to 2026-10-13)"},
		{"not yet valid", func(c *x509.Certificate, _ *crypto.PublicKey) {
			c.NotBefore, c.NotAfter = t0.Add(time.Hour), t0.Add(30*day)
		}, "the certificate is not valid now (valid from 2026-10-13 to 2026-11-12)"},
		{"name constraints written non-critical", func(c *x509.Certificate, _ *crypto.PublicKey) { c.PermittedDNSDomainsCritical = false },
			"name constraints differ from the order: certificate [permitted dns homelab.lan] (critical false), ordered [permitted dns homelab.lan] (critical true)"},
		{"an excluded name added", func(c *x509.Certificate, _ *crypto.PublicKey) { c.ExcludedDNSDomains = []string{"secret.homelab.lan"} },
			"name constraints differ from the order"},
		{"an excluded e-mail address added", func(c *x509.Certificate, _ *crypto.PublicKey) { c.ExcludedEmailAddresses = []string{"bob@homelab.lan"} },
			"name constraints differ from the order"},
		{"CA:FALSE", func(c *x509.Certificate, _ *crypto.PublicKey) { c.IsCA, c.MaxPathLenZero = false, false },
			"basicConstraints must be critical CA:TRUE"},
		{"no digitalSignature", func(c *x509.Certificate, _ *crypto.PublicKey) {
			c.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		},
			"keyUsage must be exactly digitalSignature, keyCertSign, cRLSign"},
		{"path length 2", func(c *x509.Certificate, _ *crypto.PublicKey) { c.MaxPathLen, c.MaxPathLenZero = 2, false },
			"path length 2, ordered 0"},
		{"no path length at all", func(c *x509.Certificate, _ *crypto.PublicKey) { c.MaxPathLen, c.MaxPathLenZero = -1, false },
			"path length none, ordered 0"},
		{"an extended key usage the order doesn't have", func(c *x509.Certificate, _ *crypto.PublicKey) {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}, "extended key usages differ from the order: certificate 1.3.6.1.5.5.7.3.2, ordered none"},
		{"valid beyond the root", func(c *x509.Certificate, _ *crypto.PublicKey) { c.NotAfter = t0.AddDate(21, 0, 0) },
			"is after the end of the parent"},
		{"valid before the root", func(c *x509.Certificate, _ *crypto.PublicKey) { c.NotBefore = t0.Add(-3 * day) },
			"is before the parent's notBefore"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newPendingFixture(t)
			_, err := f.v.e.InstallCACertificate(t.Context(), "issuing", f.signed(t, tt.mod), tester)
			if got := deniedErr(t, err); !strings.Contains(got, tt.want) {
				t.Errorf("reasons %q, want %q", got, tt.want)
			}
			if waiting, status, current := f.state(t); !waiting || status != StatusPendingSignature || current.Valid {
				t.Errorf("after the refusal: waiting %v, status %s, current generation %v", waiting, status, current)
			}
		})
	}
}

// TestInstallCACertificateFiles: what isn't one clean PEM certificate.
func TestInstallCACertificateFiles(t *testing.T) {
	t.Parallel()
	f := newPendingFixture(t)
	good := f.signed(t, nil)
	block, _ := pem.Decode(good)
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"nothing", nil, "no PEM block found"},
		{"text", []byte("hello"), "no PEM block found"},
		{"a CSR", f.ir.Offline.CSRPEM, `PEM block "CERTIFICATE REQUEST" is not a certificate`},
		{"with headers", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: block.Bytes}), "the PEM block has headers"},
		{"with text after it", append(append([]byte{}, good...), "tail\n"...), "there is data after the certificate"},
		{"twice", append(append([]byte{}, good...), good...), "there is data after the certificate"},
		{"damaged DER", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes[:len(block.Bytes)-3]}), "the certificate can't be parsed"},
		{"more than 64 KiB", append(append([]byte{}, good...), make([]byte, MaxCertSize)...), "the certificate file is larger than 64 KiB"},
	}
	for _, tt := range tests {
		_, err := f.v.e.InstallCACertificate(t.Context(), "issuing", tt.data, tester)
		if got := deniedErr(t, err); !strings.Contains(got, tt.want) {
			t.Errorf("%s: %q, want %q", tt.name, got, tt.want)
		}
	}
	if waiting, status, _ := f.state(t); !waiting || status != StatusPendingSignature {
		t.Errorf("after the refusals: waiting %v, status %s", waiting, status)
	}
	if _, err := f.v.e.InstallCACertificate(t.Context(), "issuing", good, tester); err != nil {
		t.Errorf("the good certificate after all of that: %v", err)
	}
}

// TestInstallCACertificateKeyAndSignerChecks: a compromised key and a wrong
// issuer are refused although the certificate itself is well formed.
func TestInstallCACertificateKeyAndSignerChecks(t *testing.T) {
	t.Parallel()
	t.Run("blocked key", func(t *testing.T) {
		t.Parallel()
		f := newPendingFixture(t)
		csr, err := x509.ParseCertificateRequest(pemBytes(t, f.ir.Offline.CSRPEM))
		if err != nil {
			t.Fatal(err)
		}
		h, err := spkiHash(csr.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if err = pkidb.New(f.v.pki).BlockKey(t.Context(), pkidb.BlockKeyParams{
			SpkiSha256: h, Reason: ReasonKeyCompromise, SourceType: "certificate", SourceID: "crt-1", BlockedAt: t0.Format(dbTime), BlockedBy: "u-1",
		}); err != nil {
			t.Fatal(err)
		}
		_, err = f.v.e.InstallCACertificate(t.Context(), "issuing", f.signed(t, nil), tester)
		if got := deniedErr(t, err); !strings.Contains(got, "this key was reported compromised (keyCompromise, certificate crt-1 on 2026-10-13)") {
			t.Errorf("reasons %q", got)
		}
	})
	t.Run("signed by the right key but another issuer name", func(t *testing.T) {
		t.Parallel()
		f := newPendingFixture(t)
		fake := *f.off.cert
		fake.RawSubject, fake.Subject = nil, pkix.Name{CommonName: "Look-alike Root"}
		der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: fake.SerialNumber, Subject: fake.Subject, SubjectKeyId: fake.SubjectKeyId,
			NotBefore: fake.NotBefore, NotAfter: fake.NotAfter, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, &fake, f.off.key.Public(), f.off.key)
		if err != nil {
			t.Fatal(err)
		}
		lookalike := &offlineRoot{cert: parse(t, der), key: f.off.key}
		_, err = f.v.e.InstallCACertificate(t.Context(), "issuing", lookalike.sign(t, f.ir.Offline, f.nc, nil), tester)
		if got := deniedErr(t, err); !strings.Contains(got, `the certificate is not signed by parent CA "offline-root" generation 1`) {
			t.Errorf("reasons %q", got)
		}
	})
}

// TestInstallCACertificateWarnsAboutURLs: a certificate with AIA or CDP URLs
// other than the ones MyOwnPKI serves is accepted but says so – strict
// clients would reject every certificate below it.
func TestInstallCACertificateWarnsAboutURLs(t *testing.T) {
	t.Parallel()
	f := newPendingFixture(t)
	res, err := f.v.e.InstallCACertificate(t.Context(), "issuing", f.signed(t, func(c *x509.Certificate, _ *crypto.PublicKey) {
		c.IssuingCertificateURL = []string{"http://elsewhere.lan/root.crt"}
		c.CRLDistributionPoints = []string{"http://elsewhere.lan/root.crl", baseURL + "/crl/offline-root/1.crl"}
	}), tester)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Warnings) != 2 ||
		!strings.Contains(res.Warnings[0], "AIA caIssuers is [http://elsewhere.lan/root.crt], MyOwnPKI serves "+baseURL+"/ca/offline-root/1.crt") ||
		!strings.Contains(res.Warnings[1], "CRL distribution point is [http://elsewhere.lan/root.crl "+baseURL+"/crl/offline-root/1.crl], MyOwnPKI serves "+baseURL+"/crl/offline-root/1.crl") {
		t.Errorf("warnings %q", res.Warnings)
	}
	var logged bool
	for _, row := range f.v.auditRows(t) {
		if row.action == ActionCACertInstall && row.result == "success" {
			w, _ := row.details["warnings"].([]any)
			logged = len(w) == 2
		}
	}
	if !logged {
		t.Error("the warnings are not in the audit entry of the install")
	}
}

// TestInstallCACertificateTargets: which CAs take a certificate, and who may
// install it.
func TestInstallCACertificateTargets(t *testing.T) {
	t.Parallel()
	f := newPendingFixture(t)
	good := f.signed(t, nil)
	f.v.root(t, "online-root", nil)
	for name, want := range map[string]string{
		"nothing":      `there is no CA named "nothing"`,
		"offline-root": `CA "offline-root" has no generation waiting for a signature`,
		"online-root":  `CA "online-root" has no generation waiting for a signature`,
	} {
		if _, err := f.v.e.InstallCACertificate(t.Context(), name, good, tester); !strings.Contains(deniedErr(t, err), want) {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := f.v.e.OfflineBundleFor(t.Context(), name); !strings.Contains(deniedErr(t, err), want) {
			t.Errorf("bundle of %s: %v", name, err)
		}
	}

	var noStepUp time.Time
	now := f.v.clk.Now()
	for _, tt := range []struct {
		name string
		who  keys.Who
		want error
	}{
		{"viewer", signedIn("view", now, authz.Binding{Role: authz.Viewer}), authz.ErrDenied},
		{"operator of the CA", signedIn("op", now, authz.Binding{CA: "issuing", Role: authz.Operator}), authz.ErrDenied},
		{"admin of another CA", signedIn("other", now, authz.Binding{CA: "online-root", Role: authz.Admin}), authz.ErrDenied},
		{"admin without a second factor", signedIn("adm", noStepUp, authz.Binding{Role: authz.Admin}), authz.ErrStepUpRequired},
		{"nobody", keys.Who{Actor: tester.Actor}, authz.ErrDenied},
	} {
		if _, err := f.v.e.InstallCACertificate(t.Context(), "issuing", good, tt.who); !errors.Is(err, tt.want) || !errors.Is(err, ErrDenied) {
			t.Errorf("%s: %v, want %v", tt.name, err, tt.want)
		}
	}
	if waiting, _, _ := f.state(t); !waiting {
		t.Error("a refused user installed the certificate")
	}

	// A retired CA takes no certificate any more.
	if err := f.v.e.RetireCA(t.Context(), "issuing", tester); err != nil {
		t.Fatal(err)
	}
	if _, err := f.v.e.InstallCACertificate(t.Context(), "issuing", good, tester); !strings.Contains(deniedErr(t, err), `CA "issuing" is retired`) {
		t.Errorf("retired: %v", err)
	}
}

// TestInstallCACertificateIsAtomic: when the store fails after every check
// has passed – here while the first CRL is written – nothing of the install
// remains: the generation waits, the CA is pending, the audit log has no
// success. The same certificate installs once the store works again.
func TestInstallCACertificateIsAtomic(t *testing.T) {
	t.Parallel()
	f := newPendingFixture(t)
	good := f.signed(t, nil)
	if _, err := f.v.pki.ExecContext(t.Context(), `CREATE TRIGGER fail_crl BEFORE INSERT ON crls BEGIN SELECT RAISE(ABORT, 'disk full'); END`); err != nil {
		t.Fatal(err)
	}
	_, err := f.v.e.InstallCACertificate(t.Context(), "issuing", good, tester)
	if err == nil || errors.Is(err, ErrDenied) || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("install with a failing store: %v", err)
	}
	if waiting, status, current := f.state(t); !waiting || status != StatusPendingSignature || current.Valid {
		t.Errorf("half an install: waiting %v, status %s, current generation %v", waiting, status, current)
	}
	var crls int
	if cerr := f.v.pki.QueryRowContext(t.Context(), `SELECT count(*) FROM crls`).Scan(&crls); cerr != nil || crls != 0 {
		t.Errorf("%d CRLs after a failed install (%v)", crls, cerr)
	}
	for _, row := range f.v.auditRows(t) {
		if row.action == ActionCACertInstall && row.result == "success" {
			t.Errorf("a success entry for an install that failed: %+v", row)
		}
	}
	if _, derr := f.v.pki.ExecContext(t.Context(), `DROP TRIGGER fail_crl`); derr != nil {
		t.Fatal(derr)
	}
	res, err := f.v.e.InstallCACertificate(t.Context(), "issuing", good, tester)
	if err != nil || res.Status != StatusActive || res.CRL == nil {
		t.Fatalf("install after the store works again: %+v %v", res, err)
	}
}
