package ca

import (
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
)

// TestReadPathsHideWhatYouMayNotRead: no read permission = not found, for
// lists, details and downloads (owner 2026-10-17).
func TestReadPathsHideWhatYouMayNotRead(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	root, issuing := v.chain(t, caOpts{})
	other := v.addCA(t, "other", caOpts{parent: root})
	mine := v.issue(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"nas.homelab.lan"}})
	v.clk.Advance(time.Second) // IDs sort by time; within one millisecond at random
	theirs := v.issue(t, Request{CA: "other", Preset: "server", DNSNames: []string{"web.homelab.lan"}})

	var none time.Time
	tenant := signedIn("tv", none, authz.Binding{Role: authz.Viewer})
	scoped := signedIn("cv", none, authz.Binding{CA: "issuing", Role: authz.Viewer})
	stranger := signedIn("x", none)

	names := func(who keys.Who) []string {
		cas, err := v.e.CAs(t.Context(), who)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, c := range cas {
			out = append(out, c.Name)
		}
		slices.Sort(out)
		return out
	}
	if got := names(tenant); !slices.Equal(got, []string{"issuing", "other", "root"}) {
		t.Errorf("tenant viewer sees %v", got)
	}
	if got := names(scoped); !slices.Equal(got, []string{"issuing"}) {
		t.Errorf("CA viewer sees %v", got)
	}
	if got := names(stranger); len(got) != 0 {
		t.Errorf("no role sees %v", got)
	}
	if _, err := v.e.CA(t.Context(), scoped, other.id); !errors.Is(err, ErrNotFound) {
		t.Errorf("other CA for the CA viewer: %v", err)
	}
	if _, err := v.e.CAChain(t.Context(), scoped, root.id); !errors.Is(err, ErrNotFound) {
		t.Errorf("root chain for the CA viewer: %v", err)
	}
	if chain, err := v.e.CAChain(t.Context(), scoped, issuing.id); err != nil || len(chain) != 2 {
		t.Errorf("issuing chain: %d %v", len(chain), err)
	}

	ids := func(who keys.Who, f CertificateFilter) []string {
		page, err := v.e.Certificates(t.Context(), who, f)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, c := range page.Items {
			out = append(out, c.ID)
		}
		return out
	}
	if got := ids(tenant, CertificateFilter{}); !slices.Equal(got, []string{theirs.ID, mine.ID}) {
		t.Errorf("tenant viewer, newest first: %v", got)
	}
	if got := ids(scoped, CertificateFilter{}); !slices.Equal(got, []string{mine.ID}) {
		t.Errorf("CA viewer: %v", got)
	}
	if got := ids(stranger, CertificateFilter{}); len(got) != 0 {
		t.Errorf("no role: %v", got)
	}
	if _, err := v.e.Certificates(t.Context(), scoped, CertificateFilter{CAID: other.id}); !errors.Is(err, ErrNotFound) {
		t.Errorf("filter by a CA you can't read: %v", err)
	}
	if _, err := v.e.Certificate(t.Context(), scoped, theirs.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("certificate of another CA: %v", err)
	}
	if _, _, err := v.e.CertificateChain(t.Context(), scoped, theirs.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("chain of another CA: %v", err)
	}
	c, chain, err := v.e.CertificateChain(t.Context(), scoped, mine.ID)
	// The chain stops below the root: issuing only.
	if err != nil || !slices.Equal(c, mine.CertDER) || len(chain) != 1 || !slices.Equal(chain[0], issuing.cert.Raw) {
		t.Errorf("own chain: %v", err)
	}
}

// TestCertificateSearchAndPages: the search is a plain substring – percent
// and underscore are no wildcards – and pages don't overlap.
func TestCertificateSearchAndPages(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.chain(t, caOpts{})
	var all []string
	for _, n := range []string{"nas", "web", "mail"} {
		all = append(all, v.issue(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{n + ".homelab.lan"}}).ID)
		v.clk.Advance(time.Second)
	}
	slices.Reverse(all)
	count := func(f CertificateFilter) int {
		page, err := v.e.Certificates(t.Context(), tester, f)
		if err != nil {
			t.Fatal(err)
		}
		return len(page.Items)
	}
	for search, want := range map[string]int{"": 3, "homelab": 3, "NAS.homelab": 1, "%": 0, "_": 0, "n_s": 0, "%.lan": 0} {
		if got := count(CertificateFilter{Search: search}); got != want {
			t.Errorf("search %q: %d, want %d", search, got, want)
		}
	}
	if got := count(CertificateFilter{Status: CertValid}); got != 3 {
		t.Errorf("valid: %d", got)
	}
	if got := count(CertificateFilter{Status: CertRevoked}); got != 0 {
		t.Errorf("revoked: %d", got)
	}

	var seen []string
	f := CertificateFilter{Limit: 2}
	for range 3 {
		page, err := v.e.Certificates(t.Context(), tester, f)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range page.Items {
			seen = append(seen, c.ID)
		}
		if page.NextCursor == "" {
			break
		}
		f.Cursor = page.NextCursor
	}
	if !slices.Equal(seen, all) {
		t.Errorf("pages %v, want %v", seen, all)
	}
	if got := count(CertificateFilter{Limit: 10_000}); got != 3 {
		t.Errorf("large limit: %d", got)
	}
}

// TestKeyDownload: only an operator of the issuing CA with a fresh second
// factor gets a server-generated key, only while unsealed, and every
// download is audited before the key leaves.
func TestKeyDownload(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.chain(t, caOpts{})
	gen := v.issue(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"nas.homelab.lan"}})
	key := mustKey(t, elliptic.P256())
	fromCSR := v.issue(t, Request{CA: "issuing", Preset: "server", DNSNames: []string{"web.homelab.lan"},
		CSR: makeCSR(t, key, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "web.homelab.lan"}})})

	var none time.Time
	viewer := signedIn("v", v.clk.Now(), authz.Binding{Role: authz.Viewer})
	tired := signedIn("op", none, authz.Binding{CA: "issuing", Role: authz.Operator})
	fresh := signedIn("op", v.clk.Now(), authz.Binding{CA: "issuing", Role: authz.Operator})

	if _, err := v.e.ExportKey(t.Context(), viewer, gen.ID); !errors.Is(err, authz.ErrDenied) || errors.Is(err, ErrNotFound) {
		t.Errorf("viewer: %v", err)
	}
	if _, err := v.e.ExportKey(t.Context(), tired, gen.ID); !errors.Is(err, authz.ErrStepUpRequired) {
		t.Errorf("without step-up: %v", err)
	}
	if _, err := v.e.ExportKey(t.Context(), fresh, fromCSR.ID); !errors.Is(err, ErrNoStoredKey) {
		t.Errorf("CSR certificate: %v", err)
	}
	pemKey, err := v.e.ExportKey(t.Context(), fresh, gen.ID)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(pemKey)
	if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
		t.Fatalf("not one PKCS#8 PEM block: %q", pemKey)
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	signer, ok := priv.(crypto.Signer)
	if err != nil || !ok || !publicKeyEqual(signer.Public(), parse(t, gen.CertDER).PublicKey) {
		t.Errorf("key doesn't match the certificate: %v", err)
	}

	unsealed := v.e.Keys
	v.e.Keys = keys.New(nil, nil, v.clk)
	if _, err := v.e.ExportKey(t.Context(), fresh, gen.ID); !errors.Is(err, keys.ErrSealed) {
		t.Errorf("sealed: %v", err)
	}
	v.e.Keys = unsealed

	got := map[string]int{}
	for _, r := range v.auditRows(t) {
		if r.action == ActionKeyDownload {
			got[r.result]++
		}
	}
	if got["success"] != 1 || got["denied"] != 2 {
		t.Errorf("key.download audit: %v", got)
	}
}
