package publish

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/ca/preset"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
)

var t0 = time.Date(2026, 10, 13, 8, 0, 0, 0, time.UTC)

// setup imports an offline root and uploads its CRL – no unsealed keyring
// needed – and returns the handler and the stored files.
func setup(t *testing.T) (http.Handler, *store.DB, []byte, []byte) {
	t.Helper()
	l := store.Layout{DataDir: t.TempDir()}
	clk := clock.NewFake(t0)
	if _, err := store.Migrate(t.Context(), l, store.DefaultTenant, clk.Now); err != nil {
		t.Fatal(err)
	}
	open := func(kind store.Kind) *store.DB {
		p, _ := l.TenantDB(store.DefaultTenant, kind)
		db, err := store.Open(t.Context(), p)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db
	}
	pki, aud := open(store.KindPKI), open(store.KindAudit)
	presets, _ := preset.Builtin()
	e := &ca.Engine{PKI: pki.Write, Audit: aud.Write, Scope: store.TenantScope(store.DefaultTenant), Keys: keys.New(nil, nil, clk), Presets: presets, Clock: clk}

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Offline Root"}, NotBefore: t0.Add(-time.Hour), NotAfter: t0.AddDate(20, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	who := keys.Who{Actor: audit.Actor{Type: audit.ActorUser, Name: "it-admin"}}
	if _, ierr := e.ImportRoot(t.Context(), ca.ImportRootRequest{
		CASettings: ca.CASettings{Name: "root", BaseURL: "http://pki.homelab.lan"},
		CertPEM:    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), Who: who,
	}); ierr != nil {
		t.Fatal(ierr)
	}
	cert, _ := x509.ParseCertificate(certDER)
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(7), ThisUpdate: t0.Add(-time.Minute), NextUpdate: t0.Add(30 * 24 * time.Hour),
	}, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.UploadCRL(t.Context(), "root", crlDER, who); err != nil {
		t.Fatal(err)
	}
	return New(pki.Read, nil), pki, certDER, crlDER
}

func get(t *testing.T, h http.Handler, method, path string, header map[string]string) *http.Response {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, path, nil)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Result()
}

func body(t *testing.T, r *http.Response) []byte {
	t.Helper()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = r.Body.Close()
	return b
}

func TestServesCertificateAndCRL(t *testing.T) {
	t.Parallel()
	h, _, certDER, crlDER := setup(t)
	for path, want := range map[string]struct {
		data []byte
		ct   string
	}{
		"/ca/root/1.crt":  {certDER, "application/pkix-cert"},
		"/crl/root/1.crl": {crlDER, "application/pkix-crl"},
	} {
		r := get(t, h, http.MethodGet, path, nil)
		if r.StatusCode != http.StatusOK || !bytes.Equal(body(t, r), want.data) || r.Header.Get("Content-Type") != want.ct {
			t.Errorf("%s: %d %s", path, r.StatusCode, r.Header.Get("Content-Type"))
		}
		if r.Header.Get("Cache-Control") != "public, max-age=900" || r.Header.Get("ETag") == "" || r.Header.Get("Last-Modified") == "" ||
			r.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: headers %v", path, r.Header)
		}

		// Conditional requests: unchanged files cost a 304.
		etag, modified := r.Header.Get("ETag"), r.Header.Get("Last-Modified")
		if code := status(t, h, path, map[string]string{"If-None-Match": etag}); code != http.StatusNotModified {
			t.Errorf("%s If-None-Match: %d", path, code)
		}
		if code := status(t, h, path, map[string]string{"If-Modified-Since": modified}); code != http.StatusNotModified {
			t.Errorf("%s If-Modified-Since: %d", path, code)
		}
		if code := status(t, h, path, map[string]string{"If-None-Match": `"other"`}); code != http.StatusOK {
			t.Errorf("%s other ETag: %d", path, code)
		}
		// HEAD: headers, no body.
		if r := get(t, h, http.MethodHead, path, nil); r.StatusCode != http.StatusOK || len(body(t, r)) != 0 || r.Header.Get("ETag") != etag {
			t.Errorf("%s HEAD: %d", path, r.StatusCode)
		}
	}
}

func TestNotFoundAndMethods(t *testing.T) {
	t.Parallel()
	h, _, _, _ := setup(t)
	for _, path := range []string{
		"/ca/root/2.crt", "/crl/root/2.crl", "/ca/nope/1.crt", "/ca/ROOT/1.crt", "/ca/root/0.crt", "/ca/root/1.crl",
		"/crl/root/1.crt", "/ca/root/01.crt", "/root.crt", "/root.crl", "/", "/ca/root/1.crt.pem", "/ca/root",
	} {
		if code := status(t, h, path, nil); code != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", path, code)
		}
	}
	r := get(t, h, http.MethodPost, "/ca/root/1.crt", nil)
	body(t, r)
	if r.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", r.StatusCode)
	}
}

func TestLegacyAliasesOnlyForImportedCAs(t *testing.T) {
	t.Parallel()
	h, pki, certDER, crlDER := setup(t)
	if code := status(t, h, "/root.crl", nil); code != http.StatusNotFound {
		t.Fatalf("alias without legacy_urls: %d", code)
	}
	if _, err := pki.Write.ExecContext(t.Context(), `UPDATE cas SET legacy_urls = 1 WHERE name = 'root'`); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string][]byte{"/root.crt": certDER, "/root.crl": crlDER} {
		if r := get(t, h, http.MethodGet, path, nil); r.StatusCode != http.StatusOK || !bytes.Equal(body(t, r), want) {
			t.Errorf("%s: %d", path, r.StatusCode)
		}
	}
}

// status makes a GET and returns only the status code.
func status(t *testing.T, h http.Handler, path string, header map[string]string) int {
	t.Helper()
	r := get(t, h, http.MethodGet, path, header)
	body(t, r)
	return r.StatusCode
}
