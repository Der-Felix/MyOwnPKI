package trustkit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// update rewrites the golden files; with -fixture it also creates a new
// fixture root first (which changes every golden file).
var (
	update     = flag.Bool("update", false, "rewrite the golden files in testdata")
	newFixture = flag.Bool("fixture", false, "with -update: create a new fixture root")
)

const (
	fixtureFile = "testdata/fixture-root.der"
	// fixtureBase is the base URL of the fixture root in every golden file.
	fixtureBase = "http://pki.example.test"
)

// fixtureRoot is a throwaway self-signed certificate, committed as
// testdata/fixture-root.der so the golden files stay stable. It is named
// "Fixture Root CA (never real)", its key was discarded at creation, and it
// is not trusted anywhere. Create a new one with
//
//	go test ./internal/trustkit -update -fixture
func fixtureRoot(t *testing.T) Root {
	t.Helper()
	if *update && *newFixture {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "Fixture Root CA (never real)", Organization: []string{"trustkit test fixture"}},
			NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:              time.Date(2046, 1, 1, 0, 0, 0, 0, time.UTC),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fixtureFile, der, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	der, err := os.ReadFile(filepath.FromSlash(fixtureFile))
	if err != nil {
		t.Fatalf("the fixture root is missing (go test ./internal/trustkit -update -fixture): %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return Root{Name: "fixture-root", Generation: 1, Current: true, DER: der, BaseURL: fixtureBase, CommonName: cert.Subject.CommonName}
}

// golden compares got with testdata/<name>, or rewrites it with -update.
func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (go test ./internal/trustkit -update)", err)
	}
	if string(want) != string(got) {
		t.Errorf("%s differs (go test ./internal/trustkit -update, then review the diff):\n--- want\n%s\n--- got\n%s", name, want, got)
	}
}
