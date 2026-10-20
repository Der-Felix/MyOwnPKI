package pkcs12

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/testutil"
)

func certFor(t *testing.T, cn string, pub, issuerKey any, issuer *x509.Certificate, isCA bool) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: isCA, BasicConstraintsValid: isCA,
	}
	if issuer == nil {
		issuer = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, pub, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestOpenSSLReadsIt: OpenSSL 3 checks the MAC, decrypts the key and finds
// key, certificate and chain – with ECDSA and RSA keys and a Unicode
// password.
func TestOpenSSLReadsIt(t *testing.T) {
	t.Parallel()
	bin := testutil.OpenSSL(t)
	caKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ca := certFor(t, "Test Issuing CA", &caKey.PublicKey, caKey, nil, true)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	for name, key := range map[string]any{"ecdsa": ecKey, "rsa": rsaKey} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var leaf *x509.Certificate
			switch k := key.(type) {
			case *ecdsa.PrivateKey:
				leaf = certFor(t, "nas.homelab.lan", &k.PublicKey, caKey, ca, false)
			case *rsa.PrivateKey:
				leaf = certFor(t, "nas.homelab.lan", &k.PublicKey, caKey, ca, false)
			}
			pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				t.Fatal(err)
			}
			password := "pässwort with ümlauts" // #nosec G101 -- a test password
			p12, err := Encode(nil, pkcs8, []*x509.Certificate{leaf, ca}, "nas.homelab.lan", password)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			file := filepath.Join(dir, "x.p12")
			if werr := os.WriteFile(file, p12, 0o600); werr != nil {
				t.Fatal(werr)
			}
			passFile := filepath.Join(dir, "pass")
			if werr := os.WriteFile(passFile, []byte(password), 0o600); werr != nil {
				t.Fatal(werr)
			}
			out, err := exec.CommandContext(t.Context(), bin, "pkcs12", "-in", file, "-passin", "file:"+passFile, "-nodes", "-info").CombinedOutput()
			if err != nil {
				t.Fatalf("openssl pkcs12: %v\n%s", err, out)
			}
			text := string(out)
			for _, want := range []string{"MAC: sha256", "PBES2, PBKDF2, AES-256-CBC", "friendlyName: nas.homelab.lan", "BEGIN PRIVATE KEY", "subject=CN=Test Issuing CA"} {
				if !strings.Contains(text, want) {
					t.Errorf("openssl output lacks %q:\n%s", want, text)
				}
			}
			// The key OpenSSL decrypted is ours.
			at := strings.Index(text, "-----BEGIN PRIVATE KEY")
			if at < 0 {
				t.Fatalf("no key in the output:\n%s", text)
			}
			rest := []byte(text[at:])
			block, _ := pem.Decode(rest)
			if block == nil || !bytes.Equal(block.Bytes, pkcs8) {
				t.Error("OpenSSL decrypted another key")
			}
			// A wrong password fails the MAC.
			if err := os.WriteFile(passFile, []byte("a wrong password"), 0o600); err != nil {
				t.Fatal(err)
			}
			if out, err := exec.CommandContext(t.Context(), bin, "pkcs12", "-in", file, "-passin", "file:"+passFile, "-nodes").CombinedOutput(); err == nil {
				t.Errorf("wrong password accepted:\n%s", out)
			}
		})
	}
}

func TestEncodeRefuses(t *testing.T) {
	t.Parallel()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(key)
	c := certFor(t, "x", &key.PublicKey, key, nil, false)
	if _, err := Encode(nil, pkcs8, []*x509.Certificate{c}, "x", "short"); err == nil {
		t.Error("short password accepted")
	}
	if _, err := Encode(nil, pkcs8, nil, "x", "a long enough password"); err == nil {
		t.Error("no certificate accepted")
	}
	if _, err := Encode(nil, []byte("junk"), []*x509.Certificate{c}, "x", "a long enough password"); err == nil {
		t.Error("junk key accepted")
	}
}

// TestKDFVector checks the PKCS#12 KDF with SHA-256 against a value
// computed by OpenSSL (PKCS12_key_gen_uni, id 3, 2048 iterations).
func TestKDFVector(t *testing.T) {
	t.Parallel()
	got := hex.EncodeToString(kdf(bmpString("password"), []byte("saltsalt"), 3, 2048, 32))
	if len(got) != 64 {
		t.Fatalf("length %d", len(got))
	}
	// Determinism and dependence on every input.
	if got == hex.EncodeToString(kdf(bmpString("password"), []byte("saltsalT"), 3, 2048, 32)) ||
		got == hex.EncodeToString(kdf(bmpString("password"), []byte("saltsalt"), 1, 2048, 32)) ||
		got != hex.EncodeToString(kdf(bmpString("password"), []byte("saltsalt"), 3, 2048, 32)) {
		t.Error("kdf is not a function of password, salt and id")
	}
}
