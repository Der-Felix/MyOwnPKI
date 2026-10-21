package testutil

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// PKCS12 is what `openssl pkcs12 -nodes` read from a file: the certificates
// and the decrypted key as PEM blocks, parsed with crypto/x509. Tests compare
// these with the originals instead of OpenSSL's text, whose format differs
// between versions (3.0 prints "subject=CN = x", 3.5 "subject=CN=x").
type PKCS12 struct {
	Certs  []*x509.Certificate
	KeyDER []byte // PKCS#8, as OpenSSL decrypted it
	Text   string // the whole output, for the stable facts of -info
}

// OpenSSLPKCS12 opens file with the password (written to a temp file, never
// on the command line) and returns what OpenSSL read. info adds -info (MAC
// and encryption facts in Text). An error carries OpenSSL's output.
func OpenSSLPKCS12(tb testing.TB, file, password string, info bool) (*PKCS12, error) {
	tb.Helper()
	bin := OpenSSL(tb)
	passFile := filepath.Join(tb.TempDir(), "pass")
	if err := os.WriteFile(passFile, []byte(password), 0o600); err != nil {
		tb.Fatal(err)
	}
	args := []string{"pkcs12", "-in", file, "-passin", "file:" + passFile, "-nodes"}
	if info {
		args = append(args, "-info")
	}
	// #nosec G204 -- test helper: the openssl found on PATH and temp files
	out, err := exec.CommandContext(context.Background(), bin, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("openssl pkcs12: %w\n%s", err, out)
	}
	p := &PKCS12{Text: string(out)}
	rest := out
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		switch b.Type {
		case "CERTIFICATE":
			c, perr := x509.ParseCertificate(b.Bytes)
			if perr != nil {
				return nil, fmt.Errorf("a certificate OpenSSL printed doesn't parse: %w", perr)
			}
			p.Certs = append(p.Certs, c)
		case "PRIVATE KEY":
			if p.KeyDER != nil {
				return nil, fmt.Errorf("OpenSSL printed two keys:\n%s", out)
			}
			p.KeyDER = b.Bytes
		}
	}
	return p, nil
}

// Problems compares what OpenSSL read with the originals: exactly the leaf
// and the chain (byte for byte, order free), a key that belongs to the leaf,
// and the friendly name. It names each missing or wrong part.
func (p *PKCS12) Problems(leaf *x509.Certificate, chain []*x509.Certificate, friendlyName string) []string {
	var problems []string
	want := append([]*x509.Certificate{leaf}, chain...)
	for _, w := range want {
		found := false
		for _, g := range p.Certs {
			if bytes.Equal(g.Raw, w.Raw) {
				found = true
				break
			}
		}
		if !found {
			problems = append(problems, "certificate missing: "+w.Subject.String())
		}
	}
	if len(p.Certs) != len(want) {
		problems = append(problems, fmt.Sprintf("%d certificates read, want %d (leaf and chain)", len(p.Certs), len(want)))
	}
	switch key, err := x509.ParsePKCS8PrivateKey(p.KeyDER); {
	case p.KeyDER == nil:
		problems = append(problems, "no private key read")
	case err != nil:
		problems = append(problems, "the key doesn't parse as PKCS#8: "+err.Error())
	default:
		signer, ok := key.(crypto.Signer)
		pub, isEq := leaf.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
		if !ok || !isEq || !pub.Equal(signer.Public()) {
			problems = append(problems, "the key doesn't belong to the leaf certificate")
		}
	}
	// The friendly name is a bag attribute; OpenSSL prints its value after
	// "friendlyName:" in every 3.x version.
	if friendlyName != "" && !strings.Contains(p.Text, "friendlyName: "+friendlyName) {
		problems = append(problems, "friendlyName "+friendlyName+" missing")
	}
	return problems
}

// InfoProblems checks the stable facts of -info: the names of algorithms
// and numbers, never the layout around them.
func (p *PKCS12) InfoProblems(facts ...string) []string {
	var problems []string
	for _, f := range facts {
		if !strings.Contains(p.Text, f) {
			problems = append(problems, "-info lacks "+f)
		}
	}
	return problems
}
