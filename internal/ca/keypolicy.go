package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/Der-Felix/MyOwnPKI/internal/ca/preset"
)

// Key algorithm names, as stored in keys.algorithm and certificates.key_algorithm.
const (
	AlgECDSAP256 = "ecdsa-p256"
	AlgECDSAP384 = "ecdsa-p384"
	AlgECDSAP521 = "ecdsa-p521"
	AlgEd25519   = "ed25519"
	AlgRSA2048   = "rsa-2048"
	AlgRSA3072   = "rsa-3072"
	AlgRSA4096   = "rsa-4096"

	// DefaultKeyAlgorithm is used for server-side key generation when the
	// request names none: what certbot, Traefik and Caddy generate too.
	DefaultKeyAlgorithm = AlgECDSAP256
)

// GeneratedAlgorithms are the algorithms the server generates keys for.
var GeneratedAlgorithms = []string{AlgECDSAP256, AlgECDSAP384, AlgECDSAP521, AlgEd25519, AlgRSA2048, AlgRSA3072, AlgRSA4096}

// RSA limits: below 2048 bits is broken in practice, above 8192 only costs
// CPU on every handshake (and invites denial of service with huge keys).
const (
	minRSABits = 2048
	maxRSABits = 8192
	rsaE       = 65537
)

// keyAlgorithm applies the key policy to a public key and returns its name.
func keyAlgorithm(pub crypto.PublicKey) (string, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return AlgECDSAP256, nil
		case elliptic.P384():
			return AlgECDSAP384, nil
		case elliptic.P521():
			return AlgECDSAP521, nil
		}
		return "", fmt.Errorf("ECDSA curve %s is not allowed (allowed: P-256, P-384, P-521)", k.Params().Name)
	case *rsa.PublicKey:
		bits := k.N.BitLen()
		if bits < minRSABits || bits > maxRSABits {
			return "", fmt.Errorf("RSA key with %d bits is not allowed (allowed: %d to %d bits)", bits, minRSABits, maxRSABits)
		}
		if k.E != rsaE {
			return "", fmt.Errorf("RSA public exponent %d is not allowed (only %d)", k.E, rsaE)
		}
		return fmt.Sprintf("rsa-%d", bits), nil
	case ed25519.PublicKey:
		return AlgEd25519, nil
	}
	return "", fmt.Errorf("key type %T is not allowed (allowed: ECDSA, RSA, Ed25519; DSA never)", pub)
}

func isRSA(alg string) bool { return strings.HasPrefix(alg, "rsa-") }

func x509Algorithm(alg string) x509.PublicKeyAlgorithm {
	switch {
	case isRSA(alg):
		return x509.RSA
	case alg == AlgEd25519:
		return x509.Ed25519
	}
	return x509.ECDSA
}

// keyWarnings names compatibility problems that don't stop issuance.
func keyWarnings(alg string, p *preset.Preset) []string {
	tlsServer := slices.Contains(p.ExtKeyUsage.Usages, "serverAuth")
	var w []string
	switch {
	case alg == AlgEd25519 && tlsServer:
		w = append(w, "Ed25519 TLS server certificates are rejected by browsers (Chrome, Firefox, Safari) – use them only for internal APIs, CLI tools or mutual TLS")
	case alg == AlgECDSAP521 && tlsServer:
		w = append(w, "P-521 TLS server certificates are rejected by Chrome – use P-256 or P-384 for web servers")
	case alg == AlgRSA2048:
		w = append(w, "RSA 2048 is for compatibility only – BSI TR-02102 recommends at least 3000 bits")
	}
	return w
}

// generateKey creates a private key for server-side key generation.
func generateKey(alg string, rnd io.Reader) (crypto.Signer, error) {
	switch alg {
	case AlgECDSAP256:
		return ecdsa.GenerateKey(elliptic.P256(), rnd)
	case AlgECDSAP384:
		return ecdsa.GenerateKey(elliptic.P384(), rnd)
	case AlgECDSAP521:
		return ecdsa.GenerateKey(elliptic.P521(), rnd)
	case AlgEd25519:
		_, priv, err := ed25519.GenerateKey(rnd)
		return priv, err
	case AlgRSA2048:
		return rsa.GenerateKey(rnd, 2048)
	case AlgRSA3072:
		return rsa.GenerateKey(rnd, 3072)
	case AlgRSA4096:
		return rsa.GenerateKey(rnd, 4096)
	}
	return nil, fmt.Errorf("key algorithm %q can't be generated (allowed: %s)", alg, strings.Join(GeneratedAlgorithms, ", "))
}

// signatureAlgorithm follows the issuer's key (pki-rules.md §4): SHA-256 for
// RSA and P-256, SHA-384 for P-384, SHA-512 for P-521, pure Ed25519.
func signatureAlgorithm(issuer crypto.PublicKey) (x509.SignatureAlgorithm, error) {
	switch k := issuer.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return x509.ECDSAWithSHA256, nil
		case elliptic.P384():
			return x509.ECDSAWithSHA384, nil
		case elliptic.P521():
			return x509.ECDSAWithSHA512, nil
		}
	case *rsa.PublicKey:
		return x509.SHA256WithRSA, nil
	case ed25519.PublicKey:
		return x509.PureEd25519, nil
	}
	return 0, fmt.Errorf("CA key type %T is not supported", issuer)
}
