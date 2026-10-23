package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
)

// Algorithms of the allowlist.
const (
	ES256 = "ES256"
	ES384 = "ES384"
	RS256 = "RS256"
	EdDSA = "EdDSA"
)

// RSA key size limits: below 2048 bits is weak (owner Q3); above 8192 only
// costs verification time.
const (
	minRSABits = 2048
	maxRSABits = 8192
)

// Key is a public JWK from the allowlist.
type Key struct {
	kty, crv string
	alg      string // what this key signs with
	pub      crypto.PublicKey
	thumb    string
}

// privateMembers must never appear in an account key.
var privateMembers = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

// ParseJWK reads a public JWK. The algorithm follows from the key type; an
// "alg" member, if present, must name the same one.
func ParseJWK(raw []byte) (*Key, error) {
	m, err := object("jwk", raw)
	if err != nil {
		return nil, err
	}
	for _, p := range privateMembers {
		if _, ok := m[p]; ok {
			return nil, fmt.Errorf("%w: the JWK carries the private member %q", ErrBadKey, p)
		}
	}
	kty, err := str("jwk kty", m["kty"])
	if err != nil {
		return nil, err
	}
	k := &Key{kty: kty}
	switch kty {
	case "EC":
		err = k.parseEC(m)
	case "RSA":
		err = k.parseRSA(m)
	case "OKP":
		err = k.parseOKP(m)
	default:
		return nil, fmt.Errorf("%w: key type %q (allowed: EC P-256/P-384, RSA, OKP Ed25519)", ErrBadKey, kty)
	}
	if err != nil {
		return nil, err
	}
	if a, ok := m["alg"]; ok {
		alg, serr := str("jwk alg", a)
		if serr != nil {
			return nil, serr
		}
		if alg != k.alg {
			return nil, fmt.Errorf("%w: the JWK says alg %q, its key signs with %s", ErrBadAlgorithm, alg, k.alg)
		}
	}
	return k, nil
}

func (k *Key) parseEC(m map[string]json.RawMessage) error {
	crv, err := str("jwk crv", m["crv"])
	if err != nil {
		return err
	}
	var curve elliptic.Curve
	switch crv {
	case "P-256":
		curve, k.alg = elliptic.P256(), ES256
	case "P-384":
		curve, k.alg = elliptic.P384(), ES384
	default:
		return fmt.Errorf("%w: curve %q (allowed: P-256, P-384)", ErrBadKey, crv)
	}
	size := (curve.Params().BitSize + 7) / 8
	coord := func(name string) ([]byte, error) {
		s, serr := str("jwk "+name, m[name])
		if serr != nil {
			return nil, serr
		}
		b, derr := decodeB64("jwk "+name, s)
		if derr != nil {
			return nil, derr
		}
		if len(b) != size {
			return nil, fmt.Errorf("%w: %s of a %s key must be %d bytes, got %d", ErrBadKey, name, crv, size, len(b))
		}
		return b, nil
	}
	x, err := coord("x")
	if err != nil {
		return err
	}
	y, err := coord("y")
	if err != nil {
		return err
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(curve, append(append([]byte{4}, x...), y...))
	if err != nil {
		return fmt.Errorf("%w: the point is not on curve %s", ErrBadKey, crv)
	}
	k.crv, k.pub = crv, pub
	k.thumb = thumbprint(`{"crv":` + strconv.Quote(crv) + `,"kty":"EC","x":"` + b64.EncodeToString(x) + `","y":"` + b64.EncodeToString(y) + `"}`)
	return nil
}

func (k *Key) parseRSA(m map[string]json.RawMessage) error {
	num := func(name string) (*big.Int, error) {
		s, err := str("jwk "+name, m[name])
		if err != nil {
			return nil, err
		}
		b, err := decodeB64("jwk "+name, s)
		if err != nil {
			return nil, err
		}
		if len(b) == 0 || b[0] == 0 {
			return nil, fmt.Errorf("%w: %s must be a minimal big-endian number (no leading zero byte)", ErrBadKey, name)
		}
		return new(big.Int).SetBytes(b), nil
	}
	n, err := num("n")
	if err != nil {
		return err
	}
	e, err := num("e")
	if err != nil {
		return err
	}
	switch bits := n.BitLen(); {
	case bits < minRSABits:
		return fmt.Errorf("%w: RSA key of %d bits – at least %d", ErrBadKey, bits, minRSABits)
	case bits > maxRSABits:
		return fmt.Errorf("%w: RSA key of %d bits – at most %d", ErrBadKey, bits, maxRSABits)
	}
	if !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 || e.Bit(0) == 0 {
		return fmt.Errorf("%w: RSA exponent must be odd and between 3 and 2^31-1", ErrBadKey)
	}
	k.alg, k.pub = RS256, &rsa.PublicKey{N: n, E: int(e.Int64())}
	k.thumb = thumbprint(`{"e":"` + b64.EncodeToString(e.Bytes()) + `","kty":"RSA","n":"` + b64.EncodeToString(n.Bytes()) + `"}`)
	return nil
}

func (k *Key) parseOKP(m map[string]json.RawMessage) error {
	crv, err := str("jwk crv", m["crv"])
	if err != nil {
		return err
	}
	if crv != "Ed25519" {
		return fmt.Errorf("%w: OKP curve %q (allowed: Ed25519)", ErrBadKey, crv)
	}
	s, err := str("jwk x", m["x"])
	if err != nil {
		return err
	}
	x, err := decodeB64("jwk x", s)
	if err != nil {
		return err
	}
	if len(x) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: an Ed25519 key is %d bytes, got %d", ErrBadKey, ed25519.PublicKeySize, len(x))
	}
	k.crv, k.alg, k.pub = crv, EdDSA, ed25519.PublicKey(x)
	k.thumb = thumbprint(`{"crv":"Ed25519","kty":"OKP","x":"` + s + `"}`)
	return nil
}

// thumbprint is RFC 7638: base64url(SHA-256(the required members in
// lexicographic order, no whitespace)).
func thumbprint(canonical string) string {
	sum := sha256.Sum256([]byte(canonical))
	return b64.EncodeToString(sum[:])
}

// Thumbprint is the RFC 7638 thumbprint – the account key's identity and
// part of every key authorization (RFC 8555 §8.1).
func (k *Key) Thumbprint() string { return k.thumb }

// Algorithm is the one algorithm this key signs with.
func (k *Key) Algorithm() string { return k.alg }

// Public is the standard library's public key.
func (k *Key) Public() crypto.PublicKey { return k.pub }

// Equal reports whether two keys are the same key.
func (k *Key) Equal(o *Key) bool { return o != nil && k.thumb == o.thumb }

// Canonical is the key as a JWK with its required members only.
func (k *Key) Canonical() []byte {
	switch p := k.pub.(type) {
	case *ecdsa.PublicKey:
		b, _ := p.Bytes() // 04 || x || y
		size := (len(b) - 1) / 2
		return []byte(`{"crv":` + strconv.Quote(k.crv) + `,"kty":"EC","x":"` + b64.EncodeToString(b[1:1+size]) + `","y":"` + b64.EncodeToString(b[1+size:]) + `"}`)
	case *rsa.PublicKey:
		return []byte(`{"e":"` + b64.EncodeToString(big.NewInt(int64(p.E)).Bytes()) + `","kty":"RSA","n":"` + b64.EncodeToString(p.N.Bytes()) + `"}`)
	case ed25519.PublicKey:
		return []byte(`{"crv":"Ed25519","kty":"OKP","x":"` + b64.EncodeToString(p) + `"}`)
	}
	return nil
}

// KeyFor wraps a standard library public key (tests, EAB comparisons).
func KeyFor(pub crypto.PublicKey) (*Key, error) {
	var raw []byte
	switch p := pub.(type) {
	case *ecdsa.PublicKey:
		k := &Key{pub: p}
		switch p.Curve {
		case elliptic.P256():
			k.crv = "P-256"
		case elliptic.P384():
			k.crv = "P-384"
		default:
			return nil, fmt.Errorf("%w: curve not allowed", ErrBadKey)
		}
		raw = k.Canonical()
	case *rsa.PublicKey:
		raw = (&Key{pub: p}).Canonical()
	case ed25519.PublicKey:
		raw = (&Key{pub: p}).Canonical()
	default:
		return nil, fmt.Errorf("%w: %T", ErrBadKey, pub)
	}
	return ParseJWK(raw)
}

// verify checks sig over input with this key's one algorithm.
func (k *Key) verify(input, sig []byte) error {
	switch p := k.pub.(type) {
	case *ecdsa.PublicKey:
		size := (p.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*size {
			return fmt.Errorf("%w: an %s signature is R||S of %d bytes, got %d (DER is not accepted)", ErrBadSignature, k.alg, 2*size, len(sig))
		}
		r, s := new(big.Int).SetBytes(sig[:size]), new(big.Int).SetBytes(sig[size:])
		var digest []byte
		if k.alg == ES256 {
			d := sha256.Sum256(input)
			digest = d[:]
		} else {
			d := sha512.Sum384(input)
			digest = d[:]
		}
		if !ecdsa.Verify(p, digest, r, s) {
			return ErrBadSignature
		}
		return nil
	case *rsa.PublicKey:
		d := sha256.Sum256(input)
		if rsa.VerifyPKCS1v15(p, crypto.SHA256, d[:], sig) != nil {
			return ErrBadSignature
		}
		return nil
	case ed25519.PublicKey:
		if len(sig) != ed25519.SignatureSize || !ed25519.Verify(p, input, sig) {
			return ErrBadSignature
		}
		return nil
	}
	return ErrBadKey
}
