// Package jose reads the JSON Web Signatures of ACME requests (RFC 7515,
// RFC 8555 §6.2) – own code for the parsing and the rules, cryptography
// only from the standard library (owner Q3, 2026-10-22).
//
// Rules, each with its own test:
//   - Flattened JSON serialization only, with exactly the members
//     "protected", "payload" and "signature" – no unprotected header, no
//     "signatures" array, no duplicate member names anywhere.
//   - Base64url without padding, strict (no stray bits).
//   - Algorithms: ES256 (P-256), ES384 (P-384), RS256 (RSA ≥ 2048 bits),
//     EdDSA (Ed25519). The algorithm follows from the key; the header must
//     name exactly that one. "none", HS*, everything else: refused.
//   - ECDSA signatures only as R‖S of the curve's fixed length (no DER).
//   - "crit" and "b64" are refused: no extension is understood.
//   - The protected header carries "url", "nonce" and exactly one of "jwk"
//     and "kid" (the caller decides which one a resource needs).
//   - A JWK never carries private members.
package jose

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Errors a caller can map to ACME problem types.
var (
	// ErrMalformed: not a JWS this server accepts (ACME "malformed").
	ErrMalformed = errors.New("malformed JWS")
	// ErrBadAlgorithm: an algorithm outside the allowlist or not matching
	// the key (ACME "badSignatureAlgorithm").
	ErrBadAlgorithm = errors.New("signature algorithm not accepted")
	// ErrBadSignature: the signature doesn't verify (ACME "malformed" or
	// "unauthorized" by context).
	ErrBadSignature = errors.New("signature does not verify")
	// ErrBadKey: a JWK this server doesn't accept (ACME "badPublicKey").
	ErrBadKey = errors.New("public key not accepted")
)

func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformed, fmt.Sprintf(format, args...))
}

// b64 is base64url without padding, strict: trailing bits must be zero, so
// every value has exactly one encoding.
var b64 = base64.RawURLEncoding.Strict()

func decodeB64(what, s string) ([]byte, error) {
	out, err := b64.DecodeString(s)
	if err != nil {
		return nil, malformed("%s is not base64url without padding", what)
	}
	return out, nil
}

// object reads one JSON object strictly: member names unique (also when
// written with escapes), nothing after the closing brace. Values stay raw.
func object(what string, data []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, malformed("%s is not a JSON object", what)
	}
	out := map[string]json.RawMessage{}
	for dec.More() {
		tok, err = dec.Token()
		if err != nil {
			return nil, malformed("%s: %v", what, err)
		}
		key, ok := tok.(string)
		if !ok {
			return nil, malformed("%s: a member name is not a string", what)
		}
		var raw json.RawMessage
		if err = dec.Decode(&raw); err != nil {
			return nil, malformed("%s: member %q: %v", what, key, err)
		}
		if _, dup := out[key]; dup {
			return nil, malformed("%s: member %q appears twice", what, key)
		}
		out[key] = raw
	}
	if _, err = dec.Token(); err != nil { // '}'
		return nil, malformed("%s: %v", what, err)
	}
	if _, err = dec.Token(); !errors.Is(err, io.EOF) {
		return nil, malformed("%s: data after the object", what)
	}
	return out, nil
}

// str reads a member that must be a JSON string.
func str(what string, raw json.RawMessage) (string, error) {
	var s string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &s) != nil {
		return "", malformed("%s must be a string", what)
	}
	return s, nil
}
