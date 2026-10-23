package jose

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
)

// JWS is a parsed flattened JWS whose signature is not checked yet.
type JWS struct {
	// The protected header, member by member.
	Alg, Nonce, URL, KID string
	// JWK is the embedded key ("jwk"), nil when the request names "kid".
	JWK *Key

	Payload []byte // empty for POST-as-GET

	signingInput []byte
	signature    []byte
}

// allowed algorithms of the outer JWS.
var allowed = map[string]bool{ES256: true, ES384: true, RS256: true, EdDSA: true}

// Parse reads an ACME request body (RFC 8555 §6.2): flattened JSON with
// exactly "protected", "payload" and "signature"; a protected header with
// an allowed "alg", "nonce", "url" and exactly one of "jwk" and "kid"; no
// "crit", no "b64". The signature is checked by Verify.
func Parse(body []byte) (*JWS, error) { return parse(body, false) }

// ParseInner reads the inner JWS of a key change (RFC 8555 §7.3.5): like
// Parse, but with "jwk" (the new key) and without "nonce" and "kid".
func ParseInner(body []byte) (*JWS, error) { return parse(body, true) }

func parse(body []byte, inner bool) (*JWS, error) {
	top, err := object("request body", body)
	if err != nil {
		return nil, err
	}
	for name := range top {
		switch name {
		case "protected", "payload", "signature":
		case "header":
			return nil, malformed("an unprotected header is not accepted – every header member belongs into \"protected\"")
		case "signatures":
			return nil, malformed("the general JSON serialization is not accepted – use the flattened one with one signature")
		default:
			return nil, malformed("unknown member %q", name)
		}
	}
	for _, name := range []string{"protected", "payload", "signature"} {
		if _, ok := top[name]; !ok {
			return nil, malformed("member %q is missing", name)
		}
	}
	protectedB64, err := str("protected", top["protected"])
	if err != nil {
		return nil, err
	}
	payloadB64, err := str("payload", top["payload"])
	if err != nil {
		return nil, err
	}
	sigB64, err := str("signature", top["signature"])
	if err != nil {
		return nil, err
	}
	j := &JWS{signingInput: []byte(protectedB64 + "." + payloadB64)}
	if j.signature, err = decodeB64("signature", sigB64); err != nil {
		return nil, err
	}
	if j.Payload, err = decodeB64("payload", payloadB64); err != nil {
		return nil, err
	}
	headerJSON, err := decodeB64("protected", protectedB64)
	if err != nil {
		return nil, err
	}
	h, err := object("protected header", headerJSON)
	if err != nil {
		return nil, err
	}
	if _, ok := h["crit"]; ok {
		return nil, malformed("\"crit\" names extensions this server doesn't understand")
	}
	if _, ok := h["b64"]; ok {
		return nil, malformed("\"b64\" (RFC 7797 unencoded payload) is not accepted")
	}
	if j.Alg, err = str("alg", h["alg"]); err != nil {
		return nil, err
	}
	if err = checkAlg(j.Alg); err != nil {
		return nil, err
	}
	if inner {
		if _, ok := h["nonce"]; ok {
			return nil, malformed("the inner JWS of a key change must not have a \"nonce\"")
		}
		if _, ok := h["kid"]; ok {
			return nil, malformed("the inner JWS of a key change names the new key in \"jwk\", not \"kid\"")
		}
	} else if j.Nonce, err = str("nonce", h["nonce"]); err != nil || j.Nonce == "" {
		return nil, malformed("the protected header needs a \"nonce\"")
	}
	if j.URL, err = str("url", h["url"]); err != nil || j.URL == "" {
		return nil, malformed("the protected header needs a \"url\"")
	}
	rawJWK, hasJWK := h["jwk"]
	rawKID, hasKID := h["kid"]
	switch {
	case hasJWK && hasKID:
		return nil, malformed("the protected header has both \"jwk\" and \"kid\" – exactly one is allowed")
	case !hasJWK && !hasKID:
		return nil, malformed("the protected header needs \"jwk\" or \"kid\"")
	case hasJWK:
		if j.JWK, err = ParseJWK(rawJWK); err != nil {
			return nil, err
		}
	default:
		if j.KID, err = str("kid", rawKID); err != nil || j.KID == "" {
			return nil, malformed("\"kid\" must be the account URL")
		}
	}
	return j, nil
}

// checkAlg refuses everything outside the allowlist, with a clear reason.
func checkAlg(alg string) error {
	switch {
	case allowed[alg]:
		return nil
	case strings.EqualFold(alg, "none"):
		return fmt.Errorf("%w: \"none\" – every request must be signed", ErrBadAlgorithm)
	case strings.HasPrefix(alg, "HS"):
		return fmt.Errorf("%w: %s is a MAC with a shared secret, not a signature", ErrBadAlgorithm, alg)
	}
	return fmt.Errorf("%w: %q (allowed: ES256, ES384, RS256, EdDSA)", ErrBadAlgorithm, alg)
}

// Verify checks the signature with key – the embedded JWK, or the
// account's key for a "kid" request. The header's algorithm must be the
// key's one algorithm.
func (j *JWS) Verify(key *Key) error {
	if key == nil {
		return ErrBadKey
	}
	if j.Alg != key.alg {
		return fmt.Errorf("%w: the header says %s, the key signs with %s", ErrBadAlgorithm, j.Alg, key.alg)
	}
	return key.verify(j.signingInput, j.signature)
}

// VerifyEAB checks an external account binding (RFC 8555 §7.3.4): a JWS
// whose protected header names HS256, the EAB key ID ("kid") and the same
// URL as the outer request, and no nonce; whose payload is the account's
// public key; and whose MAC verifies with the key the admin created. This
// is the one place where a MAC is accepted – the outer JWS never.
// It returns the EAB key ID; macKeyFor looks up the MAC key by that ID.
func VerifyEAB(raw json.RawMessage, accountKey *Key, url string, macKeyFor func(kid string) ([]byte, error)) (string, error) {
	top, err := object("externalAccountBinding", raw)
	if err != nil {
		return "", err
	}
	for name := range top {
		if name != "protected" && name != "payload" && name != "signature" {
			return "", malformed("externalAccountBinding: unknown member %q", name)
		}
	}
	protectedB64, err := str("externalAccountBinding protected", top["protected"])
	if err != nil {
		return "", err
	}
	payloadB64, err := str("externalAccountBinding payload", top["payload"])
	if err != nil {
		return "", err
	}
	sigB64, err := str("externalAccountBinding signature", top["signature"])
	if err != nil {
		return "", err
	}
	headerJSON, err := decodeB64("externalAccountBinding protected", protectedB64)
	if err != nil {
		return "", err
	}
	h, err := object("externalAccountBinding header", headerJSON)
	if err != nil {
		return "", err
	}
	for name := range h {
		if name != "alg" && name != "kid" && name != "url" {
			return "", malformed("externalAccountBinding header: member %q is not allowed", name)
		}
	}
	alg, err := str("externalAccountBinding alg", h["alg"])
	if err != nil {
		return "", err
	}
	if alg != "HS256" {
		return "", fmt.Errorf("%w: externalAccountBinding must be HS256, got %q", ErrBadAlgorithm, alg)
	}
	kid, err := str("externalAccountBinding kid", h["kid"])
	if err != nil || kid == "" {
		return "", malformed("externalAccountBinding needs the EAB key ID in \"kid\"")
	}
	u, err := str("externalAccountBinding url", h["url"])
	if err != nil || u != url {
		return "", malformed("externalAccountBinding url must be the newAccount URL")
	}
	payload, err := decodeB64("externalAccountBinding payload", payloadB64)
	if err != nil {
		return "", err
	}
	bound, err := ParseJWK(payload)
	if err != nil {
		return "", err
	}
	if !bound.Equal(accountKey) {
		return "", malformed("externalAccountBinding binds another key than the one of the request")
	}
	sig, err := decodeB64("externalAccountBinding signature", sigB64)
	if err != nil {
		return "", err
	}
	macKey, err := macKeyFor(kid)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, macKey)
	mac.Write([]byte(protectedB64 + "." + payloadB64))
	if !hmac.Equal(mac.Sum(nil), sig) {
		return "", fmt.Errorf("%w: the externalAccountBinding MAC is wrong", ErrBadSignature)
	}
	return kid, nil
}
